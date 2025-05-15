// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "./RiscZeroVerifierRouter.sol";
import "./tokens/QTOVToken.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title Bridge
 * @dev A bridge contract for cross-chain token transfers with RISC Zero verification
 */
contract Bridge is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // Core contracts
    QTOVToken public qToken;
    RiscZeroVerifierRouter public verifierRouter;

    // Bridge state
    bytes32 public IMAGE_ID;
    uint64 public outwardNonce = 0;
    bytes32 public lastFinalizedHash;
    uint64 public lastInwardNonce;

    // Token management
    mapping(address => bool) public supportedTokens;
    mapping(address => bool) public tokenDisabled;

    // Transfer tracking
    mapping(uint64 => bool) private inwardNonceExists;
    mapping(uint64 => bool) private _claimedNonces; // mapping to track claimed nonces
    uint64 private inwardNonceCount = 0;

    struct InwardRemittance {
        address beneficiary;
        address token_address; // address(0) for native (uses qToken)
        uint128 amount;
        uint64 nonce;
    }

    struct OutwardRemittance {
        address beneficiary;
        address token_address;
        uint256 amount;
        uint64 nonce;
    }

    mapping(uint64 => OutwardRemittance) public outwardTransfers;
    mapping(uint64 => InwardRemittance) public inwardTransfers;

    // Events
    event OutboundTransferInitiated(
        uint64 indexed nonce,
        address sender,
        address beneficiary,
        address token_address,
        uint256 amount
    );
    event InboundTransferRecorded(
        uint64 indexed nonce,
        address beneficiary,
        address token_address,
        uint128 amount,
        uint256 timestamp
    );
    event ProcessedTransaction(
        bytes32 indexed lastFinalizedHash,
        bytes32 indexed latestFinalizedHash,
        uint256 count
    );
    event TransferClaimed(
        uint64 indexed nonce,
        address claimer,
        address token_address,
        uint128 amount,
        uint256 timestamp
    );
    event VerifierChanged(address oldVerifier, address newVerifier);
    event TokenContractChanged(address oldToken, address newToken);
    event VerificationSuccess(bytes32 indexed imageId, bytes32 journalHash);
    event VerificationFailed(bytes32 indexed imageId, string reason);
    event TokenSupportUpdated(address token, bool supported, bool disabled);

    // Custom errors
    error InvalidHashSequence();
    error InvalidHashLength();
    error BatchAlreadyProcessed();
    error ZeroAmount();
    error InvalidImageId();
    error NonceDoesNotExist();
    error TransferAlreadyProcessed();
    error InvalidBeneficiary();
    error InvalidTokenAddress();
    error InvalidVerifierAddress();
    error NonceSequenceViolation(uint64 expected, uint64 actual);
    error UnsupportedToken();
    error TokenDisabled(address token);

    constructor(
        address verifierAddress,
        address tokenAddress,
        bytes32 _imageId,
        address initialOwner,
        bytes32 _lastFinalizedHash,
        address[] memory initialTokens
    ) Ownable(initialOwner) {
        if (verifierAddress == address(0)) revert InvalidVerifierAddress();
        if (tokenAddress == address(0)) revert InvalidTokenAddress();
        if (_imageId == bytes32(0)) revert InvalidImageId();

        verifierRouter = RiscZeroVerifierRouter(verifierAddress);
        qToken = QTOVToken(tokenAddress);
        IMAGE_ID = _imageId;
        lastFinalizedHash = _lastFinalizedHash;

        // Initialize supported tokens
        for (uint256 i = 0; i < initialTokens.length; i++) {
            if (initialTokens[i] != address(0)) {
                _addTokenSupport(initialTokens[i]);
            }
        }
    }

    /**
     * @dev Initiates a cross-chain transfer
     * @param beneficiary Address to receive tokens on the other chain
     * @param token_address Token contract address (address(0) for native via qToken)
     * @param amount Amount of tokens to transfer
     */
    function transferOut(
        address beneficiary,
        address token_address,
        uint256 amount
    ) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        if (beneficiary == address(0)) revert InvalidBeneficiary();
        
        uint64 currentNonce = ++outwardNonce;

        // Native token via qToken
        if (token_address == address(0)) {
            qToken.burnFrom(msg.sender, amount);
        } 
        // ERC20 token transfer
        else {
            if (!supportedTokens[token_address]) revert UnsupportedToken();
            if (tokenDisabled[token_address]) revert TokenDisabled(token_address);
            
            IERC20 token = IERC20(token_address);
            uint256 currentAllowance = token.allowance(msg.sender, address(this));
            
            if (currentAllowance < amount) {
                revert InsufficientAllowance(currentAllowance, amount);
            }
            
            token.safeTransferFrom(msg.sender, address(this), amount);
        }

        outwardTransfers[currentNonce] = OutwardRemittance({
            beneficiary: beneficiary,
            token_address: token_address,
            amount: amount,
            nonce: currentNonce
        });

        emit OutboundTransferInitiated(
            currentNonce,
            msg.sender,
            beneficiary,
            token_address,
            amount
        );
    }

    // InsufficientAllowance error
    error InsufficientAllowance(uint256 current, uint256 required);

    function bridgeWithVerification(
        bytes calldata seal,
        bytes calldata journal
    ) external nonReentrant {
        try verifierRouter.verifyWithJournal(seal, IMAGE_ID, journal) {
            _processVerifiedTransaction(journal);
            emit VerificationSuccess(IMAGE_ID, sha256(journal));
        } catch Error(string memory reason) {
            emit VerificationFailed(IMAGE_ID, reason);
        } catch (bytes memory) {
            emit VerificationFailed(IMAGE_ID, "Low-level verification error");
        }
    }

    function bridgeWithVerificationDebug(
        bytes calldata seal,
        bytes calldata journal,
        bytes calldata journal2
    ) external nonReentrant {
        try verifierRouter.verifyWithJournal(seal, IMAGE_ID, journal) {
            _processVerifiedTransaction(journal2);
            emit VerificationSuccess(IMAGE_ID, sha256(journal));
        } catch Error(string memory reason) {
            emit VerificationFailed(IMAGE_ID, reason);
        } catch (bytes memory) {
            emit VerificationFailed(IMAGE_ID, "Low-level verification error");
        }
    }

    function _processVerifiedTransaction(bytes calldata journal) private {
        (
            bytes memory lastFinalizedHashBytes,
            InwardRemittance[] memory transfers,
            bytes memory latestFinalizedHashBytes
        ) = abi.decode(journal, (bytes, InwardRemittance[], bytes));

        // Validate hashes
        if (lastFinalizedHashBytes.length != 32 || latestFinalizedHashBytes.length != 32) {
            revert InvalidHashLength();
        }

        bytes32 _lastFinalizedHash = abi.decode(lastFinalizedHashBytes, (bytes32));
        bytes32 _latestFinalizedHash = abi.decode(latestFinalizedHashBytes, (bytes32));

        if (_latestFinalizedHash == lastFinalizedHash) revert BatchAlreadyProcessed();
        if (_latestFinalizedHash != bytes32(0) && _lastFinalizedHash != lastFinalizedHash) {
            revert InvalidHashSequence();
        }

        uint256 transfersLength = transfers.length;
        if (transfersLength > 0) {
            uint64 prevNonce = lastInwardNonce;

            for (uint256 i = 0; i < transfersLength; ) {
                InwardRemittance memory transfer = transfers[i];
                uint64 currentNonce = transfer.nonce;
                address beneficiary = transfer.beneficiary;
                uint128 amount = transfer.amount;
                address tokenAddress = transfer.token_address;

                // Validate nonce sequence
                if (currentNonce != prevNonce + 1) {
                    revert NonceSequenceViolation(prevNonce + 1, currentNonce);
                }
                prevNonce = currentNonce;

                // Verify token support (except for native)
                if (tokenAddress != address(0)) {
                    if (!supportedTokens[tokenAddress]) revert UnsupportedToken();
                    if (tokenDisabled[tokenAddress]) revert TokenDisabled(tokenAddress);
                    require(tokenAddress.code.length > 0, "Invalid token contract");
                }

                // Store transfer
                inwardTransfers[currentNonce] = InwardRemittance({
                    beneficiary: beneficiary,
                    token_address: tokenAddress,
                    amount: amount,
                    nonce: currentNonce
                });

                inwardNonceExists[currentNonce] = true;
                inwardNonceCount++;

                emit InboundTransferRecorded(
                    currentNonce,
                    beneficiary,
                    tokenAddress,
                    amount,
                    block.timestamp
                );

                unchecked { i++; }
            }
            lastInwardNonce = prevNonce;
        }

        lastFinalizedHash = _latestFinalizedHash;
        emit ProcessedTransaction(_lastFinalizedHash, _latestFinalizedHash, transfersLength);
    }

    function claim(uint64 nonce) external nonReentrant {
        InwardRemittance storage transfer = inwardTransfers[nonce];

        if (transfer.nonce == 0 || !inwardNonceExists[nonce]) revert NonceDoesNotExist();
        if (_claimedNonces[nonce]) revert TransferAlreadyProcessed(); // New check for claimed nonces

        uint128 amount = transfer.amount;
        address tokenAddress = transfer.token_address;
        
        if (tokenAddress == address(0)) {
            // Native via qToken
            qToken.mint(transfer.beneficiary, amount);
        } else {
            // ERC20 token transfer
            if (!supportedTokens[tokenAddress]) revert UnsupportedToken();
            if (tokenDisabled[tokenAddress]) revert TokenDisabled(tokenAddress);
            require(tokenAddress.code.length > 0, "Invalid token contract");
            
            IERC20(tokenAddress).safeTransfer(transfer.beneficiary, amount);
        }

        _claimedNonces[nonce] = true; // Mark nonce as claimed

        emit TransferClaimed(
            nonce,
            transfer.beneficiary,
            transfer.token_address,
            amount,
            block.timestamp
        );
    }

    // ========== Token Management ==========

    function _addTokenSupport(address token) private {
        require(token != address(0), "Invalid token address");
        require(token != address(qToken), "Cannot modify native token");
        require(token.code.length > 0, "Not a contract");
        
        supportedTokens[token] = true;
        emit TokenSupportUpdated(token, true, false);
    }

    function addSupportedToken(address token) external {
        _addTokenSupport(token);
    }

    function setTokenDisabled(address token, bool disabled) external {
        require(supportedTokens[token], "Token not supported");
        tokenDisabled[token] = disabled;
        emit TokenSupportUpdated(token, true, disabled);
    }

    function removeTokenSupport(address token) external {
        require(supportedTokens[token], "Token not supported");
        supportedTokens[token] = false;
        tokenDisabled[token] = false;
        emit TokenSupportUpdated(token, false, false);
    }

    // ========== Admin Functions ==========

    function setVerifier(address newVerifier) external {
        if (newVerifier == address(0)) revert InvalidVerifierAddress();
        emit VerifierChanged(address(verifierRouter), newVerifier);
        verifierRouter = RiscZeroVerifierRouter(newVerifier);
    }

    function setTokenContract(address newToken) external {
        if (newToken == address(0)) revert InvalidTokenAddress();
        emit TokenContractChanged(address(qToken), newToken);
        qToken = QTOVToken(newToken);
    }

    function setImageId(bytes32 _imageId) external {
        if (_imageId == bytes32(0)) revert InvalidImageId();
        IMAGE_ID = _imageId;
    }

    function setLastFinalizedHash(bytes32 _hash) external {
        lastFinalizedHash = _hash;
    }

    function getInwardNonceCount() external view returns (uint64) {
        return inwardNonceCount;
    }

    // view function to check if a nonce has been claimed
    function isNonceClaimed(uint64 nonce) external view returns (bool) {
        return _claimedNonces[nonce];
    }

    function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
        if (token == address(0)) {
            payable(owner()).transfer(amount);
        } else {
            IERC20(token).safeTransfer(owner(), amount);
        }
    }
}