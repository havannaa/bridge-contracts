// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract QTOVToken is ERC20, ERC20Burnable, Ownable {
    // Custom errors
    error OnlyBridge();
    error ZeroAddress();
    error BridgeNotInitialized();

    address public bridge;
    bool public bridgeInitialized; // Track if bridge has been set

    event BridgeUpdated(address indexed newBridge);

    constructor(
        address initialOwner
    ) ERC20("Quantova", "QTOV") Ownable(initialOwner) {}

    modifier onlyBridge() {
        if (msg.sender != bridge) revert OnlyBridge();
        _;
    }

    function setBridge(address _bridge) external onlyOwner {
        if (_bridge == address(0)) revert ZeroAddress();
        bridge = _bridge;

        // Only emit event if bridge wasn't previously initialized or if bridge address changed
        if (!bridgeInitialized || bridge != _bridge) {
            bridgeInitialized = true; // Mark bridge as initialized
            emit BridgeUpdated(_bridge);
        }
    }

    function mint(address to, uint256 amount) external virtual onlyBridge {
        if (!bridgeInitialized) revert BridgeNotInitialized();
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external virtual onlyBridge {
        _burn(from, amount);
    }

    function burnFrom(address account, uint256 amount) public virtual override {
        if (msg.sender == bridge) {
            // Bridge can bypass allowance check
            _burn(account, amount);
            return;
        }

        super.burnFrom(account, amount);
    }
}
