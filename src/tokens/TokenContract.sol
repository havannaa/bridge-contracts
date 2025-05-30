// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract TKNB is ERC20, ERC20Burnable, Ownable {
    constructor(address initialOwner) ERC20("Token B", "TKNB") Ownable(initialOwner) {
        _mint(initialOwner, 1_000_000 * 10 ** decimals()); // Optional: Mint initial supply
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
}
