// SPDX-License-Identifier: UNLICENSE
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Deadcoin is ERC20 {
    constructor() ERC20("Deadcoin", "PIXEL") {
        // We mint 1000 to our BOB for the test
        _mint(0x70997970C51812dc3A010C7d01b50e0d17dc79C8, 1000);
    }
}