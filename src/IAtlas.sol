// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IERC1271} from "./IERC1271.sol";

interface IAtlas is IERC1271 {
    event CallExecuted(address indexed sender, address indexed to, bytes returnData);

    error InvalidSigner();
    error ExpiredSignature();
    error Unauthorized();
    error NonceAlreadyUsed();
    error CallReverted();

    /// @notice Represents a single call within a batch.
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    function executeCall(Call calldata call, uint256 deadline, uint256 nonce, uint8 v, bytes32 r, bytes32 s)
        external
        payable;
    function executeCalls(Call[] calldata calls, uint256 deadline, uint256 nonce, uint8 v, bytes32 r, bytes32 s)
        external
        payable;
    function executeCall(Call calldata call) external payable;
    function executeCalls(Call[] calldata calls) external payable;
}
