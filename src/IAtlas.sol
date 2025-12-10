// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IERC1271} from "./IERC1271.sol";

interface IAtlas is IERC1271 {
    /* ===================== EVENTS ===================== */

    event CallExecuted(address indexed sender, address indexed to, bytes returnData);

    /* ===================== ERRORS ===================== */

    error InvalidSigner();
    error ExpiredSignature();
    error Unauthorized();
    error NonceAlreadyUsed();
    error CallReverted();

    /* ===================== STRUCTS ===================== */

    /// @notice Represents a single call to execute on behalf of the EOA.
    struct Call {
        /// @param to The target address to call
        address to;
        /// @param value The amount of ETH to send with the call
        uint256 value;
        /// @param data The calldata to send to the target address
        bytes data;
    }

    /* ===================== FUNCTIONS ===================== */

    /// @notice Executes a single call with signature verification (sponsored execution)
    /// @param call The call to execute
    /// @param deadline The timestamp after which the signature expires
    /// @param nonce The nonce to prevent replay attacks
    /// @param v The recovery id of the signature
    /// @param r The r component of the signature
    /// @param s The s component of the signature
    function executeCall(Call calldata call, uint256 deadline, uint256 nonce, uint8 v, bytes32 r, bytes32 s)
        external
        payable;

    /// @notice Executes multiple calls in a batch with signature verification (sponsored execution)
    /// @param calls The array of calls to execute
    /// @param deadline The timestamp after which the signature expires
    /// @param nonce The nonce to prevent replay attacks
    /// @param v The recovery id of the signature
    /// @param r The r component of the signature
    /// @param s The s component of the signature
    function executeCalls(Call[] calldata calls, uint256 deadline, uint256 nonce, uint8 v, bytes32 r, bytes32 s)
        external
        payable;

    /// @notice Executes a single call without signature verification (direct execution by the EOA)
    /// @param call The call to execute
    function executeCall(Call calldata call) external payable;

    /// @notice Executes multiple calls in a batch without signature verification (direct execution by the EOA)
    /// @param calls The array of calls to execute
    function executeCalls(Call[] calldata calls) external payable;
}
