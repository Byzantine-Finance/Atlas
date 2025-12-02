// SPDX-License-Identifier: UNLICENSE
pragma solidity 0.8.30;

interface IAtlas {
    event CallExecuted(address indexed sender, address indexed to, uint256 value, bytes data);
    event BatchExecuted(uint256 indexed nonce, Call[] calls);

    error InvalidSignature();

    /// @notice Represents a single call within a batch.
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    function execute(Call[] calldata calls, uint8 v, bytes32 r, bytes32 s) external payable;
}

contract Atlas is IAtlas{
    uint256 public nonce;

    constructor() {
        // Initiate nonce to '0'
        nonce = 0;
    }

    function execute(Call[] calldata calls, uint8 v, bytes32 r, bytes32 s) external payable {
        bytes memory encodedCalls;
        for (uint256 i = 0; i < calls.length; i++) {
            encodedCalls = abi.encodePacked(encodedCalls, calls[i].to, calls[i].value, calls[i].data);
        }
        bytes32 digest = keccak256(abi.encodePacked(nonce, encodedCalls));

        // Recover the signer from the provided signature.
        address recoveredAddress = ecrecover(digest, v, r, s);
        require(recoveredAddress == address(this), InvalidSignature());

        _executeBatch(calls);
    }

    function _executeBatch(Call[] calldata calls) internal {
        uint256 currentNonce = nonce;
        nonce++; // Increment nonce to protect against replay attacks

        for (uint256 i = 0; i < calls.length; i++) {
            _executeCall(calls[i]);
        }

        emit BatchExecuted(currentNonce, calls);
    }

    function _executeCall(Call calldata callItem) internal {
        // address(this) in the contract equals the EOA address NOT the contract address
        (bool success,) = callItem.to.call{value: callItem.value}(callItem.data);
        require(success, "Call reverted");
        emit CallExecuted(msg.sender, callItem.to, callItem.value, callItem.data);
    }
}
