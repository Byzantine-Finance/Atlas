// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Receiver} from "@solady/accounts/Receiver.sol";
import {IAtlas, IERC1271} from "./IAtlas.sol";

/**
 * @title Atlas
 * @author Byzantine
 * @notice This contract is designed to be used with https://eips.ethereum.org/EIPS/eip-7702 [EIP-7702]
 * to enable transaction batching and sponsoring for EOAs.
 *
 * EIP-7702 allows EOAs to temporarily set contract code, enabling them to
 * act as smart contract wallets without deploying a separate contract. This provides a seamless
 * way to add advanced features like batch execution and sponsored transactions to existing EOAs.
 *
 * @dev By delegating to the Atlas contract EOAs can execute single or multiple calls in a batch, either directly
 * or through a sponsor using https://eips.ethereum.org/EIPS/eip-712[EIP-712] signatures.
 * The contract is also compatible with https://eips.ethereum.org/EIPS/eip-1271 [ERC-1271] to verify whether
 * a signature on a behalf of a given contract is valid.
 *
 * ## Key Features:
 *
 * 1. **Batch Execution**: Execute multiple calls atomically in a single transaction
 * 2. **Sponsored Transactions**: Allow third parties (sponsors) to pay gas fees on behalf of the EOA
 * 3. **Replay Protection**: Uses nonces to prevent signature replay attacks
 * 4. **EIP-712 Signatures**: Secure and human-readable signature format
 * 5. **ERC-1271 Support**: Can validate signatures for smart contract interactions
 *
 * ## Security Considerations:
 *
 * - **Nonce Management**: Each nonce can only be used once to prevent replay attacks
 * - **Deadline**: Signatures expire after the deadline timestamp
 * - **Signer Verification**: Only signatures from the contract itself (representing the EOA) are valid
 * - **Authorization**: Direct calls (without signature) can only be made by the contract itself (representing the EOA)
 *
 * ## EIP-712 Domain:
 * - Name: "Byzantine"
 * - Version: "1"
 * - ChainId: Current chain ID
 * - VerifyingContract: This address of the EOA delegating to this contract
 *
 * ## Storage:
 * Uses ERC-7201 namespaced storage pattern to avoid storage collisions in the case the EOA delegate to another contract.
 */
contract Atlas is Receiver, IAtlas {
    /* ===================== CONSTANTS ===================== */

    bytes32 public constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 public constant CALL_TYPEHASH = keccak256("Call(address to,uint256 value,bytes data)");

    bytes32 public constant EXECUTE_CALLS_TYPEHASH =
        keccak256("ExecuteCalls(Call[] calls,uint256 deadline,uint256 nonce)Call(address to,uint256 value,bytes data)");

    bytes32 public constant EXECUTE_CALL_TYPEHASH =
        keccak256("ExecuteCall(Call call,uint256 deadline,uint256 nonce)Call(address to,uint256 value,bytes data)");

    bytes32 constant NAME_HASH = keccak256("Byzantine");

    bytes32 constant VERSION_HASH = keccak256("1");

    // keccak256(abi.encode(uint256(keccak256("byzantine.storage.atlas")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ATLAS_STORAGE_LOCATION =
        0x7b665f45e4b9dda43280f67c1696d154475f0e64f9b905838885415666944f00;

    /* ===================== STORAGE ===================== */

    /// @custom:storage-location erc7201:byzantine.storage.atlas
    struct AtlasStorage {
        /// @notice Mapping of used nonces (true if already used)
        /// @dev Used to prevent replay attacks
        mapping(uint256 => bool) isNonceUsed;
    }

    /* ===================== EXTERNAL FUNCTIONS ===================== */

    /// @inheritdoc IAtlas
    function executeCall(Call calldata call, uint256 deadline, uint256 nonce, uint8 v, bytes32 r, bytes32 s)
        external
        payable
    {
        AtlasStorage storage $ = _getAtlasStorage();

        // Verify deadline
        require(block.timestamp <= deadline, ExpiredSignature());

        // Verify nonce
        require(!$.isNonceUsed[nonce], NonceAlreadyUsed());

        // Retrieve eip-712 digest
        bytes32 encodeData = keccak256(abi.encode(CALL_TYPEHASH, call.to, call.value, keccak256(call.data)));
        bytes32 hashStruct = keccak256(abi.encode(EXECUTE_CALL_TYPEHASH, encodeData, deadline, nonce));
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR(), hashStruct));

        // Recover the signer
        address recoveredAddress = ECDSA.recover(digest, v, r, s);
        require(recoveredAddress == address(this), InvalidSigner());

        // Mark the nonce as used
        $.isNonceUsed[nonce] = true;

        _executeCall(call);
    }

    /// @inheritdoc IAtlas
    function executeCalls(Call[] calldata calls, uint256 deadline, uint256 nonce, uint8 v, bytes32 r, bytes32 s)
        external
        payable
    {
        AtlasStorage storage $ = _getAtlasStorage();

        // Verify deadline
        require(block.timestamp <= deadline, ExpiredSignature());

        // Verify nonce
        require(!$.isNonceUsed[nonce], NonceAlreadyUsed());

        // Hash each call individually
        bytes32[] memory callStructHashes = new bytes32[](calls.length);
        for (uint256 i; i < calls.length; ++i) {
            callStructHashes[i] =
                keccak256(abi.encode(CALL_TYPEHASH, calls[i].to, calls[i].value, keccak256(calls[i].data)));
        }

        // Retrieve eip-712 digest
        bytes32 encodeData = keccak256(abi.encodePacked(callStructHashes));
        bytes32 hashStruct = keccak256(abi.encode(EXECUTE_CALLS_TYPEHASH, encodeData, deadline, nonce));
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR(), hashStruct));

        // Recover the signer
        address recoveredAddress = ECDSA.recover(digest, v, r, s);
        require(recoveredAddress == address(this), InvalidSigner());

        // Mark the nonce as used
        $.isNonceUsed[nonce] = true;

        _executeBatch(calls);
    }

    /// @inheritdoc IAtlas
    function executeCall(Call calldata call) external payable {
        require(msg.sender == address(this), Unauthorized());
        _executeCall(call);
    }

    /// @inheritdoc IAtlas
    function executeCalls(Call[] calldata calls) external payable {
        require(msg.sender == address(this), Unauthorized());
        _executeBatch(calls);
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (address recovered,,) = ECDSA.tryRecover(hash, signature);
        return recovered == address(this) ? this.isValidSignature.selector : bytes4(0);
    }

    /* ===================== PRIVATE FUNCTIONS ===================== */

    function _executeBatch(Call[] calldata calls) private {
        for (uint256 i; i < calls.length; ++i) {
            _executeCall(calls[i]);
        }
    }

    function _executeCall(Call calldata callItem) private {
        (bool success, bytes memory returndata) = callItem.to.call{value: callItem.value}(callItem.data);
        require(success, CallReverted());
        emit CallExecuted(msg.sender, callItem.to, returndata);
    }

    function _getAtlasStorage() private pure returns (AtlasStorage storage $) {
        assembly {
            $.slot := ATLAS_STORAGE_LOCATION
        }
    }

    /* ===================== VIEW FUNCTIONS ===================== */

    /// @dev Returns the domain separator used in the encoding of the signatures, as defined by {EIP712}.
    /// forge-lint: disable-next-line(mixed-case-function)
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    /// @dev Returns whether a `nonce` has already been used by the signer
    function isNonceUsed(uint256 nonce) public view returns (bool) {
        return _getAtlasStorage().isNonceUsed[nonce];
    }
}
