// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Script, console} from "forge-std/Script.sol";
import {Atlas} from "../src/Atlas.sol";

/**
 * @notice Script to verify if an EOA is delegated to Atlas using EIP-7702
 *
 * @dev This script checks if an EOA has delegated its execution to a contract
 * and extracts the delegation address from the EIP-7702 delegation indicator.
 *
 * EIP-7702 Delegation Format:
 * The account's code should be: (0xef0100 || <contract-address>)
 * - 0xef: Magic byte indicating delegation
 * - 0x01: Version
 * - 0x00: Reserved byte
 * - Next 20 bytes: Address of the delegated contract
 *
 * USAGE:
 * ```bash
 * export EOA_ADDRESS=0x123456789...
 * forge script script/Verify_Delegation.s.sol:VerifyDelegationScript --rpc-url $RPC_URL -vvvv
 * ```
 */
contract VerifyDelegationScript is Script {
    // EIP-7702 magic bytes
    bytes3 constant EIP7702_MAGIC = 0xef0100;
    
    // Expected Atlas address
    address constant ATLAS_ADDRESS = 0x3d965CFdDA791589cCAB955498D509f2F7E30b79;

    function run() public view {
        address eoaAddress = vm.envAddress("EOA_ADDRESS");
        _verifyDelegation(eoaAddress);
    }

    function _verifyDelegation(address eoaAddress) internal view {
        console.log("=== EIP-7702 Delegation Verification ===");
        console.log("Checking EOA:", eoaAddress);
        console.log("");

        // Get the code at the EOA address
        bytes memory code = eoaAddress.code;

        if (code.length == 0) {
            console.log("Status: NO DELEGATION");
            console.log("The EOA has no code (standard EOA)");
            return;
        }

        console.log("Status: DELEGATION DETECTED");
        console.log("");

        // Check if it's an EIP-7702 delegation
        if (code.length == 23) {
            // Extract magic bytes
            bytes3 magic = bytes3(code);
            
            if (magic == EIP7702_MAGIC) {
                console.log("Type: EIP-7702 Delegation");
                console.log("");

                // Extract the delegated address (bytes 3-22, skipping the 3-byte magic)
                address delegatedTo;
                assembly {
                    // mload(add(code, 32)) loads the first 32 bytes of actual data
                    // We need to skip the first 3 bytes (magic: 0xef0100)
                    // Shift left by 24 bits (3 bytes) to remove magic, then shift right by 96 bits to get address
                    let data := mload(add(code, 32))
                    delegatedTo := shr(96, shl(24, data))
                }

                console.log("Delegated to:", delegatedTo);
                
                // Check if it's delegated to Atlas
                if (delegatedTo == ATLAS_ADDRESS) {
                    console.log("Result: DELEGATED TO ATLAS");
                    console.log("The EOA is correctly delegated to Atlas!");
                } else {
                    console.log("Result: DELEGATED TO ANOTHER CONTRACT");
                    console.log("Expected Atlas:", ATLAS_ADDRESS);
                }
            } else {
                console.log("Type: Unknown delegation format");
                console.log("Magic bytes:", vm.toString(magic));
                console.log("This is not a standard EIP-7702 delegation");
            }
        } else {
            console.log("Type: Unknown (account's code too short for EIP-7702)");
            console.log("The account's code is too short to be a valid EIP-7702 delegation");
        }
    }
}
