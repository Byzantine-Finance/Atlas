// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Script, console} from "forge-std/Script.sol";
import {Atlas} from "../src/Atlas.sol";

/**
 * @notice Script to deploy the Atlas contract using CREATE2 for deterministic addresses across chains
 *
 * Usage:
 * forge script script/Deploy_Atlas_v1.s.sol --rpc-url $RPC_URL --broadcast --etherscan-api-key $ETHERSCAN_API_KEY --verify -vvvv
 *
 * The same salt will produce the same address on different chains if:
 * 1. The deployer address is the same
 * 2. The contract bytecode is identical
 * 3. The salt is the same
 *
 * To get the predicted address before deployment:
 * forge script script/Deploy_Atlas_v1.s.sol --sig "predictAddress()"
 */
contract DeployAtlasV1Script is Script {
    Atlas public atlas;

    // Salt for CREATE2 - change this to get a different address
    bytes32 public constant SALT = keccak256("byzantine.atlas.v1");
    address public constant DETERMINISTIC_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function run() public {
        vm.startBroadcast();

        // Deploy using CREATE2
        atlas = new Atlas{salt: SALT}();

        vm.stopBroadcast();

        console.log("Atlas deployed at:", address(atlas));
        console.log("Salt used:", vm.toString(SALT));
    }

    /**
     * @notice Predict the address where Atlas will be deployed
     * @dev Useful to know the address before actually deploying
     */
    function predictAddress() public pure returns (address) {
        return vm.computeCreate2Address(SALT, keccak256(type(Atlas).creationCode), DETERMINISTIC_DEPLOYER);
    }
}
