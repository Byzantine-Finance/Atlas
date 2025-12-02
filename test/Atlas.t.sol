// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import "../src/Atlas.sol";
import "./Deadcoin.sol";
import {console} from "forge-std/console.sol";

contract AtlasTest is Test {
    Atlas public atlas;
    Deadcoin public deadcoin;

    // Alice's address and private key (EOA with no initial contract code).
    Vm.Wallet alice = vm.createWallet("alice");
    
    // Bob's address and private key (Bob will execute transactions on Alice's behalf).
    Vm.Wallet bob = vm.createWallet("bob");

    function setUp() public {
        atlas = new Atlas();

        // Alice signs an authorization
        Vm.SignedDelegation memory signedDelegation = vm.signDelegation(address(atlas), alice.privateKey);
        // Bob send the authorization signed by Alice
        vm.broadcast(bob.privateKey);
        vm.attachDelegation(signedDelegation);

        // We create our ERC20 token
        deadcoin = new Deadcoin();

        vm.broadcast(bob.privateKey);
        deadcoin.transfer(alice.addr, 100);

        // set bob as sponsor
        vm.broadcast(bob.privateKey);
        Atlas(alice.addr).addSponsor(bob.addr);
    }

    function getDigest(Atlas.Call[] memory calls, uint256 deadline, uint nonce) internal view returns (bytes32 digest) {
        bytes memory encodedCalls;
        for (uint256 i = 0; i < calls.length; i++) {
            encodedCalls = abi.encodePacked(encodedCalls, calls[i].to, calls[i].value, calls[i].data);
        }

        // IMPORTANT!! `Atlas(alice.addr).DOMAIN_SEPARATOR()` need ot be called from alice bytecodes because it doesn't have the same address as the atlas deployed one.
        digest = keccak256(
            abi.encodePacked(hex"1901", Atlas(alice.addr).DOMAIN_SEPARATOR(), keccak256(abi.encodePacked(deadline, nonce, encodedCalls)))
        );
    }

    function test_executeSuccesfull() public {
        Atlas.Call memory call = IAtlas.Call({
            to: address(deadcoin),
            value: 0,
            data: hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        });
        Atlas.Call[] memory calls = new IAtlas.Call[](1);
        calls[0] = call;

        uint256 deadline = block.timestamp + 1;

        bytes32 digest = getDigest(calls, deadline, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        vm.broadcast(bob.privateKey);
        Atlas(alice.addr).execute(calls, deadline, v, r, s);
    }

    function test_executeFail() public {
        Atlas.Call memory call = IAtlas.Call({
            to: address(deadcoin),
            value: 0,
            data: hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        });
        Atlas.Call[] memory calls = new IAtlas.Call[](1);
        calls[0] = call;

        uint256 deadline = block.timestamp + 1;

        bytes32 digest = getDigest(calls, deadline, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        // tempered r
        r = bytes32(0);

        vm.expectRevert(); // Expect to revert because of the wrong value in the call (invalid signature)
        
        vm.broadcast(bob.privateKey);
        Atlas(alice.addr).execute(calls, deadline, v, r, s);
    }

    function test_replayFail() public {
        Atlas.Call memory call = IAtlas.Call({
            to: address(deadcoin),
            value: 0,
            data: hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        });
        Atlas.Call[] memory calls = new IAtlas.Call[](1);
        calls[0] = call;

        uint256 deadline = block.timestamp + 1;

        bytes32 digest = getDigest(calls, deadline, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        vm.broadcast(bob.privateKey);
        Atlas(alice.addr).execute(calls, deadline, v, r, s);

        vm.expectRevert(); // we should not be able to resend the same call signed
        
        vm.broadcast(bob.privateKey);
        Atlas(alice.addr).execute(calls, deadline, v, r, s);
    }
}
