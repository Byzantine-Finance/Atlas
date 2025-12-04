// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import "../src/Atlas.sol";
import "./Deadcoin.sol";
import {console} from "forge-std/console.sol";

// Need to copy those constant from Atlas.sol otherwise trying to read them from the contract fail
bytes32 constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
bytes32 constant CALL_TYPEHASH = keccak256("Call(address to,uint256 value,bytes data)");
bytes32 constant EXECUTE_CALLS_TYPEHASH =
    keccak256("ExecuteCalls(Call[] calls,uint256 deadline,uint256 nonce)Call(address to,uint256 value,bytes data)");
bytes32 constant EXECUTE_CALL_TYPEHASH =
    keccak256("ExecuteCall(Call call,uint256 deadline,uint256 nonce)Call(address to,uint256 value,bytes data)");

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
        vm.startBroadcast(bob.privateKey);
    }

    // Utilitary function to get the digest of several calls
    function getDigest(Atlas.Call[] memory calls, uint256 deadline, uint256 cnonce)
        internal
        view
        returns (bytes32 digest)
    {
        bytes32[] memory callStructHashes = new bytes32[](calls.length);
        for (uint256 i; i < calls.length; ++i) {
            callStructHashes[i] =
                keccak256(abi.encode(CALL_TYPEHASH, calls[i].to, calls[i].value, keccak256(calls[i].data)));
        }

        // Retrieve eip-712 digest
        bytes32 encodeData = keccak256(abi.encodePacked(callStructHashes));
        bytes32 hashStruct = keccak256(abi.encode(EXECUTE_CALLS_TYPEHASH, encodeData, deadline, cnonce));

        // IMPORTANT!! `Atlas(alice.addr).DOMAIN_SEPARATOR()` need ot be called from alice bytecodes because it doesn't have the same address as the atlas deployed one.
        digest = keccak256(abi.encodePacked(hex"1901", Atlas(alice.addr).DOMAIN_SEPARATOR(), hashStruct));
    }

    // Utilitary function to get the digest of one single call
    function getDigest(Atlas.Call memory call, uint256 deadline, uint256 cnonce)
        internal
        view
        returns (bytes32 digest)
    {
        // Retrieve eip-712 digest
        bytes32 encodeData = keccak256(abi.encode(CALL_TYPEHASH, call.to, call.value, keccak256(call.data)));
        bytes32 hashStruct = keccak256(abi.encode(EXECUTE_CALL_TYPEHASH, encodeData, deadline, cnonce));

        // IMPORTANT!! `Atlas(alice.addr).DOMAIN_SEPARATOR()` need ot be called from alice bytecodes because it doesn't have the same address as the atlas deployed one.
        digest = keccak256(abi.encodePacked(hex"1901", Atlas(alice.addr).DOMAIN_SEPARATOR(), hashStruct));
    }

    // Sucess calls execution with one call
    function test_executeSuccesfull() public {
        Atlas.Call memory call = IAtlas.Call({
            to: address(deadcoin),
            value: 0,
            data: hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        });
        Atlas.Call[] memory calls = new IAtlas.Call[](1);
        calls[0] = call;

        uint256 deadline = block.timestamp + 1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(calls, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        Atlas(alice.addr).executeCalls(calls, deadline, cnonce, v, r, s);

        // Check balance has decreased
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == 90);
    }

    // Sucess calls execution with two calls
    function test_executeSuccesfullMulticalls() public {
        Atlas.Call memory call = IAtlas.Call({
            to: address(deadcoin),
            value: 0,
            data: hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        });
        Atlas.Call[] memory calls = new IAtlas.Call[](2);
        calls[0] = call;
        calls[1] = call;

        uint256 deadline = block.timestamp + 1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(calls, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        Atlas(alice.addr).executeCalls(calls, deadline, cnonce, v, r, s);

        // Check balance has decreased
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == 80);
    }

    // Sending the wrong signature
    function test_executeFail() public {
        Atlas.Call memory call = IAtlas.Call({
            to: address(deadcoin),
            value: 0,
            data: hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        });
        Atlas.Call[] memory calls = new IAtlas.Call[](1);
        calls[0] = call;

        uint256 deadline = block.timestamp + 1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(calls, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        // tempered r
        r = bytes32(0);

        vm.expectRevert(); // Expect to revert because of the wrong value in the call (invalid signature)

        Atlas(alice.addr).executeCalls(calls, deadline, cnonce, v, r, s);

        // Check balance hasn't changed        
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == 100);
    }

    // Replaying the same call twice with the same signature
    function test_replayFail() public {
        Atlas.Call memory call = IAtlas.Call({
            to: address(deadcoin),
            value: 0,
            data: hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        });
        Atlas.Call[] memory calls = new IAtlas.Call[](1);
        calls[0] = call;

        uint256 deadline = block.timestamp + 1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(calls, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        Atlas(alice.addr).executeCalls(calls, deadline, cnonce, v, r, s);

        vm.expectRevert(); // we should not be able to resend the same call signed

        Atlas(alice.addr).executeCalls(calls, deadline, cnonce, v, r, s);

        // Check balance has only decreased by 10  
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == 90);
    }

    // Sending expired call with correct signature so the call should fail
    function test_expiredDeadline() public {
        Atlas.Call memory call = IAtlas.Call({
            to: address(deadcoin),
            value: 0,
            data: hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        });
        Atlas.Call[] memory calls = new IAtlas.Call[](1);
        calls[0] = call;

        uint256 deadline = block.timestamp -1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(calls, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        vm.expectRevert();
        Atlas(alice.addr).executeCalls(calls, deadline, cnonce, v, r, s);

        // Check balance hasn't changed        
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == 100);
    }

    // Sucessfully call `executeCall` with a simple call
    function test_simpleCall() public {
        Atlas.Call memory call = IAtlas.Call({
            to: address(deadcoin),
            value: 0,
            data: hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        });

        uint256 deadline = block.timestamp + 1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(call, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        Atlas(alice.addr).executeCall(call, deadline, cnonce, v, r, s);

        // Check balance has decreased  
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == 90);
    }

    // Send an invalid signature with our simple call
    function test_simpleCallInvalidSignature() public {
        Atlas.Call memory call = IAtlas.Call({
            to: address(deadcoin),
            value: 0,
            data: hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        });

        uint256 deadline = block.timestamp -1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(call, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        // tempered s
        s = bytes32(0);

        vm.expectRevert();
        Atlas(alice.addr).executeCall(call, deadline, cnonce, v, r, s);

        // Check balance hasn't changed        
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == 100);
    }

    // Send an invalid signature with our simple call
    function test_simpleCallReplayFail() public {
        Atlas.Call memory call = IAtlas.Call({
            to: address(deadcoin),
            value: 0,
            data: hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        });

        uint256 deadline = block.timestamp + 1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(call, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        Atlas(alice.addr).executeCall(call, deadline, cnonce, v, r, s);

        vm.expectRevert(); // we should not be able to resend the same call signed
        Atlas(alice.addr).executeCall(call, deadline, cnonce, v, r, s);

        // Check balance has only decreased by 10
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == 90);
    }

    // Alice can call her own EOA code should be sucessful
    function test_executeOwnCall() public {
        Atlas.Call memory call = IAtlas.Call({
            to: address(deadcoin),
            value: 0,
            data: hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        });

        vm.stopBroadcast();
        vm.broadcast(alice.privateKey);
        Atlas(alice.addr).executeCall(call);

        // Check balance has only decreased by 10
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == 90);
    }

    // Alice can call her own EOA code should be sucessful with multiple calls
    function test_executeOwnCallMultipleCalls() public {
        Atlas.Call memory call = IAtlas.Call({
            to: address(deadcoin),
            value: 0,
            data: hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        });
        Atlas.Call[] memory calls = new IAtlas.Call[](2);
        calls[0] = call;
        calls[1] = call;

        vm.stopBroadcast();
        vm.broadcast(alice.privateKey);
        Atlas(alice.addr).executeCalls(calls);

        // Check balance has decreased
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == 80);
    }

    // Bob should not be able to call Alice's function without her signature
    function test_bobFailCall() public {
        Atlas.Call memory call = IAtlas.Call({
            to: address(deadcoin),
            value: 0,
            data: hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        });
        Atlas.Call[] memory calls = new IAtlas.Call[](2);
        calls[0] = call;
        calls[1] = call;

        vm.expectRevert();
        Atlas(alice.addr).executeCalls(calls);

        // Check balance not have changed
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == 100);
    }

}
