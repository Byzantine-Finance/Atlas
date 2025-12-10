// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {MockERC20} from "@solady-test/utils/mocks/MockERC20.sol";
import {MockERC721} from "@solady-test/utils/mocks/MockERC721.sol";
import {MockERC1155} from "@solady-test/utils/mocks/MockERC1155.sol";
import {Atlas} from "../src/Atlas.sol";
import {IAtlas, IERC1271} from "../src/IAtlas.sol";
/// forge-lint: disable-next-line(unaliased-plain-import)
import "forge-std/Test.sol";

contract EtherSenderContract {
    error FailedToSendEther();

    receive() external payable {}

    function sendEther(address to, uint256 amount) external {
        (bool success,) = to.call{value: amount}("");
        require(success, FailedToSendEther());
    }
}

contract AtlasTest is Test {
    Atlas public atlas;
    MockERC20 public deadcoin;

    // Initial MockERC20 balance for Alice
    uint256 constant INITIAL_AMOUNT = 100;

    // Alice's address and private key (EOA with no initial contract code).
    Vm.Wallet alice = vm.createWallet("alice");

    // Bob's address and private key (Bob will execute transactions on Alice's behalf).
    Vm.Wallet bob = vm.createWallet("bob");

    // Charlie's address and private key (Charlie will try to call Alice's function without her signature).
    Vm.Wallet charlie = vm.createWallet("charlie");

    function setUp() public {
        atlas = new Atlas();

        // Alice signs an authorization
        Vm.SignedDelegation memory signedDelegation = vm.signDelegation(address(atlas), alice.privateKey);
        // Bob send the authorization signed by Alice
        vm.prank(bob.addr);
        vm.attachDelegation(signedDelegation);

        // Create an ERC20 Mock token
        deadcoin = new MockERC20("Deadcoin", "DEAD", 18);

        // Mint initial balance to Alice
        deadcoin.mint(alice.addr, INITIAL_AMOUNT);
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
                keccak256(abi.encode(atlas.CALL_TYPEHASH(), calls[i].to, calls[i].value, keccak256(calls[i].data)));
        }

        // Retrieve eip-712 digest
        bytes32 encodeData = keccak256(abi.encodePacked(callStructHashes));
        bytes32 hashStruct = keccak256(abi.encode(atlas.EXECUTE_CALLS_TYPEHASH(), encodeData, deadline, cnonce));

        // IMPORTANT!! `Atlas(payable(alice.addr)).DOMAIN_SEPARATOR()` need ot be called from alice bytecodes because it doesn't have the same address as the atlas deployed one.
        digest = keccak256(abi.encodePacked(hex"1901", Atlas(payable(alice.addr)).DOMAIN_SEPARATOR(), hashStruct));
    }

    // Utilitary function to get the digest of one single call
    function getDigest(Atlas.Call memory call, uint256 deadline, uint256 cnonce)
        internal
        view
        returns (bytes32 digest)
    {
        // Retrieve eip-712 digest
        bytes32 encodeData = keccak256(abi.encode(atlas.CALL_TYPEHASH(), call.to, call.value, keccak256(call.data)));
        bytes32 hashStruct = keccak256(abi.encode(atlas.EXECUTE_CALL_TYPEHASH(), encodeData, deadline, cnonce));

        // IMPORTANT!! `Atlas(payable(alice.addr)).DOMAIN_SEPARATOR()` need ot be called from alice bytecodes because it doesn't have the same address as the atlas deployed one.
        digest = keccak256(abi.encodePacked(hex"1901", Atlas(payable(alice.addr)).DOMAIN_SEPARATOR(), hashStruct));
    }

    // Sucess calls execution with one call
    function test_executeSuccesfull(uint256 amount) public {
        vm.assume(amount <= INITIAL_AMOUNT);

        Atlas.Call memory call =
            IAtlas.Call({to: address(deadcoin), value: 0, data: abi.encodeCall(deadcoin.transfer, (bob.addr, amount))});
        Atlas.Call[] memory calls = new IAtlas.Call[](1);
        calls[0] = call;

        uint256 deadline = block.timestamp + 1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(calls, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        vm.prank(bob.addr);
        IAtlas(alice.addr).executeCalls(calls, deadline, cnonce, v, r, s);

        // Check balance has decreased
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == INITIAL_AMOUNT - amount);

        // Check nonce is marked as used
        assert(Atlas(payable(alice.addr)).isNonceUsed(cnonce));
    }

    // Sucess calls execution with two calls
    function test_executeSuccesfullMulticalls(uint256 amount) public {
        vm.assume(amount <= INITIAL_AMOUNT / 2);

        Atlas.Call memory call =
            IAtlas.Call({to: address(deadcoin), value: 0, data: abi.encodeCall(deadcoin.transfer, (bob.addr, amount))});
        Atlas.Call[] memory calls = new IAtlas.Call[](2);
        calls[0] = call;
        calls[1] = call;

        uint256 deadline = block.timestamp + 1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(calls, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        vm.prank(bob.addr);
        IAtlas(alice.addr).executeCalls(calls, deadline, cnonce, v, r, s);

        // Check balance has decreased
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == INITIAL_AMOUNT - (2 * amount));
    }

    // Sending the wrong signature
    function test_executeFail(uint256 amount) public {
        vm.assume(amount <= INITIAL_AMOUNT);

        Atlas.Call memory call =
            IAtlas.Call({to: address(deadcoin), value: 0, data: abi.encodeCall(deadcoin.transfer, (bob.addr, amount))});
        Atlas.Call[] memory calls = new IAtlas.Call[](1);
        calls[0] = call;

        uint256 deadline = block.timestamp + 1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(calls, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(charlie, digest);

        vm.expectRevert(IAtlas.InvalidSigner.selector);

        vm.prank(charlie.addr);
        IAtlas(alice.addr).executeCalls(calls, deadline, cnonce, v, r, s);

        // Check balance hasn't changed
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == INITIAL_AMOUNT);
    }

    // Replaying the same call twice with the same signature
    function test_replayFail(uint256 amount) public {
        vm.assume(amount <= INITIAL_AMOUNT);

        Atlas.Call memory call =
            IAtlas.Call({to: address(deadcoin), value: 0, data: abi.encodeCall(deadcoin.transfer, (bob.addr, amount))});
        Atlas.Call[] memory calls = new IAtlas.Call[](1);
        calls[0] = call;

        uint256 deadline = block.timestamp + 1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(calls, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        vm.prank(bob.addr);
        IAtlas(alice.addr).executeCalls(calls, deadline, cnonce, v, r, s);

        vm.expectRevert(IAtlas.NonceAlreadyUsed.selector);

        vm.prank(bob.addr);
        IAtlas(alice.addr).executeCalls(calls, deadline, cnonce, v, r, s);

        // Check balance has only decreased by 10
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == INITIAL_AMOUNT - amount);
    }

    // Sending expired call with correct signature so the call should fail
    function test_expiredDeadline(uint256 amount) public {
        vm.assume(amount <= INITIAL_AMOUNT);

        Atlas.Call memory call =
            IAtlas.Call({to: address(deadcoin), value: 0, data: abi.encodeCall(deadcoin.transfer, (bob.addr, amount))});
        Atlas.Call[] memory calls = new IAtlas.Call[](1);
        calls[0] = call;

        uint256 deadline = block.timestamp + 1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(calls, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        skip(2);
        vm.expectRevert(IAtlas.ExpiredSignature.selector);
        vm.prank(bob.addr);
        IAtlas(alice.addr).executeCalls(calls, deadline, cnonce, v, r, s);

        // Check balance hasn't changed
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == INITIAL_AMOUNT);
    }

    // Sucessfully call `executeCall` with a simple call
    function test_simpleCall(uint256 amount) public {
        vm.assume(amount <= INITIAL_AMOUNT);

        Atlas.Call memory call =
            IAtlas.Call({to: address(deadcoin), value: 0, data: abi.encodeCall(deadcoin.transfer, (bob.addr, amount))});

        uint256 deadline = block.timestamp + 1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(call, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        // Should emit CallExecuted event
        vm.expectEmit();
        emit IAtlas.CallExecuted(bob.addr, address(deadcoin), abi.encode(true));

        vm.prank(bob.addr);
        IAtlas(alice.addr).executeCall(call, deadline, cnonce, v, r, s);

        // Check balance has decreased
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == INITIAL_AMOUNT - amount);
    }

    // Send an invalid signature with our simple call
    function test_simpleCallInvalidSignature(uint256 amount) public {
        vm.assume(amount <= INITIAL_AMOUNT);

        Atlas.Call memory call =
            IAtlas.Call({to: address(deadcoin), value: 0, data: abi.encodeCall(deadcoin.transfer, (bob.addr, amount))});

        uint256 deadline = block.timestamp + 1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(call, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(charlie, digest);

        vm.expectRevert(IAtlas.InvalidSigner.selector);
        vm.prank(charlie.addr);
        IAtlas(alice.addr).executeCall(call, deadline, cnonce, v, r, s);

        // Check balance hasn't changed
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == INITIAL_AMOUNT);
    }

    // Send an invalid signature with our simple call
    function test_simpleCallReplayFail(uint256 amount) public {
        vm.assume(amount <= INITIAL_AMOUNT);

        Atlas.Call memory call =
            IAtlas.Call({to: address(deadcoin), value: 0, data: abi.encodeCall(deadcoin.transfer, (bob.addr, amount))});

        uint256 deadline = block.timestamp + 1;
        uint256 cnonce = vm.randomUint();

        bytes32 digest = getDigest(call, deadline, cnonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, digest);

        vm.prank(bob.addr);
        IAtlas(alice.addr).executeCall(call, deadline, cnonce, v, r, s);

        vm.expectRevert(IAtlas.NonceAlreadyUsed.selector);
        vm.prank(bob.addr);
        IAtlas(alice.addr).executeCall(call, deadline, cnonce, v, r, s);

        // Check balance has only decreased by 10
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == INITIAL_AMOUNT - amount);
    }

    // Alice can call her own EOA code should be sucessful
    function test_executeOwnCall(uint256 amount) public {
        vm.assume(amount <= INITIAL_AMOUNT);

        Atlas.Call memory call =
            IAtlas.Call({to: address(deadcoin), value: 0, data: abi.encodeCall(deadcoin.transfer, (bob.addr, amount))});

        vm.prank(alice.addr);
        IAtlas(alice.addr).executeCall(call);

        // Check balance has only decreased by 10
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == INITIAL_AMOUNT - amount);
    }

    // Alice can call her own EOA code should be sucessful with multiple calls
    function test_executeOwnCallMultipleCalls(uint256 amount) public {
        vm.assume(amount <= INITIAL_AMOUNT / 2);

        Atlas.Call memory call =
            IAtlas.Call({to: address(deadcoin), value: 0, data: abi.encodeCall(deadcoin.transfer, (bob.addr, amount))});
        Atlas.Call[] memory calls = new IAtlas.Call[](2);
        calls[0] = call;
        calls[1] = call;

        vm.prank(alice.addr);
        IAtlas(alice.addr).executeCalls(calls);

        // Check balance has decreased
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == INITIAL_AMOUNT - (2 * amount));
    }

    // Bob should not be able to call Alice's function without her signature
    function test_bobFailCall(uint256 amount) public {
        vm.assume(amount <= INITIAL_AMOUNT);

        Atlas.Call memory call =
            IAtlas.Call({to: address(deadcoin), value: 0, data: abi.encodeCall(deadcoin.transfer, (bob.addr, amount))});
        Atlas.Call[] memory calls = new IAtlas.Call[](2);
        calls[0] = call;
        calls[1] = call;

        vm.expectRevert(IAtlas.Unauthorized.selector);
        vm.prank(bob.addr);
        IAtlas(alice.addr).executeCalls(calls);

        vm.expectRevert(IAtlas.Unauthorized.selector);
        vm.prank(bob.addr);
        IAtlas(alice.addr).executeCall(call);

        // Check balance not have changed
        uint256 balance = deadcoin.balanceOf(alice.addr);
        assert(balance == INITIAL_AMOUNT);
    }

    // Alice can't call an unexisting function
    function test_executeCallReverted() public {
        Atlas.Call memory call =
            IAtlas.Call({to: address(deadcoin), value: 0, data: abi.encodeWithSignature("nonExistentFunction()")});

        vm.expectRevert(IAtlas.CallReverted.selector);
        vm.prank(alice.addr);
        IAtlas(alice.addr).executeCall(call);
    }

    // Test that the isValidSignature function returns the correct selector if hash signed by alice
    function test_isValidSignature(bytes32 hash) public {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes4 result = IAtlas(alice.addr).isValidSignature(hash, signature);
        assert(result == IERC1271.isValidSignature.selector);
    }

    // Test that the isValidSignature function returns 0 if the hash is not signed by alice
    function test_isValidSignature_notVerified(bytes32 hash) public {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bob, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes4 result = IAtlas(alice.addr).isValidSignature(hash, signature);
        assert(result != IERC1271.isValidSignature.selector);
    }

    function test_canReceiveEther(uint256 amount) public {
        EtherSenderContract senderImpl = new EtherSenderContract();
        vm.deal(address(senderImpl), amount);

        uint256 aliceInitialBalance = alice.addr.balance;

        vm.prank(alice.addr);
        senderImpl.sendEther(alice.addr, amount);

        assertEq(alice.addr.balance, aliceInitialBalance + amount, "wrong balance");
    }

    function test_canReceiveERC721(uint256 id) public {
        MockERC721 erc721 = new MockERC721();
        erc721.mint(bob.addr, id);

        assertEq(erc721.ownerOf(id), bob.addr);

        vm.prank(bob.addr);
        erc721.safeTransferFrom(bob.addr, alice.addr, id);

        assertEq(erc721.ownerOf(id), alice.addr, "wrong owner");
    }

    function test_canReceiveERC1155() public {
        uint256 id = 1;
        uint256 amount = 100;
        MockERC1155 erc1155 = new MockERC1155();
        erc1155.mint(bob.addr, id, amount, "");

        assertEq(erc1155.balanceOf(bob.addr, id), amount);

        vm.prank(bob.addr);
        erc1155.safeTransferFrom(bob.addr, alice.addr, id, amount, "");

        assertEq(erc1155.balanceOf(alice.addr, id), amount, "wrong balance");
    }
}
