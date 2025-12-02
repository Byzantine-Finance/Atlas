// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import {Atlas} from "../src/Atlas.sol";
import {Deadcoin} from "./Deadcoin.sol";

contract AtlasTest is Test {
    Atlas public atlas;

    // Alice's address and private key (EOA with no initial contract code).
    address payable ALICE_ADDRESS = payable(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
    uint256 constant ALICE_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    // Bob's address and private key (Bob will execute transactions on Alice's behalf).
    address constant BOB_ADDRESS = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    uint256 constant BOB_PK = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    function setUp() public {
        atlas = new Atlas();

        deployCodeTo("Deadcoin.sol", 0x8464135c8F25Da09e49BC8782676a84730C318bC);

        // Alice signs an authorization
        Vm.SignedDelegation memory signedDelegation = vm.signDelegation(address(atlas), ALICE_PK);
        // Bob send the authorization signed by Alice
        vm.broadcast(BOB_PK);
        vm.attachDelegation(signedDelegation);

        Deadcoin(0x8464135c8F25Da09e49BC8782676a84730C318bC).transfer(ALICE_ADDRESS, 100);
    }

    function test_executeSuccesfull() public {
        uint8 v = 27;
        bytes32 r = 0x1abc8e5eeaf76de3fb25e59d3bd3f7df1f5ec15ac4fc1e4eae79fae4c0d322ab;
        bytes32 s = 0x14166b66a522d2867d4305596833df6737d01ebd8ac10babcf34011a24a87187;

        Atlas.Call memory call = Atlas.Call(
            0x8464135c8F25Da09e49BC8782676a84730C318bC,
            0,
            hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        );
        Atlas.Call[] memory calls = new Atlas.Call[](1);
        calls[0] = call;

        Atlas(ALICE_ADDRESS).execute(calls, v, r, s);
    }

    function test_executeFail() public {
        uint8 v = 27;
        bytes32 r = 0x1abc8e5eeaf76de3fb25e59d3bd3f7df1f5ec15ac4fc1e4eae79fae4c0d322ab;
        bytes32 s = 0x14166b66a522d2867d4305596833df6737d01ebd8ac10babcf34011a24a87187;

        Atlas.Call memory call = Atlas.Call(
            0x8464135c8F25Da09e49BC8782676a84730C318bC,
            10,
            hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        );
        Atlas.Call[] memory calls = new Atlas.Call[](1);
        calls[0] = call;

        vm.expectRevert(); // Expect to revert because of the wrong value in the call (invalid signature)
        Atlas(ALICE_ADDRESS).execute(calls, v, r, s);
    }

    function test_replayFail() public {
        uint8 v = 27;
        bytes32 r = 0x1abc8e5eeaf76de3fb25e59d3bd3f7df1f5ec15ac4fc1e4eae79fae4c0d322ab;
        bytes32 s = 0x14166b66a522d2867d4305596833df6737d01ebd8ac10babcf34011a24a87187;

        Atlas.Call memory call = Atlas.Call(
            0x8464135c8F25Da09e49BC8782676a84730C318bC,
            0,
            hex"a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000a"
        );
        Atlas.Call[] memory calls = new Atlas.Call[](1);
        calls[0] = call;

        Atlas(ALICE_ADDRESS).execute(calls, v, r, s);

        vm.expectRevert(); // we should not be able to resend the same call signed
        Atlas(ALICE_ADDRESS).execute(calls, v, r, s);
    }
}
