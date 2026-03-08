# Confirmed Valid Issues

This document summarizes the issues that were classified as `LIKELY VALID`, including a brief description, impact, attack path, mitigation, and the corresponding PoC path.

## 1. AtomWallet validity metadata tampering

- Target file: `src/protocol/wallet/AtomWallet.sol`
- Description:
  `AtomWallet._validateSignature()` parses `validUntil` and `validAfter` from the last 12 bytes of `userOp.signature`, but the digest used for signature recovery is derived only from `userOpHash`. Because `userOpHash` does not bind that trailing metadata, a relayer or bundler can modify the execution window without breaking signature validation.
- Impact:
  A malicious bundler/relayer, or anyone who obtains the signed UserOperation off-chain, can extend, remove, or alter the validity window of an already signed action. As a result, transfers, approvals, or arbitrary calls signed by the owner may execute outside the owner’s intended time bounds.
- Attack path:
  1. The owner signs a UserOperation using the format that appends `validUntil || validAfter`.
  2. The attacker or relayer obtains the signed UserOperation off-chain.
  3. The attacker modifies the trailing 12-byte validity metadata while keeping the ECDSA signature bytes unchanged.
  4. `AtomWallet` still recovers the signer successfully because the digest does not include the modified metadata.
  5. `EntryPoint` enforces the attacker-chosen validity window.
- Mitigation:
  1. Include `validUntil` and `validAfter` in the signed payload.
  2. Reject signature formats that contain mutable trailing metadata not covered by the signed digest.
  3. If validity windows are needed, derive `validationData` only from owner-signed data rather than from mutable appended bytes.
- PoC path:
  - Source: `test/AtomWalletValidityMetadataTampering_SingleFilePOC.t.sol`
  - Foundry path: `tests/AtomWalletValidityMetadataTampering_SingleFilePOC.t.sol`

## 2. Epoch-boundary utilization manipulation in TrustBonding

- Target file: `src/protocol/emissions/TrustBonding.sol`
- Description:
  `TrustBonding` scales emissions using the utilization delta between epochs, while `MultiVault` records utilization as net amount per epoch and rolls it forward lazily. Because this metric is not time-weighted, an attacker can deposit a large amount near the end of an epoch, hold the position across the boundary, and redeem shortly after the next epoch starts to inflate utilization for the target epoch.
- Impact:
  An attacker can artificially increase both the system utilization ratio and their personal utilization ratio for the target epoch, allowing them to receive significantly more emissions and dilute honest participants.
- Attack path:
  1. The attacker holds veTRUST so they are eligible to claim rewards.
  2. Near the end of epoch `n`, the attacker deposits a large amount of TRUST into `MultiVault`.
  3. The position is held across the boundary into epoch `n + 1`, causing epoch `n` utilization to appear much higher.
  4. At the start of epoch `n + 1`, the attacker redeems most of the position and recovers the capital.
  5. When claiming rewards for epoch `n`, the attacker benefits from the inflated utilization delta.
- Mitigation:
  1. Replace epoch-end net delta logic with time-weighted utilization.
  2. Snapshot utilization using a mechanism that cannot be manipulated through short-lived boundary parking.
  3. Introduce a cooldown or minimum holding period before capital contributes to reward-relevant utilization.
  4. Exclude or discount positions that are unwound immediately after the epoch boundary.
- PoC path:
  - Source: `test/EpochBoundaryUtilizationManipulation_SingleFilePOC.t.sol`
  - Foundry path: `tests/EpochBoundaryUtilizationManipulation_SingleFilePOC.t.sol`

## 3. Alternating grace-claimant bypass in TrustBonding

- Target file: `src/protocol/emissions/TrustBonding.sol`
- Description:
  `TrustBonding` grants a 100% personal utilization ratio when an account has no claimed rewards in the previous epoch and also had no eligibility in the previous epoch. The implementation comment describes this like a "first ever claim" grace period, but in reality it only checks the immediately preceding epoch and does not track long-term claim history. This allows one actor to rotate across multiple accounts so that each active account appears to be a new claimant.
- Impact:
  The personal utilization gate can be bypassed repeatedly, allowing rotating claimants to receive near-full or full rewards instead of being reduced to the floor or a partial ratio. This misallocates emissions and dilutes users who claim consistently from a single account.
- Attack path:
  1. The attacker controls at least two accounts and can stagger veTRUST locks across epochs.
  2. Account A is active in one epoch and claims rewards.
  3. In the following epoch, Account A remains inactive so it has no previous-epoch eligibility, while Account B becomes the active account.
  4. When Account B claims, it enters the grace branch and receives a 100% personal utilization ratio.
  5. The attacker repeats the process with alternating accounts to keep bypassing the intended personal utilization requirement.
- Mitigation:
  1. Track true first-claim state in persistent storage rather than inferring it from previous-epoch eligibility.
  2. Allow the grace path only once per account.
  3. If stronger anti-sybil protection is needed, tie the grace logic to persistent participation history instead of only the immediately previous epoch.
  4. Consider disabling the grace path once an account has previously locked, claimed, or otherwise participated historically.
- PoC path:
  - Source: `test/AlternatingGraceClaimantBypass_SingleFilePOC.t.sol`
  - Foundry path: `tests/AlternatingGraceClaimantBypass_SingleFilePOC.t.sol`
