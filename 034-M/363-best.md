Fast Turquoise Mantis

high

# Slashing penalty is unfairly paid by a subset of users if a deficit is accumulated.

## Summary

If a deficit is accumulated in the EigenPodManager due to slashing when ETH is being withdrawn the slashing payment will be taken from the first cohort to complete a withdrawal.

## Vulnerability Detail

A deficit can happen in `podOwnerShares[podOwner]` in the EigenPodManager in the EigenLayer protocol. This can happen if validators are slashed when ETH is queued for withdrawal.

The issue is that this deficit will be paid for by the next cohort to complete a withdrawal by calling `settleEpochFromEigenLayer()`.

In the following code we can see how `epochWithdrawals.assetsReceived` is calculated based on the amount received from the `delegationManager.completeQueuedWithdrawal` call

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTWithdrawalQueue.sol#L242-L268

```solidity
        uint256 balanceBefore = asset.getSelfBalance();

        address[] memory assets = asset.toArray();
        bytes32[] memory roots = new bytes32[](queuedWithdrawalCount);

        IDelegationManager.Withdrawal memory queuedWithdrawal;
        for (uint256 i; i < queuedWithdrawalCount; ++i) {
            queuedWithdrawal = queuedWithdrawals[i];

            roots[i] = _computeWithdrawalRoot(queuedWithdrawal);
            delegationManager.completeQueuedWithdrawal(queuedWithdrawal, assets, middlewareTimesIndexes[i], true);

            // Decrease the amount of ETH queued for withdrawal. We do not need to validate the staker as
            // the aggregate root will be validated below.
            if (asset == ETH_ADDRESS) {
                IRioLRTOperatorDelegator(queuedWithdrawal.staker).decreaseETHQueuedForUserSettlement(
                    queuedWithdrawal.shares[0]
                );
            }
        }
        if (epochWithdrawals.aggregateRoot != keccak256(abi.encode(roots))) {
            revert INVALID_AGGREGATE_WITHDRAWAL_ROOT();
        }
        epochWithdrawals.shareValueOfAssetsReceived = SafeCast.toUint120(epochWithdrawals.sharesOwed);

        uint256 assetsReceived = asset.getSelfBalance() - balanceBefore;
        epochWithdrawals.assetsReceived += SafeCast.toUint120(assetsReceived);
```

the amount received could be 0 if the deficit is larger than the amount queued for this cohort. See following code in `withdrawSharesAsTokens()` EigenPodManager

https://github.com/Layr-Labs/eigenlayer-contracts/blob/e12b03f20f7dceded8de9c6901ab05cfe61a2113/src/contracts/pods/EigenPodManager.sol#L216C1-L220C14

```solidity
            } else {
                podOwnerShares[podOwner] += int256(shares);
                emit PodSharesUpdated(podOwner, int256(shares));
                return;
            }
```

These users will pay for all slashing penalties instead of it being spread out among all LRT holders.

## Impact

If a deficit is accumulated the first cohort to settle will pay for the entire amount. If they can not cover it fully, they will receive 0 and the following cohort will pay for the rest.

## Code Snippet

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTWithdrawalQueue.sol#L242-L268

## Tool used

Manual Review
## Recommendation

A potential solution to deal with this is to check if a deficit exists in `settleEpochFromEigenLayer()`. If it exists functionality has to be added that spreads the cost of the penalty fairly among all LRT holders.
