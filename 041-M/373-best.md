Fast Turquoise Mantis

high

# LRT holders share of rewards are not counted in TVL

## Summary

Rewards from validator staking are collected through the DelayedWithdrawalRouter in the EigenLayer protocol where they are queued before being distributed.

These rewards are then sent to the RioLRTRewardDistributed where they are distributed to 3 different parties - treasure, operators and the deposit pool.

A portion of the rewards therefore belonging to the LRT holders (90%, based on initial parameters) . This is not accounted for in the TVL calculations. Depositing users will therefore receive more LRT than they should since rewards belonging to the pool is not accounted for.
## Vulnerability Detail

Rewards from staking on the beacon chain are withdrawn through partial withdrawals in `verifyAndProcessWithdrawals()` in the EigenPod. This will send  ETH to DelayedWithdrawalRouter and queue a withdrawal.

https://github.com/Layr-Labs/eigenlayer-contracts/blob/e12b03f20f7dceded8de9c6901ab05cfe61a2113/src/contracts/pods/EigenPod.sol#L271

```solidity
_sendETH_AsDelayedWithdrawal(podOwner, withdrawalSummary.amountToSendGwei * GWEI_TO_WEI);
```

When `sharesOwed` is calculated based on current TVL this is not accounted for

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L101

```solidity
sharesOwed = convertToSharesFromRestakingTokens(asset, amountIn);
```

## Impact

Since the deposit pool owns a large part of the rewards (90% based on initial parameters) it should be accounted for in the TVL. Otherwise depositing users will receive more LRT than they should since the TVL below the actual amount.

Withdrawing users will also receive less than they should when TVL is not accurate.
## Code Snippet

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L101

## Tool used

Manual Review
## Recommendation

Functionality to incorporate queued rewards belonging to LRT holders need to be implemented. Based on initial parameters 90% belongs to LRT users, this should be accounted for when TVL is calculated.



