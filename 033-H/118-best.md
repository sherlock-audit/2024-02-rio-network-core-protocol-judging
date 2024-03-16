Obedient Carbon Leopard

high

# Partial withdrawals will decrease the LRT exchange rate

## Summary
When the native staking validators are claimed via partial withdrawals from EigenPod the eigen pod shares will decrease whenever someone verifies the beacon chain balance of the validator. The rewards that are previously counted will decrease immediately hence, the exchange rate will change. 
## Vulnerability Detail
Assume that an operators validator has 34 ether in its validator where as 32 ether of it is the deposited part and the 2 ether is the reward. Also, the EigenPods balance is verified via [verifyBalanceUpdates](https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L185-L191) hence, the eigen pod shares that the operator has is 34 and its confirmed. 

Assume the validator decides to a partial withdrawal and claims the 2 ether from its beacon chain validator balance via [verifyAndProcessWithdrawals](https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L232-L239)

as we can see in the below snippet of **partial withdrawal**, there will be no shares difference which the EigenPod shares will not be updated after the `verifyAndProcessWithdrawals` call, however, the amount (2 ether in our case) will be sent to delayed router and can be claimed after the delay passes.
```solidity
function _processPartialWithdrawal(
        uint40 validatorIndex,
        uint64 withdrawalTimestamp,
        address recipient,
        uint64 partialWithdrawalAmountGwei
    ) internal returns (VerifiedWithdrawal memory) {
        emit PartialWithdrawalRedeemed(
            validatorIndex,
            withdrawalTimestamp,
            recipient,
            partialWithdrawalAmountGwei
        );

        sumOfPartialWithdrawalsClaimedGwei += partialWithdrawalAmountGwei;

        // For partial withdrawals, the withdrawal amount is immediately sent to the pod owner
        return
            VerifiedWithdrawal({
                amountToSendGwei: uint256(partialWithdrawalAmountGwei),
                sharesDeltaGwei: 0
            });
    }
```

```solidity
if (withdrawalSummary.amountToSendGwei != 0) {
            _sendETH_AsDelayedWithdrawal(podOwner, withdrawalSummary.amountToSendGwei * GWEI_TO_WEI);
        }
```

At this point, if someone calls `verifyBalanceUpdates` since the beacon chain of the validator has 32 ether now and previously it had 34 ether, the 2 ether excess will be decreased. Hence, the pod will have now 32 eigen pod shares. 

That means now the TVL has decreased by 2 ether until the delayed router claims and sends the ether back to the reward distributor contract. Also, note that the reward distributor contract not distributes the entire 2 ether to the deposit pool but some portion, so the recovered TVL will be lesser than 34 ether anyways. 

Conclusively, the ether balance will decrease 2 ether immediately and the exchange rate will be manipulated in this time window. All the functions such as deposit/withdrawals will be accounted mistakenly. 

**`Flow of the above scenario:`**
1- Operators validator receives 32 ether, and gets confirmed by the `verifyBalanceUpdates`, which EigenPodManager credits 32 shares.
2- After sometime, someone again calls `verifyBalanceUpdates` this time there are 34 ether due to rewards accrued from pos staking hence, an another 2 eigen pod shares credited, in total there are 34 eigen pod shares.
3- Validator does a partial withdrawal
4- Validator claims the 2 ether by partial withdrawal via `verifyAndProcessWithdrawals` this function sends the 2 ether to delayed router which can be claimed by operator delegator contract once the delay has passed. However, this function does not updates the eigen pod shares, which means the TVL is still 34 eigen pod shares
5- Someone proves the balance via `verifyBalanceUpdates` again and now since the validator has 32 ether, the excess 2 pod shares will be decreased and the TVL is now 32 eigen pod shares! 
6- The TVL decreased by 2 shares but in reality those 2 shares are the result of 2 ether claimed from rewards and they will be re-added to the contract balance after a delay. Decreasing the TVL here will manipulate the LRT exchange rate mistakenly since the 2 ether is not lost, they are just claimed and will be re-accounted soon.

## Impact
High, since the rewards will be claimed frequently and every time rewards are claimed the TVL will drop hence the exchange rate will be manipulated mistakenly. 
## Code Snippet
https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L185-L277
## Tool used

Manual Review

## Recommendation
