Obedient Carbon Leopard

high

# ETH TVL can be double erased by `verifyBalanceUpdates`

## Summary
When users request withdrawals from EigenLayer, the withdrawals are bulked. Then, the rebalance is triggered, during which the EigenPod shares are decreased and the queued ETH inside the Rio contracts are increased. The total TVL of ETH balance is calculated as follows: EigenPod shares + depositPool balance + queued balance. However, someone can call the `verifyBalanceUpdates` function to recover the Eigen pod shares before the actual withdrawal from the beacon chain. In this scenario, the Eigen pod shares + queued ETH would be double counted, leading to an incorrect TVL for ETH. Consequently, the deposits/withdrawals going through will not be correct because the price per share will be incorrect.
## Vulnerability Detail
First, let's see how the TVL of ETH is calculated in Rio:
```solidity
function getTotalBalanceForAsset(address asset) public view returns (uint256) {
       .
        address depositPool_ = address(depositPool());
        if (asset == ETH_ADDRESS) {
            return depositPool_.balance + getETHBalanceInEigenLayer();
        }
        .
    }

    /// @notice Returns the ETH balance held in EigenLayer. This includes the ETH held in
    /// unverified validators, EigenPod shares, and ETH that's queued for withdrawal.
    function getETHBalanceInEigenLayer() public view returns (uint256 balance) {
        balance = ethBalanceInUnverifiedValidators;

        IRioLRTOperatorRegistry operatorRegistry_ = operatorRegistry();
        uint8 endAtID = operatorRegistry_.operatorCount() + 1; // Operator IDs start at 1.
        for (uint8 id = 1; id < endAtID; ++id) {
            balance += operatorDelegator(operatorRegistry_, id).getETHUnderManagement();
        }
    }
```

```solidity
function getEigenPodShares() public view returns (int256) {
        return eigenPodManager.podOwnerShares(address(this));
    }

    /// @notice The amount of ETH queued for withdrawal from EigenLayer, in wei.
    function getETHQueuedForWithdrawal() public view returns (uint256) {
        uint256 ethQueuedSlotData;
        assembly {
            ethQueuedSlotData := sload(ethQueuedForUserSettlementGwei.slot)
        }

        uint64 userSettlementGwei = uint64(ethQueuedSlotData);
        uint64 operatorExitAndScrapeGwei = uint64(ethQueuedSlotData >> 64);

        return (userSettlementGwei + operatorExitAndScrapeGwei).toWei();
    }

    /// @notice Returns the total amount of ETH under management by the operator delegator.
    /// @dev This includes EigenPod shares (verified validator balances minus queued withdrawals)
    /// and ETH queued for withdrawal from EigenLayer. Returns `0` if the total is negative.
    function getETHUnderManagement() external view returns (uint256) {
        int256 aum = getEigenPodShares() + int256(getETHQueuedForWithdrawal());
        if (aum < 0) return 0;

        return uint256(aum);
    }
```

So from above snippets we can say that the total balance of ETH in rio is:
**idle ETH in deposit pool + eigen pod shares + queued ETH**

Now, let's go through an example where we can inflate this number, assume the operator has 64 ETH and users asked 32 ether in an epoch and then the `rebalance` is called. Inside the `rebalance` method there is a function called `_processUserWithdrawalsForCurrentEpoch` which calls the internal library function `OperatorOperations.queueWithdrawalFromOperatorsForUserSettlement` which it deallocates from operators and calls the operators delegators `queueWithdrawalForUserSettlement` function to queue a withdrawal. 

   ```solidity
 function queueWithdrawalForUserSettlement(address strategy, uint256 shares) external onlyCoordinator returns (bytes32 root) {
        if (strategy == BEACON_CHAIN_STRATEGY) {
            _increaseETHQueuedForUserSettlement(shares);
        }
        root = _queueWithdrawal(strategy, shares, address(withdrawalQueue()));
    }
```

```solidity
function _queueWithdrawal(address strategy, uint256 shares, address withdrawer) internal returns (bytes32 root) {
        IDelegationManager.QueuedWithdrawalParams[] memory withdrawalParams = new IDelegationManager.QueuedWithdrawalParams[](1);
        withdrawalParams[0] = IDelegationManager.QueuedWithdrawalParams({
            strategies: strategy.toArray(),
            shares: shares.toArray(),
            withdrawer: withdrawer
        });
        root = delegationManager.queueWithdrawals(withdrawalParams)[0];
    }
```

as we can see this function will increase the queued eth, which is 32 ether and then queues a withdrawal in the delegation manager which reduces the Eigen pod shares 32 ether. In result, the queued ether balance increased 32 ether and Eigen pod shares decreased 32 ether so the TVL hasn't changed which is the correct behaviour we expect. 
Now, the ETH TVL in Rio is:
0 -> idle eth in deposit pool
32 ether -> in eigen pod shares
32 ether -> in queued 
in total 64 ether = correct

From there, the correct flow would be that the operator calling this function in the EigenPod to withdraw the beacon chain ether from the pos to EigenPod
https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L232C14-L277
And then the epoch can be settled in the withdrawal queue where the queued eth would be reseted to 0 and 32 ether withdrawn to the withdrawal queue here:
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTWithdrawalQueue.sol#L248-L271

However, a malicious actor can call [verifyBalanceUpdates](https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L185-L221) function in the EigenPod after the validator is exited the beacon chain which means that the validator has "0" ether and its verified, hence, an another 32 eigen pod shares would decreased! 

Now, the ETH TVL in Rio is:
0 -> idle eth in deposit pool
0 ether -> in eigen pod shares
32 ether -> in queued 
which is in total 32 ether! All the deposits and withdrawals that relies on total assets now are manipulated!

Though, when the [verifyAndProcessWithdrawal](https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L232-L239) is called, the 32 eigen pod shares will be re-added to contract and the TVL will be corrected. However, in that time window, the ether that Rio holds will be manipulated. 

**Step by step attack scenario:**
Assume:
2 validators in an operator where both of the validators has 64 ether deposited in beacon chain. 
An user requests 32 ether withdrawal

At this stage:
queued -> 0
eigen pod shares -> 64

1- the withdrawal request increases queued ether balance by 32 and decreases 32 eigen pod shares
At this stage:
queued -> 32
eigen pod shares -> 32

2- Validator exits the beacon chain, now the validator has "0" ether balance in beacon chain

3- Attacker calls `verifyBalanceUpdates` to prove that the validator has "0" ether balance which decreases 32 more eigen pod shares
At this stage:
queued -> 32
eigen pod shares -> 0

Attacker now manipulated the exchange rate because the TVL is misleading now by not accounting 32 ether. 


## Impact
Manipulation of total assets that the Rio holds for a LRT. This could affect all the deposit/withdrawals on each asset that are allowed (cbETH, rETH, etc) hence high.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L89-L114

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L101-L126

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L245-L267

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorOperations.sol#L88C5-L107C6

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L213-L218

https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/core/DelegationManager.sol#L267-L289

https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L232C14-L277
## Tool used

Manual Review

## Recommendation
