Obedient Carbon Leopard

high

# Big withdrawals can make some ether requested stuck in the delayed router of EigenLayer

## Summary
When a user requests a large withdrawal from a LRT in the form of ETH, the beacon chain strategy (EigenPod) will attempt to withdraw a significant amount. The EigenPod contract includes a variable that, if the withdrawal request exceeds a certain threshold, will send the excess amount to something called a **delayed router, which requires a separate claim**. However, the current scope of Rio contracts does not account for this edge case.
## Vulnerability Detail
Let's assume there is one operator with one strategy, which is a Beacon chain strategy utilizing EigenPod for simplicity. Also, let's assume that the operator's EigenPod has 100 validators, each staked with 32 ether, totaling 3200 ether staked in the beacon chain via EigenPod.

When users request a withdrawal, there is no restriction on the size of the withdrawal they can request, as seen here:
```solidity
function requestWithdrawal(address asset, uint256 amountIn) external checkWithdrawal(asset, amountIn) returns (uint256 sharesOwed) {
        // Determine the amount of shares owed to the withdrawer using the current exchange rate.
        sharesOwed = convertToSharesFromRestakingTokens(asset, amountIn);

        // If requesting ETH, reduce the precision of the shares owed to the nearest Gwei,
        // which is the smallest unit of account supported by EigenLayer.
        if (asset == ETH_ADDRESS) sharesOwed = sharesOwed.reducePrecisionToGwei();

        // Pull restaking tokens from the sender to the withdrawal queue.
        token.safeTransferFrom(msg.sender, address(withdrawalQueue()), amountIn);

        // Ensure there are enough shares to cover the withdrawal request, and queue the withdrawal.
        uint256 availableShares = assetRegistry().convertToSharesFromAsset(asset, assetRegistry().getTotalBalanceForAsset(asset));
        if (sharesOwed > availableShares - withdrawalQueue().getSharesOwedInCurrentEpoch(asset)) {
            revert INSUFFICIENT_SHARES_FOR_WITHDRAWAL();
        }
        withdrawalQueue().queueWithdrawal(msg.sender, asset, sharesOwed, amountIn);
    }
```

Assume that all the ether has requested for withdrawal which is 3200 ether. That means the operators EigenPod needs to a full withdrawal with all of its 100 validators. When `rebalance` called after 3200 ether requested the `rebalance` function will call the internal `_processUserWithdrawalsForCurrentEpoch` function and then it will call the library internal function which has the following implementation:
```solidity
function queueETHWithdrawalFromOperatorsForUserSettlement(IRioLRTOperatorRegistry operatorRegistry, uint256 amount) internal returns (bytes32 aggregateRoot) {
        uint256 depositCount = amount.divUp(ETH_DEPOSIT_SIZE);
        (, IRioLRTOperatorRegistry.OperatorETHDeallocation[] memory operatorDepositDeallocations) = operatorRegistry.deallocateETHDeposits(
            depositCount
        );
        uint256 length = operatorDepositDeallocations.length;
        bytes32[] memory roots = new bytes32[](length);

        uint256 remainingAmount = amount;
        for (uint256 i = 0; i < length; ++i) {
            address delegator = operatorDepositDeallocations[i].delegator;

            // Ensure we do not send more than needed to the withdrawal queue. The remaining will stay in the Eigen Pod.
            uint256 amountToWithdraw = (i == length - 1) ? remainingAmount : operatorDepositDeallocations[i].deposits * ETH_DEPOSIT_SIZE;

            remainingAmount -= amountToWithdraw;
            -> roots[i] = IRioLRTOperatorDelegator(delegator).queueWithdrawalForUserSettlement(BEACON_CHAIN_STRATEGY, amountToWithdraw);
        }
        aggregateRoot = keccak256(abi.encode(roots));
    }
```

as we can see above the entire 3200 ether is requested from operator delegator by calling the `queueWithdrawalForUserSettlement` function in the operator delegator. Now, let's see the implementation of that:
 
```solidity
function queueWithdrawalForUserSettlement(address strategy, uint256 shares) external onlyCoordinator returns (bytes32 root) {
        if (strategy == BEACON_CHAIN_STRATEGY) {
            _increaseETHQueuedForUserSettlement(shares);
        }
        root = _queueWithdrawal(strategy, shares, address(withdrawalQueue()));
    }
```

as we can see above, it first increases the queued eth balance as 3200 ether. 
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

then, as we can see above again, it calls delegation manager to queue the withdrawal which this is the part where the 3200 ether worth Eigen pod shares will be decreased from the balance sheet of the EigenPod of operator. 

Now, the operator should exit with all 100 validators from the beacon chain and needs to call this function in its EigenPod:
https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L232-L277

As we can see in the above code link, there is an internal function called `_verifyAndProcessWithdrawal` which is responsible for verifying the withdrawal request and determining the withdrawal type (partial or full)
https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L566-L649

Since we made a full withdrawal we will execute the full withdrawal part of the [code](https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L651-L708)

As we can see if the amount to withdraw is bigger than `MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR` then the excess amount is immediately withdrawn and the difference is queued:
```solidity
function _processFullWithdrawal(
        uint40 validatorIndex,
        bytes32 validatorPubkeyHash,
        uint64 withdrawalTimestamp,
        address recipient,
        uint64 withdrawalAmountGwei,
        ValidatorInfo memory validatorInfo
    ) internal returns (VerifiedWithdrawal memory) {
        uint64 amountToQueueGwei;
        if (withdrawalAmountGwei > MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR) {
            amountToQueueGwei = MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR;
        } else {
            amountToQueueGwei = withdrawalAmountGwei;
        }
        VerifiedWithdrawal memory verifiedWithdrawal;
        verifiedWithdrawal.amountToSendGwei = uint256(withdrawalAmountGwei - amountToQueueGwei);
        withdrawableRestakedExecutionLayerGwei += amountToQueueGwei;
}
```

then, as final step of `verifyAndProcessWithdrawal` the excess amount is sent directly to the delayed router which can be claimed after a delay and the rest is accounted in `withdrawableRestakedExecutionLayerGwei` variable which can be claimed via completing the withdrawal request in delegation manager.

```solidity
// If any withdrawals are eligible for immediate redemption, send to the pod owner via
        // DelayedWithdrawalRouter
        if (withdrawalSummary.amountToSendGwei != 0) {
            _sendETH_AsDelayedWithdrawal(podOwner, withdrawalSummary.amountToSendGwei * GWEI_TO_WEI);
        }
        // If any withdrawals resulted in a change in the pod's shares, update the EigenPodManager
        if (withdrawalSummary.sharesDeltaGwei != 0) {
            eigenPodManager.recordBeaconChainETHBalanceUpdate(podOwner, withdrawalSummary.sharesDeltaGwei * int256(GWEI_TO_WEI));
        }
```

Finally, the Rio contract expects the full withdrawal amount, but some amount remains in the delayed router. Since the withdrawn Ether will be less than 3200 ether, the withdrawers in the queue will receive less ETH because the withdrawal queue didn't receive the excess ether, which is stuck in the delayed router.





**Another issue from same root cause**
When the operators pod receives more ether than `MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR` value set in EigenPod contract, the excess amount will not be accounted and the eigen pod shares will be capped to that number.

If the `MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR` 200 ether, and the LRT has 300 ether in deposit pool:
TVL is 300 ether in beginning. 
300 ether will be deposited to operator delegators eigen pod, only the 200 ether will be verified hence, the TVL will drop to 200 ether worth of eigen pod shares.
## Impact
Ether sent to delayed router will be stuck, the tvl will be accounted mistakenly hence the deposit/withdrawals when the ether was stuck will be not correct. 
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L99-L116

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L121-L151

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L245-L267

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorOperations.sol#L88C5-L107C6

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L213-L218

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L265-L273

https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/core/DelegationManager.sol#L267-L289

https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/core/DelegationManager.sol#L670-L735

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTWithdrawalQueue.sol#L216-L271
## Tool used

Manual Review

## Recommendation
Introduce a withdrawal cap when removing from the Beacon chain strategy just like in the deposit flow here:
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTDepositPool.sol#L52-L63