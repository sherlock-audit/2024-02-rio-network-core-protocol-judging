Harsh Fiery Halibut

medium

# Withdrawals Will Get Stuck Even Though They Can Be Handled , Due To An Edge Case

## Summary

The rebalance function would not work properly due to an edge case , due to this the processing of the withdrawals happening at
  [L128 in ](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L128) would keep reverting even if the withdrawal queue has enough funds to settle the withdrawals , therefore RIO users would not be able to claim their withdrawals even when funds are present.

## Vulnerability Detail

1.) The rebalance function in the RioLRTCoordinator.sol contract does two things , it settles the withdrawals (when there are enough
  funds sent from the deposit pool) and then sends the remaining excess funds from the deposit pool into Eigen layer.
  
  2.) When depositBalanceIntoEigenLayer() is invoked in rebalalnce , it invokes depositETHToOperators() which invokes invokes stakeETH()
  which invokes stake() function in the EigenPodManager contract in Eigen Layer.
  
  3.) In an emergency situation the EigenPodManager might be paused , and if paused the call to stake() function here https://github.com/Layr-Labs/eigenlayer-contracts/blob/dev/src/contracts/pods/EigenPodManager.sol#L94
  would revert.
  
  4.) Therefore , it is possible that when calling rebalance , the call to `_processUserWithdrawalsForCurrentEpoch` was successfull , 
  i.e. deposit pool sent enough funds to cover the owed shares and then users can claim their withdrawals , but since EigenPodManager
  is paused , the call to `depositBalanceIntoEigenLayer` would revert and the whole rebalance function reverts.
  
  5.) Therefore , in this situation the withdrawals would never be processed even though the deposit pool had enough funds to cover
  pending withdrawals , RIO would be in an unexpected state.

## Impact

 The withdrawals won't be processed even though RIO can handle the withdrawals and the users would never get their justified withdrawals , in short , withdrawals would be stuck in the deposit pool / withdrawal queue.

## Code Snippet

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L132
https://github.com/Layr-Labs/eigenlayer-contracts/blob/dev/src/contracts/pods/EigenPodManager.sol#L94

## Tool used

Manual Analysis

## Recommendation

  When calling depositBalanceIntoEigenLayer , it should be wrapped in a if block which only calls depositBalanceIntoEigenLayer when
  the Eigen Pod is not paused , if it is paused then go through with the processing of the withdrawals.