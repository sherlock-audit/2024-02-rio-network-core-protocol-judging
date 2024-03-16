Obedient Carbon Leopard

medium

# EigenLayer's StrategyManager `thirdPartyTransfersForbidden` setting can block the withdrawals

## Summary
EigenLayer strategy manager has a setting `thirdPartyTransfersForbidden` which is used to not accept withdrawals to an address that is different than the initiator. In such cases if that's set to true by EigenLayer, the Rio's contracts will fail to deliver all types of withdrawals, operator exit and user exit. 
## Vulnerability Detail
When users exit:
OperatorDelegator contract initiates withdrawal in EigenLayer DelegationManager contract to **withdrawal queue contract**

When operator exit by admin:
OperatorDelegator contract initiates withdrawal in EigenLayer DelegationManager contract to **deposit pool contract** 

So, in both withdrawal types the withdrawer (OperatorDelegator) is not the receiver (deposit pool / withdrawal queue). 

In the StrategyManager contract of EigenLayer, we can see the usage of `thirdPartyTransfersForbidden` setting:
```solidity
/**
     * If true for a strategy, a user cannot depositIntoStrategyWithSignature into that strategy for another staker
     * and also when performing DelegationManager.queueWithdrawals, a staker can only withdraw to themselves.
     * Defaulted to false for all existing strategies.
     * @param strategy The strategy to set `thirdPartyTransfersForbidden` value to
     * @param value bool value to set `thirdPartyTransfersForbidden` to
     */
    function setThirdPartyTransfersForbidden(
        IStrategy strategy,
        bool value
    ) external onlyStrategyWhitelister {
        _setThirdPartyTransfersForbidden(strategy, value);
    }
```
```solidity
 function _removeSharesAndQueueWithdrawal(
        address staker, 
        address operator,
        address withdrawer,
        IStrategy[] memory strategies, 
        uint256[] memory shares
    ) internal returns (bytes32) {
        .

            // Remove active shares from EigenPodManager/StrategyManager
            if (strategies[i] == beaconChainETHStrategy) {
                .
            } else {
                -> require(
                   -> staker == withdrawer || !strategyManager.thirdPartyTransfersForbidden(strategies[i]),
                    "DelegationManager._removeSharesAndQueueWithdrawal: withdrawer must be same address as staker if thirdPartyTransfersForbidden are set"
                );
                // this call will revert if `shares[i]` exceeds the Staker's current shares in `strategies[i]`
                strategyManager.removeShares(staker, strategies[i], shares[i]);
            }
```

As seen above, if the EigenLayer governance decides to add a strategy to `thirdPartyTransfersForbidden = true` then all type of withdrawals will be impossible for Rio because of this check:
```solidity
staker == withdrawer || !strategyManager.thirdPartyTransfersForbidden(strategies[i]),
                    "DelegationManager._removeSharesAndQueueWithdrawal: withdrawer must be same address as staker if thirdPartyTransfersForbidden are set"
```

**Coded PoC:**
```solidity
// forge test --match-contract RioLRTWithdrawalQueueTest --match-test test_settingThirdPartyTransferForbidFailsWithdrawals -vv
    function test_settingThirdPartyTransferForbidFailsWithdrawals() public {
        uint256 initialTotalSupply = reLST.token.totalSupply();

        uint8 operatorId = addOperatorDelegator(reLST.operatorRegistry, address(reLST.rewardDistributor));
        address operatorDelegator = reLST.operatorRegistry.getOperatorDetails(operatorId).delegator;

        uint256 amount = 100 * 1e18;
        
        cbETH.approve(address(reLST.coordinator), type(uint256).max);
        uint256 restakingTokensInEL = reLST.coordinator.deposit(CBETH_ADDRESS, amount);

        vm.prank(EOA, EOA);
        reLST.coordinator.rebalance(CBETH_ADDRESS);

        reLST.coordinator.requestWithdrawal(CBETH_ADDRESS, restakingTokensInEL);

        strategyManager.setThirdPartyTransfersForbidden(cbETHStrategy, true);
        skip(reLST.coordinator.rebalanceDelay());
        vm.startPrank(EOA, EOA);
        vm.expectRevert("DelegationManager._removeSharesAndQueueWithdrawal: withdrawer must be same address as staker if thirdPartyTransfersForbidden are set");
        reLST.coordinator.rebalance(CBETH_ADDRESS);
        vm.stopPrank();
    }
```
## Impact
Withdrawals are completely broken.
## Code Snippet
https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/core/StrategyManager.sol#L211-L223
https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/core/DelegationManager.sol#L267-L289
https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/core/DelegationManager.sol#L704-L709

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L213-L218

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L253-L258
## Tool used

Manual Review

## Recommendation
