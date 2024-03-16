Massive Syrup Sheep

medium

# Validator balances less than 32 ETH is not considered when withdrawing for user settlement

## Summary
Validator balances less than 32 ETH is not considered when withdrawing for user settlement

## Vulnerability Detail
Validators can have less than 32 ETH as their balance in the beacon chain due to penalties and slashing. The balance in EigenLayer matches this amount when the balance updates are pushed. But this is not considered when processing user withdrawals

```solidity
    function queueETHWithdrawalFromOperatorsForUserSettlement(IRioLRTOperatorRegistry operatorRegistry, uint256 amount) internal returns (bytes32 aggregateRoot) {
        uint256 depositCount = amount.divUp(ETH_DEPOSIT_SIZE);
        (, IRioLRTOperatorRegistry.OperatorETHDeallocation[] memory operatorDepositDeallocations) = operatorRegistry.deallocateETHDeposits(
            depositCount
        );
        
        .....

        for (uint256 i = 0; i < length; ++i) {
            address delegator = operatorDepositDeallocations[i].delegator;

            // @audit assumes that each validator has ETH_DEPOSIT_SIZE (ie.32 eth) as their balance

=>          uint256 amountToWithdraw = (i == length - 1) ? remainingAmount : operatorDepositDeallocations[i].deposits * ETH_DEPOSIT_SIZE;

            ....
        }
```

In case a validator's balance is less than 32 eth, it will revert since it is attempted to remove more shares than the operator's balance

## Impact
Withdrawals will revert in case the validator's balance drop below 32 eth 

## Code Snippet
attempts to withdraw ETH_DEPOSIT_SIZE from each validator 
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorOperations.sol#L103-L104

## Tool used

Manual Review

## Recommendation
Check for delegator share balance when deallocating shares  