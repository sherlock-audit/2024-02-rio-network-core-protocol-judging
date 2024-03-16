Plain Vinyl Cobra

medium

# The number of eigenlayer shares held for an asset is updated wrongly in an edge case scenario.

## Summary
The number of eigenlayer shares held for an asset is updated wrongly in an edge case scenario.

## Vulnerability Detail
1. Let assume , for an asset, depositcap = 200k. The asset has a strategy.
2. The strategy has currently only one operatorid.
3. The operatorid’s cap = 100k.
4. After some time the operatorid’s allocation becomes 95k.
5.  Now the deposit function is called with 10k amount(with this asset) and lets assume, there is 1k withdrawal shareowed for the asset and 0 asset’s balance in the address pool.after depositing this address pool asset’s balance = 10k.
6. Rebalance function is called, so shareowed 1k goes to withdrawalQueue and other 9k will be deposited to eigenlayer. The assetRegistry contract’s increaseSharesHeldForAsset function is called which increases the shares of 9k asset’s amount for the asset.
7. RioLRTDepositPool’s  depositBalanceIntoEigenLayer function is called in rebalance function which calls the OperatorOperations’s  depositTokenToOperators function which calls the operatorRegistry’s allocateStrategyShares function 
8. See allocateStrategyShares function, as the strategy has only one operatorid and the operatorid’s cap = 100k, current allocation = 95k. So only the shares of  5k asset’s amount is allocated to the operatorid.
9. but remaining 4k is not deposited to eigenlayer but The number of eigenlayer shares held for an asset is increased to 9k asset’s amount  in the rebalance function which is wrong, it should increase only 5k asset’s amount shares.

## Impact

If a new operator is added to the strategy , this operator can be allocated less shares which is unfair.

## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L369
## Tool used

Manual Review

## Recommendation
update the allocated  shares in  function allocateStrategyShares