Obedient Carbon Leopard

medium

# Withdrawals will fail if the EigenLayer strategy is removed

## Summary
EigenLayer strategy manager can remove any strategy any time by its governance. In such case, the withdrawals can still go through but the further deposits are not allowed. However, in Rio, as long as there are idle tokens in deposit pool that are not requested as withdrawal the excess will be deposited to EigenLayer, if the strategy is removed by EigenLayer then all the withdrawals will fail in Rio. 
## Vulnerability Detail
First, let's see how StrategyManager decides the deposits of the underlying strategies:
 ```solidity
function _depositIntoStrategy(
        address staker,
        IStrategy strategy,
        IERC20 token,
        uint256 amount
    ) internal -> onlyStrategiesWhitelistedForDeposit(strategy) returns (uint256 shares) {
        // transfer tokens from the sender to the strategy
        token.safeTransferFrom(msg.sender, address(strategy), amount);

        // deposit the assets into the specified strategy and get the equivalent amount of shares in that strategy
        shares = strategy.deposit(token, amount);

        // add the returned shares to the staker's existing shares for this strategy
        _addShares(staker, token, strategy, shares);

        // Increase shares delegated to operator, if needed
        delegation.increaseDelegatedShares(staker, strategy, shares);

        return shares;
    }
```
```solidity
modifier onlyStrategiesWhitelistedForDeposit(IStrategy strategy) {
        require(
            strategyIsWhitelistedForDeposit[strategy],
            "StrategyManager.onlyStrategiesWhitelistedForDeposit: strategy not whitelisted"
        );
        _;
    }
```

As we can see in above code snippets, if the strategy is temporarily or permanently removed from the whitelist, no further deposits are allowed in EigenLayer level. 

Assume that the Rio LRT has 100 EigenLayer-cbETH shares and 0 cbETH in the deposit pool. cbETH strategy deprecates in the EigenLayer, removed from the whitelist, further deposits are not allowed. In such case, users of Rio and EigenLayer should start withdrawing their EigenLayer-cbETH strategy tokens. 
Assume that in an epoch 90 of EigenLayer-cbETH is requested and the epoch is settled. Now, there are only 10 EigenLayer-cbETH left for an user, say Alice. 

Someone can airdrop 10.00001 cbETH to deposit pool. which would make the Alice's requested withdrawal available in the deposit pool. However, the excess 1 wei will tried to deposited to the deprecated EigenLayer strategy which will not go through because the strategy is removed from the whitelist and not accepting further deposits.

Conclusively, Alice's 10 cbETH is stuck in the contract.
## Impact
Since the EigenLayer emergency situation are accepted as valid issues, I think this issue fits that. 
## Code Snippet
https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/core/StrategyManager.sol#L264-L280

https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/core/StrategyManager.sol#L323-L343
## Tool used

Manual Review

## Recommendation
Add a variable in deposit pool that tells the deposit pool to put excess funds to EigenLayer strategy.