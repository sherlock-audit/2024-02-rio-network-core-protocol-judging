Obedient Carbon Leopard

medium

# Deposits to EigenLayer strategy from deposit pool can revert due to `maxPerDeposit` cap in the EigenLayer strategies

## Summary
The collected LSTs in the deposit pool are deposited to EigenLayer when a rebalance occurs. Rio contracts only check the total cap, but they don't verify the `maxPerDeposit` in the strategy contracts of EigenLayer. If the deposit exceeds the `maxPerDeposit` set in the strategy contract, the rebalancing will revert.
## Vulnerability Detail
Best to demonstrate this with an example, so let's proceed:

Suppose there is only one operator with one strategy in the Rio network, which is the stETH strategy. Users deposit a total of 500 stETH to the contract, which is directly sent to the deposit pool, as evident in the following snippet from the coordinator contract:

```solidity
function deposit(address asset, uint256 amountIn) external checkDeposit(asset, amountIn) returns (uint256 amountOut) {
        // Convert deposited asset amount to restaking tokens.
        amountOut = convertFromAssetToRestakingTokens(asset, amountIn);

        // Pull tokens from the sender to the deposit pool.
        // @review sends directly to depositPool which the funds are stay idle till the rebalancing happens
        -> IERC20(asset).safeTransferFrom(msg.sender, address(depositPool()), amountIn);

        // Mint restaking tokens to the caller.
        token.mint(msg.sender, amountOut);

        emit Deposited(msg.sender, asset, amountIn, amountOut);
    }
```
When the rebalance is called in the coordinator, it triggers the deposit pool to deposit its balance to the EigenLayer. For the sake of this example, let's assume there are no withdrawals queued in the epoch. The following snippet will be called in the deposit pool:
```solidity
function depositBalanceIntoEigenLayer(address asset) external onlyCoordinator returns (uint256, bool) {
        .
        .
        address strategy = assetRegistry().getAssetStrategy(asset);
        uint256 sharesToAllocate = assetRegistry().convertToSharesFromAsset(asset, amountToDeposit);
        -> return (OperatorOperations.depositTokenToOperators(operatorRegistry(), asset, strategy, sharesToAllocate), isDepositCapped);
    }
```

As seen in the above snippet, the `OperatorOperations` library contract is called to deposit the stETH to operators (assuming there is only one in this example). Since there is only one operator, all the shares will be allocated to the stETH strategy, and the `stakeERC20` function will be called in the `OperatorOperations`, which does the following:

```solidity
function stakeERC20(address strategy, address token_, uint256 amount) external onlyDepositPool returns (uint256 shares) {
        if (IERC20(token_).allowance(address(this), address(strategyManager)) < amount) {
            IERC20(token_).forceApprove(address(strategyManager), type(uint256).max);
        }
        // @review deposits all the tokens to strategy
        -> shares = strategyManager.depositIntoStrategy(strategy, token_, amount);
    }
```

As observed above, all the funds are directly sent to the strategy for deposit. Inside the strategy manager contract from EigenLayer, there is a `_beforeDeposit` hook that checks the deposit amount and performs some validations:


```solidity
function _beforeDeposit(IERC20 token, uint256 amount) internal virtual override {
        require(amount <= maxPerDeposit, "StrategyBaseTVLLimits: max per deposit exceeded");
        require(_tokenBalance() <= maxTotalDeposits, "StrategyBaseTVLLimits: max deposits exceeded");

        super._beforeDeposit(token, amount);
    }
```

As seen, the deposited amount is checked to see whether it exceeds the `maxPerDeposit` allowed or not, which is not related to the total cap. In our example, if we were depositing 500 stETH and the `maxPerDeposit` is less than 500 stETH, the call will revert, making rebalancing impossible.

## Impact
Rebalance would revert. However, the owner can set the operators cap to maxPerDeposit and call rebalance quickly and then sets the cap back to normal. However, this would only solve the issue temporarily and can be frontrunned. I am not sure how to label this, will go for medium.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L77-L88

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L121-L151

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTDepositPool.sol#L47-L67

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorOperations.sol#L51-L68

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L342-L392

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L174-L179

https://github.com/Layr-Labs/eigenlayer-contracts/blob/5c192e1a780c22e027f6861f958db90fb9ae263c/src/contracts/core/StrategyManager.sol#L323-L342

https://github.com/Layr-Labs/eigenlayer-contracts/blob/5c192e1a780c22e027f6861f958db90fb9ae263c/src/contracts/core/StrategyManager.sol#L105-L111

https://github.com/Layr-Labs/eigenlayer-contracts/blob/5c192e1a780c22e027f6861f958db90fb9ae263c/src/contracts/strategies/StrategyBaseTVLLimits.sol#L79-L84
## Tool used

Manual `Review`

## Recommendation
Check the `maxPerDeposit` in the strategy contract and cap the deposits to EigenLayer to that amount