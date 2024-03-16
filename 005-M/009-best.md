Obedient Carbon Leopard

high

# Depositing to EigenLayer can revert due to round downs in converting shares<->assets

## Summary
When the underlying tokens deposited from depositPool to EigenLayer strategy, there are bunch of converting operations done which rounds down the solution at some point and the require check reverts hence, the depositing might not be possible due to this small round down issue. 
## Vulnerability Detail
Best to go for this is an example, so let's do it.

Assume the deposit pool has 111 * 1e18 stETH waiting for rebalance to be deposited to EigenLayer and there is only 1 operator with 1 strategy allowed which is the EigenLayers stETH strategy. 
Also, assume the EigenLayer has 3333 * 1e18 stETH in total and 3232  * 1e18 shares in supply. Also, note that the EigenLayer uses virtual shares offset which is 1e3.

Now, let's say there is no withdrawal queue to ease the complexity of the issue and rebalance is called and the balance in the deposit pool will be forwarded to EigenLayer strategy as follows:
```solidity
function rebalance(address asset) external checkRebalanceDelayMet(asset) {
        .
        .
        // Deposit remaining assets into EigenLayer.
        (uint256 sharesReceived, bool isDepositCapped) = depositPool().depositBalanceIntoEigenLayer(asset);
        .
    }
```

Then, the `depositBalanceIntoEigenLayer` will trigger the `OperatorOperations.depositTokenToOperators` function as follows:
```solidity 
function depositBalanceIntoEigenLayer(address asset) external onlyCoordinator returns (uint256, bool) {
        uint256 amountToDeposit = asset.getSelfBalance();
        if (amountToDeposit == 0) return (0, false);
        .
        .
        address strategy = assetRegistry().getAssetStrategy(asset);
        uint256 sharesToAllocate = assetRegistry().convertToSharesFromAsset(asset, amountToDeposit);
        // @review library called
        -> return (OperatorOperations.depositTokenToOperators(operatorRegistry(), asset, strategy, sharesToAllocate), isDepositCapped);
    }
```
As we can see in the above snippet, the underlying tokens to be deposited which is 111 * 1e18 stETH in our example will be converted to EigenLayer strategy shares via `assetRegistry().convertToSharesFromAsset`

Now, how does EigenLayer calculates how much shares to be minted given an underlying token deposit is as follows:
```solidity
function underlyingToSharesView(uint256 amountUnderlying) public view virtual returns (uint256) {
        // account for virtual shares and balance
        uint256 virtualTotalShares = totalShares + SHARES_OFFSET;
        uint256 virtualTokenBalance = _tokenBalance() + BALANCE_OFFSET;
        // calculate ratio based on virtual shares and balance, being careful to multiply before dividing
        return (amountUnderlying * virtualTotalShares) / virtualTokenBalance;
    }
```

Now, let's plugin our numbers in the example to calculate how much shares would be minted according to EigenLayer:
`virtualTotalShares` = 3232 * 1e18 + 1e3
`virtualTokenBalance` = 3333 * 1e18 + 1e3
`amountUnderlying` = 111 * 1e18

**and when we do the math we will calculate the shares to be minted as:
107636363636363636364**

Then, the library function will be executed as follows:
```solidity
function depositTokenToOperators(
        IRioLRTOperatorRegistry operatorRegistry,
        address token,
        address strategy,
        uint256 sharesToAllocate // @review 107636363636363636364 as we calculated above!
    ) internal returns (uint256 sharesReceived) {
        (uint256 sharesAllocated, IRioLRTOperatorRegistry.OperatorStrategyAllocation[] memory  allocations) = operatorRegistry.allocateStrategyShares(
            strategy, sharesToAllocate
        );

        for (uint256 i = 0; i < allocations.length; ++i) {
            IRioLRTOperatorRegistry.OperatorStrategyAllocation memory allocation = allocations[i];

            IERC20(token).safeTransfer(allocation.delegator, allocation.tokens);
            sharesReceived += IRioLRTOperatorDelegator(allocation.delegator).stakeERC20(strategy, token, allocation.tokens);
        }
        if (sharesReceived != sharesAllocated) revert INCORRECT_NUMBER_OF_SHARES_RECEIVED();
    }
```

The very first line of the above snippet executes the `operatorRegistry.allocateStrategyShares`, let's examine that:
```solidity
 function allocateStrategyShares(address strategy, uint256 sharesToAllocate) external onlyDepositPool returns (uint256 sharesAllocated, OperatorStrategyAllocation[] memory allocations) {
        .
        uint256 remainingShares = sharesToAllocate;
        allocations = new OperatorStrategyAllocation[](s.activeOperatorCount);
        while (remainingShares > 0) {
            .
            .
            uint256 newShareAllocation = FixedPointMathLib.min(operatorShares.cap - operatorShares.allocation, remainingShares);
            uint256 newTokenAllocation = IStrategy(strategy).sharesToUnderlyingView(newShareAllocation);
            allocations[allocationIndex] = OperatorStrategyAllocation(
                operator.delegator,
                newShareAllocation,
                newTokenAllocation
            );
            remainingShares -= newShareAllocation;
            .
            .
        }
        sharesAllocated = sharesToAllocate - remainingShares;
        .
        .
    }
```

So, let's value the above snippet aswell considering the cap is not reached. As we can see the how much underlying token needed is again calculated by querying the EigenLayer strategy `sharesToUnderlyingView`, so let's first calculate that:
```solidity
function sharesToUnderlyingView(uint256 amountShares) public view virtual override returns (uint256) {
        // account for virtual shares and balance
        uint256 virtualTotalShares = totalShares + SHARES_OFFSET;
        uint256 virtualTokenBalance = _tokenBalance() + BALANCE_OFFSET;
        // calculate ratio based on virtual shares and balance, being careful to multiply before dividing
        return (virtualTokenBalance * amountShares) / virtualTotalShares;
    }
```
Let's put the values to above snippet:
`virtualTotalShares` = 3232 * 1e18 + 1e3
`virtualTokenBalance` = 3333 * 1e18 + 1e3
`amountShares` = 107636363636363636364
**hence, the return value is 110999999999999999999(as you noticed it is not 111 * 1e18 as we expect!)**

`sharesToAllocate` =  remainingShares  = newShareAllocation  = 107636363636363636364
`newTokenAllocation` = 110999999999999999999
`sharesAllocated` = 107636363636363636364

Now, let's go back to `depositTokenToOperators` function and move with the execution flow:

as we can see the underlying tokens we calculated (110999999999999999999) is deposited to EigenLayer for shares here and then compared in the last line in the if check as follows:
```solidity
for (uint256 i = 0; i < allocations.length; ++i) {
            IRioLRTOperatorRegistry.OperatorStrategyAllocation memory allocation = allocations[i];

            IERC20(token).safeTransfer(allocation.delegator, allocation.tokens);
            sharesReceived += IRioLRTOperatorDelegator(allocation.delegator).stakeERC20(strategy, token, allocation.tokens);
        }
        if (sharesReceived != sharesAllocated) revert INCORRECT_NUMBER_OF_SHARES_RECEIVED();
```

`stakeERC20` will stake 110999999999999999999 tokens and in exchange **will receive 107636363636363636363** shares. Then the `sharesReceived` will be compared with the **initial share amount calculation which is 107636363636363636364**

**hence, the last if check will revert because
107636363636363636363 != 107636363636363636364**

**Coded PoC:**
```solidity
function test_RioRoundingDownPrecision() external pure returns (uint, uint) {
        uint underlyingTokens = 111 * 1e18;
        uint totalUnderlyingTokensInEigenLayer = 3333 * 1e18;
        uint totalSharesInEigenLayer = 3232 * 1e18;
        uint SHARE_AND_BALANCE_OFFSET = 1e3;

        uint virtualTotalShares =  totalSharesInEigenLayer + SHARE_AND_BALANCE_OFFSET;
        uint virtualTokenBalance = totalUnderlyingTokensInEigenLayer + SHARE_AND_BALANCE_OFFSET;

        uint underlyingTokensToEigenLayerShares = (underlyingTokens * virtualTotalShares) / virtualTokenBalance;
        uint eigenSharesToUnderlying = (virtualTokenBalance * underlyingTokensToEigenLayerShares) / virtualTotalShares;

        // we expect eigenSharesToUnderlying == underlyingTokens, which is not
        require(eigenSharesToUnderlying != underlyingTokens);

        return (underlyingTokensToEigenLayerShares, eigenSharesToUnderlying);
    }
```
## Impact
The issue described above can happen frequently as long as the perfect division is not happening when converting shares/assets. In order to solve the issue the amounts and shares has to be perfectly divisible such that the rounding down is not an issue. This can be fixed by owner to airdrop some assets such that this is possible. However, considering how frequent and easy the above scenario can happen and owner needs to do some math to fix the issue, I'll label this as high.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTDepositPool.sol#L47-L67

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L215-L221

https://github.com/Layr-Labs/eigenlayer-contracts/blob/5c192e1a780c22e027f6861f958db90fb9ae263c/src/contracts/strategies/StrategyBase.sol#L211-L243

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorOperations.sol#L51-L68

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L342-L392

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L174-L179
## Tool used

Manual Review

## Recommendation
