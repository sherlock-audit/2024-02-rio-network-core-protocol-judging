Obedient Carbon Leopard

medium

# If the operators receives or tries to deposit dust amount of shares then the rebalance will not be possible

## Summary
Operators has caps when depositing to the strategies of EigenLayer. If the deposited amount is dust then the round down of the shares minted can be "0" which the tx would revert in EigenLayer side. This would brick the deposit and rebalance flow completely. 
## Vulnerability Detail
When the deposit pool has excess balance, the balance will be distributed to operators respecting their utilizations and caps. Assume the least utilized operator has only a few remaining spots left, which is a dust amount like 1e3. Now, let's see what would happen in the allocation flow:
```solidity
function allocateStrategyShares(address strategy, uint256 sharesToAllocate) external onlyDepositPool returns (uint256 sharesAllocated, OperatorStrategyAllocation[] memory allocations) {
        .
        while (remainingShares > 0) {
            .
            .
           -> uint256 newShareAllocation = FixedPointMathLib.min(operatorShares.cap - operatorShares.allocation, remainingShares);
            -> uint256 newTokenAllocation = IStrategy(strategy).sharesToUnderlyingView(newShareAllocation);
            allocations[allocationIndex] = OperatorStrategyAllocation(
                operator.delegator,
                newShareAllocation,
                newTokenAllocation
            );
            .
            .
        }
       .
    }
```

As we can observe in the above snippet, if the amount is dust, then `uint256 newTokenAllocation = IStrategy(strategy).sharesToUnderlyingView(newShareAllocation);` can be rounded down to "0" since EigenLayer rounds down when calculating the underlying tokens needed. Then, the `newTokenAllocation` will be equal to "0", and the delegation operator deposits the amount to EigenLayer as follows:

```solidity
function stakeERC20(address strategy, address token_, uint256 amount) external onlyDepositPool returns (uint256 shares) {
        if (IERC20(token_).allowance(address(this), address(strategyManager)) < amount) {
            IERC20(token_).forceApprove(address(strategyManager), type(uint256).max);
        }
        -> shares = strategyManager.depositIntoStrategy(strategy, token_, amount);
    }
```

From the above snippet, we can see that the `strategyManager.depositIntoStrategy` will be called with an amount of "0". Now, let's examine how EigenLayer handles the "0" amount deposits:

```solidity
function deposit(
        IERC20 token,
        uint256 amount
    ) external virtual override onlyWhenNotPaused(PAUSED_DEPOSITS) onlyStrategyManager returns (uint256 newShares) {
        .
        .
        // account for virtual shares and balance
        uint256 virtualShareAmount = priorTotalShares + SHARES_OFFSET;
        uint256 virtualTokenBalance = _tokenBalance() + BALANCE_OFFSET;
        // calculate the prior virtual balance to account for the tokens that were already transferred to this contract
        uint256 virtualPriorTokenBalance = virtualTokenBalance - amount;
        newShares = (amount * virtualShareAmount) / virtualPriorTokenBalance;

        // extra check for correctness / against edge case where share rate can be massively inflated as a 'griefing' sort of attack
        -> require(newShares != 0, "StrategyBase.deposit: newShares cannot be zero");
        .
    }
```

As we can see, if the shares to be minted are "0," which will be the case since we try to deposit "0" amount of tokens, then the transaction will revert, hence, the entire deposit flow will be halted.

Malicious Scenario:
Assume that at an epoch, there are "N" assets requested for withdrawal, and there are no deposits to the LRT token. The attacker can donate 1 wei to the deposit pool just before the rebalance call. Subsequently, the rebalance would attempt to withdraw the "N" tokens as normal. However, when it tries to deposit the excess back to operators, which is only "1 wei," the transaction can revert since it's a dust amount.
## Impact
The above scenarios can happen in normal flow or can be triggered by a malicious user. There is a DoS threat and it needs donations or owner manually lowering the caps. Hence, I will label this as medium.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L342-L392

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L174-L179

https://github.com/Layr-Labs/eigenlayer-contracts/blob/5c192e1a780c22e027f6861f958db90fb9ae263c/src/contracts/strategies/StrategyBase.sol#L96-L123
## Tool used

Manual Review

## Recommendation
If the amount is dust then skip to the next operator and ignore the amount, don't deposit. 