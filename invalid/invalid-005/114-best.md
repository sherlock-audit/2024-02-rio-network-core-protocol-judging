Witty Tiger Poodle

medium

# Revert on Large Approvals & Transfers

## Summary
Some tokens (e.g. UNI, COMP) revert if the value passed to approve or transfer is larger than uint96.


## Vulnerability Detail
In the `RioLRTOperatorDelegator.stakeERC20()` function, if the contract's allowance for the strategy manager is less than the stake amount, the contract forcefully sets the allowance for the strategy manager to the maximum value of uint256 using the `forceApprove()` function to ensure the stake operation can proceed. 
```solidity
    function stakeERC20(address strategy, address token_, uint256 amount) external onlyDepositPool returns (uint256 shares) {
        if (IERC20(token_).allowance(address(this), address(strategyManager)) < amount) {
            IERC20(token_).forceApprove(address(strategyManager), type(uint256).max);
        }
        shares = strategyManager.depositIntoStrategy(strategy, token_, amount);
    }

```

However, Some tokens (e.g., [UNI](https://etherscan.io/token/0x1f9840a85d5af5bf1d1762f925bdaddc4201f984#code), COMP) revert if the value passed to approve or transfer is larger than uint96.



## Impact
Revert on large approvals 

## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L176

## Tool used

Manual Review

## Recommendation
Recommend handling tokens of this type.

