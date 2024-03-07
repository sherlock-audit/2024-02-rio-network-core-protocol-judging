Obedient Carbon Leopard

high

# `forceApprove` function is not implemented in most of the EigenLayer underlying tokens

## Summary
When operator delegator deposits the underlying token to strategy manager of EigenLayer, it uses `forceApprove` function from ERC20 to give allowance to strategy manager contract. However, majority of the underlying tokens that can be used in EigenLayer do not implement the `forceApprove` method. 
## Vulnerability Detail
Tokens such as cbETH and rETH, which are used in EigenLayer and have corresponding strategies deployed, do not implement the `forceApprove` method. 
https://etherscan.io/address/0xBe9895146f7AF43049ca1c1AE358B0541Ea49704#writeProxyContract
https://etherscan.io/token/0xae78736cd615f374d3085123a210448e74fc6393#writeContract

Consequently, the attempt to stake these tokens in EigenLayer fails due to the absence of `forceApprove`. The following lines of code demonstrate the issue:
```solidity
function stakeERC20(address strategy, address token_, uint256 amount) external onlyDepositPool returns (uint256 shares) {
        if (IERC20(token_).allowance(address(this), address(strategyManager)) < amount) {
            -> IERC20(token_).forceApprove(address(strategyManager), type(uint256).max);
        }
        shares = strategyManager.depositIntoStrategy(strategy, token_, amount);
    }
```
## Impact
Funds can't be pushed to EigenLayer. Breaks the core logic.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L174-L179
## Tool used

Manual Review

## Recommendation
approve to 0 first and then approve to max instead of using forceApprove