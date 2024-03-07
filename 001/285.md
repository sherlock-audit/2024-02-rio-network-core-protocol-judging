Brief Chartreuse Tadpole

medium

# Price arbitrage between different assets supporting a single LRT token

## Summary

A malicious actor can exploit price fluctuations in oracles and withdraw with a significant profit within a short time (24h), exposing the protocol to losses.

## Vulnerability Detail

A single LRT token can be supported by multiple different LST assets (like RETH, CBETH).

When a user deposits LST tokens, the amount of minted LRT tokens (e.g., reETH) is calculated based on the price fetched from an oracle.
The project utilizes the Chainlink oracle, which allows deviations depending on the asset. For instance, CBETH/ETH has a 1% deviation, RETH/ETH 2%, STETH/ETH 0.5%.

On the other hand, at the time of withdrawal, the user can select which asset they want to exchange their LRT tokens for, and if they are in the internal deposit (waiting for rebalance and transfer to eigenlayer), they can withdraw them in a short time span of 24h without waiting for the protocol to withdraw funds from eigenlayer (withdrawal takes 7 days).

LRT tokens are sent to the user immediately after deposit, and are available; similarly, the amount owed is calculated immediately upon calling the function (only waiting for the actual withdrawal of the calculated amount).

This mechanism allows for simultaneous deposits of one LST asset and, if another LST asset is pending in the internal deposit for the given epoch, the user can exploit oracle fluctuations on these two assets and immediately request the withdrawal of the second asset. With proper monitoring of prices in example assets RETH and CBETH, this can result in profits of up to 3% in just 24 hours.

While in the case of DEXs and lending pools, price arbitrage is a positive phenomenon balancing prices, in the case of the RIO protocol, there is no need to balance prices, and this is a move on which the protocol loses, covering the differences in rates.

## Impact

The protocol will suffer losses due to price differences in a very short time due to permissible price fluctuations by Chainlink.

## Code Snippet

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L77

```solidity
File: rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol
77:     function deposit(address asset, uint256 amountIn) external checkDeposit(asset, amountIn) returns (uint256 amountOut) {
78:         // Convert deposited asset amount to restaking tokens.
79:         amountOut = convertFromAssetToRestakingTokens(asset, amountIn);//@audit instant calculation witch oracle
80: 
81:         // Pull tokens from the sender to the deposit pool.
82:         IERC20(asset).safeTransferFrom(msg.sender, address(depositPool()), amountIn);
83: 
84:         // Mint restaking tokens to the caller.
85:         token.mint(msg.sender, amountOut); //@audit transfer
86: 
87:         emit Deposited(msg.sender, asset, amountIn, amountOut);
88:     }
```

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L99

```solidity
File: rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol
099:     function requestWithdrawal(address asset, uint256 amountIn) external checkWithdrawal(asset, amountIn) returns (uint256 sharesOwed) {
100:         // Determine the amount of shares owed to the withdrawer using the current exchange rate.
101:         sharesOwed = convertToSharesFromRestakingTokens(asset, amountIn);//@audit instant calculation witch oracle
102: 
103:         // If requesting ETH, reduce the precision of the shares owed to the nearest Gwei,
104:         // which is the smallest unit of account supported by EigenLayer.
105:         if (asset == ETH_ADDRESS) sharesOwed = sharesOwed.reducePrecisionToGwei();
106: 
107:         // Pull restaking tokens from the sender to the withdrawal queue.
108:         token.safeTransferFrom(msg.sender, address(withdrawalQueue()), amountIn);
109: 
110:         // Ensure there are enough shares to cover the withdrawal request, and queue the withdrawal.
111:         uint256 availableShares = assetRegistry().convertToSharesFromAsset(asset, assetRegistry().getTotalBalanceForAsset(asset));
112:         if (sharesOwed > availableShares - withdrawalQueue().getSharesOwedInCurrentEpoch(asset)) {
113:             revert INSUFFICIENT_SHARES_FOR_WITHDRAWAL();
114:         }
115:         withdrawalQueue().queueWithdrawal(msg.sender, asset, sharesOwed, amountIn); //@audit queue calculated amount
116:     }
```

## Tool used

Manual Review

## Recommendation

A mechanism for balancing and maintaining prices as close to current as possible can minimize the problem while retaining one of RIO's best features: fast 24-hour withdrawals.

One solution could be to use multiple oracles and calculate the average of the obtained prices. Another approach could be to use, for example, three oracles and discard the price that deviates the most from the others and average the rest.