Radiant Amethyst Haddock

medium

# `requestWithdrawal` doesn't estimate accurately the available shares for withdrawals

## Summary

The `requestWithdrawal` function inaccurately estimates the available shares for withdrawals by including funds stored in the deposit pool into the already deposited EigenLayer shares. This can potentially lead to blocking withdrawals or users receiving less funds for their shares.

## Vulnerability Detail

For a user to withdraw funds from the protocol, they must first request a withdrawal using the `requestWithdrawal` function, which queues the withdrawal in the current epoch by calling `withdrawalQueue().queueWithdrawal`.

To evaluate the available shares for withdrawal, the function converts the protocol asset balance into shares:

```solidity
uint256 availableShares = assetRegistry().convertToSharesFromAsset(asset, assetRegistry().getTotalBalanceForAsset(asset));
```

The issue arises from the `getTotalBalanceForAsset` function, which returns the sum of the protocol asset funds held, including assets already deposited into EigenLayer and assets still in the deposit pool:

```solidity
function getTotalBalanceForAsset(
    address asset
) public view returns (uint256) {
    if (!isSupportedAsset(asset)) revert ASSET_NOT_SUPPORTED(asset);

    address depositPool_ = address(depositPool());
    if (asset == ETH_ADDRESS) {
        return depositPool_.balance + getETHBalanceInEigenLayer();
    }

    uint256 sharesHeld = getAssetSharesHeld(asset);
    uint256 tokensInRio = IERC20(asset).balanceOf(depositPool_);
    uint256 tokensInEigenLayer = convertFromSharesToAsset(
        getAssetStrategy(asset),
        sharesHeld
    );

    return tokensInRio + tokensInEigenLayer;
}
```

This causes the calculated `availableShares` to differ from the actual shares held by the protocol because the assets still in the deposit pool shouldn't be converted to shares with the current share price (shares/asset) as they were not deposited into EigenLayer yet.

Depending on the current shares price, the function might over or under-estimate the available shares in the protocol. This can potentially result in allowing more queued withdrawals than the available shares in the protocol, leading to blocking withdrawals later on or users receiving less funds for their shares.

## Impact

The `requestWithdrawal` function inaccurately estimates the available shares for withdrawals, potentially resulting in blocking withdrawals or users receiving less funds for their shares.

## Code Snippet

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L111-L114

## Tool used

Manual Review

## Recommendation

There is no straightforward way to handle this issue as the asset held by the deposit pool can't be converted into shares while they were not deposited into EigenLayer. The code should be reviewed to address this issue.