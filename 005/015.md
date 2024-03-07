Obedient Carbon Leopard

medium

# AssetRegistry owner can be frontrunned when removing asset

## Summary
The AssetRegistry owner can remove an asset at any time, provided that certain checks are satisfied. One of these checks is that the TVL for the asset must be "0". This implies that the asset should not exist in the system at all, neither in the deposit pool nor in the EigenLayer strategy. However, anyone can donate 1 wei of the asset to the deposit pool address to grief the owner, and the owner cannot do anything to prevent it.
## Vulnerability Detail
This is the validation checks in the `removeAsset` function implemented:

```solidity
function removeAsset(address asset) external onlyOwner {
        if (!isSupportedAsset(asset)) revert ASSET_NOT_SUPPORTED(asset);
        // @review someone can donate 1 wei to grief here
        -> if (getTVLForAsset(asset) > 0) revert ASSET_HAS_BALANCE();
        .
    }
```

now let's also check how `getTVLForAsset` function is implemented:

```solidity
function getTVLForAsset(address asset) public view returns (uint256) {
        uint256 balance = getTotalBalanceForAsset(asset);
        if (asset == ETH_ADDRESS) {
            return balance;
        }
        return convertToUnitOfAccountFromAsset(asset, balance);
    }

function getTotalBalanceForAsset(address asset) public view returns (uint256) {
        .
        .
        -> uint256 tokensInRio = IERC20(asset).balanceOf(depositPool_);
        uint256 tokensInEigenLayer = convertFromSharesToAsset(getAssetStrategy(asset), sharesHeld);

        return tokensInRio + tokensInEigenLayer;
    }
```

as we can observe, `tokensInRio` variable is the `IERC20.balanceOf` call result which means that if anyone donates 1 wei of the asset to deposit pool just before the owners `removeAsset` tx, then the tx will revert.

**Another scenario from same root cause:**
Since every LRT gets a sacrificial deposit in the deployment phrase, there will be always some excess tokens that are not possible to be burnt because the coordinator can't burn the LRT tokens received in deployment. 
## Impact
Very cheap to execute the attack (1 wei of token) and can be called simply even every block to grief owner if really wanted.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L250C5-L263C6

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L79-L102

## Tool used

Manual Review

## Recommendation
