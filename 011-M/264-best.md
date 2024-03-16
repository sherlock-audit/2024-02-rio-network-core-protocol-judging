Vast Peach Cyborg

high

# Users can receive less tokens than expected due to precision loss

## Summary

When user makes a deposit into the RIO LRT Coordinator, the amount of due LST is calculated with a precision loss bug. As a result, the user can receive much less LST than expected.

## Vulnerability Detail

Users can deposit asset to Rio via the `RioLRTCoordinator::deposit()` method. Inside this method, the due `amountOut` of LST is calculated like this:

```javascript
amountOut = convertFromAssetToRestakingTokens(asset, amountIn);
```

The method `RioLRTCoordinator::convertFromAssetToRestakingTokens()` does the following calculation:

```javascript
function convertFromAssetToRestakingTokens(address asset, uint256 amount) public view returns (uint256) {
        uint256 value = assetRegistry().convertToUnitOfAccountFromAsset(asset, amount);
        return convertFromUnitOfAccountToRestakingTokens(value);
}
```

In order to calculate the due amount of LST, the value of asset deposited by the user gets converted to ETH. Subsequently, the value in ETH gets converted to the value in LST. The first calculation of value in ETH is executed in the `RioLRTAssetRegistry::convertToUnitOfAccountFromAsset()` method:

```javascript
function convertToUnitOfAccountFromAsset(address asset, uint256 amount) public view returns (uint256) {
        if (asset == ETH_ADDRESS) {
            return amount;
        }
        address priceFeed = assetInfo[asset].priceFeed;
        uint256 price = getPrice(priceFeed);

        return _normalizeDecimals(price * amount / priceScale, assetInfo[asset].decimals, priceFeedDecimals);
}
```

The math is as follows:

**valueInEth = \_normalizeDecimals(price \* amount / priceScale, tokenDecimals, priceFeedDecimals)**

When we investigate the `RioLRTAssetRegistry::_normalizeDecimals()` method, we can see that it multiplies or divides the argument by the difference between decimals of asset and its price feed:

```javascript
function _normalizeDecimals(uint256 amount, uint8 fromDecimals, uint8 toDecimals) internal pure returns (uint256) {
        // No adjustment needed if decimals are the same.
        if (fromDecimals == toDecimals) {
            return amount;
        }
        // Scale down to match the target decimal precision.
        if (fromDecimals > toDecimals) {
            return amount / 10 ** (fromDecimals - toDecimals);
        }
        // Scale up to match the target decimal precision.
        return amount * 10 ** (toDecimals - fromDecimals);
}
```

Let's consider a scenario where the decimals of token asset (`fromDecimals`) are smaller than the decimals of price feed (`toDecimals`). As example of such a scenario will be `USDT` asset, which has 6 decimals, while its price feed has 18 decimals.

The final formula for the ETH value will be then as follows:

**valueInEth = (price \* amount / priceScale) \* 10 \*\* (toDecimals - fromDecimals)**

Applying the `USDT` scenario decimals gives us:

**valueInEth = (price \* amount / 10e18) \* 10e12**

We can see a division happening before multiplication. As Solidity rounds down integer divisions, it is strongly advised to perform multiplications before divisions in order to avoid precision losses. This advice is not followed here and the calculation leads to loss of precision.

The vulnerable method `RioLRTAssetRegistry::_normalizeDecimals()` is also utilized in calculating the amounts for withdrawal and calculating the TVLs. As such, the precision loss issue scope is broad as it affects multiple scenarios of interaction within the Rio protocol.

## Impact

The amount of LST minted for the user can be much less than expected if the deposited asset decimals are lower than price feed decimals. This scenario is likely to happen, as the documentation states:

> We plan to support tokens with no less than 6 decimals and no more than 18 decimals

The precision loss may also impact the amounts withdrawn from the Protocol.

## Proof of concept

Run the following test inside a Foundry test suite to demonstrate the precision loss:

```javascript
function test_precisionLoss(uint256 amount) public {
        vm.assume(amount > 1e6);
        vm.assume(amount < 1000e6);       

        uint256 price = 294104713183814; //The USDT/ETH hardcoded price
        uint256 tokenDecimals = 6;
        uint256 priceFeedDecimals = 18;
        uint256 priceScale = uint64(10) ** priceFeedDecimals; //10e18
        uint256 decimalsNormalizer = uint64(10) ** (priceFeedDecimals - tokenDecimals); //10e12

        uint256 priceCalculatedAsForNow = ((price * amount / priceScale) * decimalsNormalizer);
        uint256 priceCalculatedCorrectly = ((price * amount * decimalsNormalizer) / priceScale);
        
        assertEq(priceCalculatedAsForNow, priceCalculatedCorrectly);
}
```

Example of precision loss:

```javascript
Error: a == b not satisfied [uint]
        Left: 294000000000000
       	Right: 294105007288527
```

## Code Snippet

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L195

## Tool used

Manual Review

## Recommendation

Always execute the division after the multiplications to avoid precision loss.