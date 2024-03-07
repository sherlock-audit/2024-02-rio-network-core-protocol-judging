Witty Tiger Poodle

high

# The protocol cannot prevent inflation attacks

## Summary
Some tokens with high precision, if the deposit amount is too small, cannot prevent inflation attacks, leading to the ability to steal assets from other users.

## Vulnerability Detail
In the function `RioLRTIssuer.issueLRT()`, the protocol calls the `_deposit()` function to make a sacrificial deposit to prevent inflation attacks. 
```solidity
   // Make a sacrificial deposit to prevent inflation attacks.
        _deposit(
            IRioLRTCoordinator(d.coordinator),
            config.deposit.asset,
            config.deposit.amount
        );
```

The protocol checks that the amount being deposited must be greater than or equal to `MIN_SACRIFICIAL_DEPOSIT`, which is set to 1000. Let's say the asset is a token with 18 decimal places, such as DAI.
```solidity

    function _deposit(IRioLRTCoordinator coordinator, address asset, uint256 amount) internal {
        if (amount < MIN_SACRIFICIAL_DEPOSIT) revert INSUFFICIENT_SACRIFICIAL_DEPOSIT();
        if (asset == ETH_ADDRESS) {
            if (amount != msg.value) revert INVALID_ETH_PROVIDED();
            coordinator.depositETH{value: amount}();
            return;
        }
        IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);
        IERC20(asset).approve(address(coordinator), amount);

        coordinator.deposit(asset, amount);

uint256 constant MIN_SACRIFICIAL_DEPOSIT = 1_000;

```

When the protocol calls `coordinator.deposit()` for the deposit, it internally retrieves the oracle price for the asset and then multiplies the asset's quantity by the asset's value, converting it into the oracle price precision. 
```solidity
    function convertFromAssetToRestakingTokens(address asset, uint256 amount) public view returns (uint256) {
        uint256 value = assetRegistry().convertToUnitOfAccountFromAsset(asset, amount);
        return convertFromUnitOfAccountToRestakingTokens(value);
    }


```

In the case of DAI, with a precision of 18, and the oracle price precision being 8, the conversion to the oracle price precision becomes amount / 10 ** (fromDecimals - toDecimals). Since the amount is 1000, dividing by 10 ** (18-8) results in 0. As a consequence, when calculating the resting token value, it also becomes 0.

```solidity

   function convertToUnitOfAccountFromAsset(address asset, uint256 amount) public view returns (uint256) {
        if (asset == ETH_ADDRESS) {
            return amount;
        }
        address priceFeed = assetInfo[asset].priceFeed;
        uint256 price = getPrice(priceFeed);

        return _normalizeDecimals(price * amount / priceScale, assetInfo[asset].decimals, priceFeedDecimals);
    }

    function convertFromUnitOfAccountToRestakingTokens(uint256 value) public view returns (uint256) {
        uint256 tvl = getTVL();
        uint256 supply = token.totalSupply();

        if (supply == 0) {
            return value;
        }
        return value * supply / tvl;
    }
```

Thus, the protocol obtains 1000 amount from the user and gets 0 LP tokens in return. This scenario fails to prevent inflation attacks. A user could deposit 1 wei, and front-run another user's deposit to transfer assets to the protocol early, causing the second user to lose funds due to round errors. The first user can then profit when withdrawing.

## Impact
Stealing assets from other users

## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTIssuer.sol#L163-L175

## Tool used

Manual Review

## Recommendation
Don't use `balanceOf` to calculate the amount, instead, define a new variables and record the deposited asset amount by the variables