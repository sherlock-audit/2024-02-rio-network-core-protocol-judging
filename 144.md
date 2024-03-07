Silly Jade Capybara

high

# Assets received from EL are assumed to be correct in amounts and not cross checked.

## Summary
Assets received from EL in RioLRTWithdrawalQueue.settleEpochFromEigenLayer() is accepted without cross verification.

## Vulnerability Detail
In the function, epochWithdrawals.assetsReceived is incremented by assetsReceived amount without any cross verification. There may be a problem in EL which returns less/more than what is expected. If less is returned than expected, withdrawal claims may not be fulfilled. However, such check is present when depositing.

## Impact
If EL returns less than expected then the RioLRTWithdrawalQueue may not be able to settle all the claims of the epoch completely.

## Code Snippet
[ epochWithdrawals.assetsReceived += SafeCast.toUint120(assetsReceived);](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTWithdrawalQueue.sol#L268)

## Tool used
Manual Review

## Recommendation
```solidity
if ( assetsReceived >= assetRegistry().convertFromSharesToAsset(assetRegistry().getAssetStrategy(asset),sharesReceivedDuringSettlement) )
 epochWithdrawals.assetsReceived += SafeCast.toUint120(assetsReceived);
else revert INCORRECT_NUMBER_OF_ASSETS_RECEIVED();
```