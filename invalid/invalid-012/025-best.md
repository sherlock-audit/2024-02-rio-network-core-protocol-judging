Wide Laurel Skunk

medium

# RioLRTDepositPool.sol::No check for whether the asset is ETH or not when poolBalanceShareValue >= shareRequested result no reduction from wei to gwei

## Summary
No check for whether the asset is Ether or not, as a result precision was not reduced to gwei in RioLRTDepositPool.sol::transferMaxAssetForShare().
## Vulnerability Detail
This code block checks whether the requested share is greater than the pool balance's share or not, if poolBalanceShareValue >= shareRequested then it means the pool has enough balance to cover the requested share:
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTDepositPool.sol#L90-L96 However this transferMaxAssetForShare() does not check the case where the pool has enough balance to cover the requested share in Ether means when the asset is Ether, this results precision miscalculation because in case of ETH the amount's precision should be reduced to gwei. 
Run this test in RioLRTDepositPool.t.sol contract:
```solidity
    function test_precisionIssue() public {
        address strategy = reETH.assetRegistry.getAssetStrategy(ETH_ADDRESS);
        console.log("Initial balance of withdrawalQueue contract:", address(reETH.withdrawalQueue).balance);
        vm.deal(address(reETH.depositPool), 50 ether);
        vm.prank(address(reETH.coordinator));
        (uint256 assetsSent, uint256 sharesSent) =
                                reETH.depositPool.transferMaxAssetsForShares(ETH_ADDRESS, 9999999999999999999 wei, address(reETH.withdrawalQueue));
        console.log("Now balance of withdrawalQueue contract:", address(reETH.withdrawalQueue).balance);
        assertEq(address(reETH.withdrawalQueue).balance, 9999999999999999999 wei);
    }
```
The log is:
```solidity
[PASS] test_precisionIssue() (gas: 60093)
Logs:
  Initial balance of withdrawalQueue contract: 0
  Now balance of withdrawalQueue contract: 9999999999999999999

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 9.88ms

```
If we convert the 9999999999999999999 wei into gwei we can see:
```solidity
➜ !exec  cast to-unit 9999999999999999999wei gwei
9999999999.999999999
```
As per the system demand the amount sent to withdrawalQueue contract should be 9999999999000000000.
## Impact
Precision was not reduced to gwei while dealing with ether.
## Code Snippet
1. https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTDepositPool.sol#L76-L109
## Tool used

Manual Review, Foundry

## Recommendation
Add a check for whether the asset is ETH or not, if ETH then reduce the precision to gwei.