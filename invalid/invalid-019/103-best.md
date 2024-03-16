Cool Aquamarine Unicorn

medium

# Out of gas due to unchecked array length

## Summary
`RioLRTWithdrawalQueue::claimWithdrawalsForManyEpochs` receives an array of `ClaimRequests` as parameter that has no check on the length of it which could lead to an out of gas error.
## Vulnerability Detail
There is no upper limit on `ClaimRequest[] calldata requests`, users can enter an array of any length and run out of gas due to "gas limit" or "block gas limit" and suffer large losses of funds in gas costs.
Moreover, since the user would see his transaction reversed without a proper error explaining the situation, he would not know how to withdraw correctly.

A test to check this situation was already done by the protocol on `test/RioLRTWithdrawalQueueTest::test_claimWithdrawalsForManyEpochsTillBlockGasLimit`.

I consider this check necessary given the small amount of epochs (100) it needs to revert and cause the gas loss for the user.
## Impact
Users could suffer large losses of funds in the cost of gas without proper error handling.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTWithdrawalQueue.sol#L110-L122
## Tool used

Manual Review
## Recommendation
Add a limit on the length array and throw a proper error when the max length is reached:
```diff
    /// @notice Withdraws owed assets owed to the caller from many withdrawal requests.
    /// @param requests The withdrawal claim request.
    function claimWithdrawalsForManyEpochs(ClaimRequest[] calldata requests)
        external
        returns (uint256[] memory amountsOut)
    {
        uint256 requestLength = requests.length;
		
+		if(requestLength > ARRAY_LIMIT) revert ARRAY_LIMIT_REACHED(); 
        
        amountsOut = new uint256[](requestLength);
        for (uint256 i; i < requestLength; ++i) {
            amountsOut[i] = claimWithdrawalsForEpoch(requests[i]);
        }
    }
```
