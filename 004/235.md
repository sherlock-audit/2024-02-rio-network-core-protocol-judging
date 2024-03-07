Obedient Carbon Leopard

medium

# All operators can have ETH deposits regardless of the cap setted for them leading to miscalculated TVL

## Summary
Some operators might not be eligible for using some strategies in the LRT's underlying tokens. However, in default every operator can have ETH deposits which would impact the TVL/Exchange rate of the LRT regardless of they have a cap or not. 
## Vulnerability Detail
First, let's examine how an operator can have ETH deposit

An operator can have ETH deposits by simply staking in beacon chain, to do so they are not mandatory to call EigenPods "stake" function. They can do it separately without calling the EigenPods [stake](https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L403-L412) function. 

Also, every operator delegator contract can call [`verifyWithdrawalCredentials`](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L135-L145) to increase EigenPod shares and decrease the queued ETH regardless of they are active operator or they have a cap determined for BEACON_CHAIN_STRATEGY. 

Now, let's look at how the TVL of ETH (BEACON_CHAIN_STRATEGY) is calculated in the AssetRegistry:
```solidity
function getTVLForAsset(address asset) public view returns (uint256) {
        uint256 balance = getTotalBalanceForAsset(asset);
        if (asset == ETH_ADDRESS) {
            return balance;
        }
        return convertToUnitOfAccountFromAsset(asset, balance);
    }

    function getTotalBalanceForAsset(address asset) public view returns (uint256) {
        if (!isSupportedAsset(asset)) revert ASSET_NOT_SUPPORTED(asset);

        address depositPool_ = address(depositPool());
        if (asset == ETH_ADDRESS) {
            return depositPool_.balance + getETHBalanceInEigenLayer();
        }

        uint256 sharesHeld = getAssetSharesHeld(asset);
        uint256 tokensInRio = IERC20(asset).balanceOf(depositPool_);
        uint256 tokensInEigenLayer = convertFromSharesToAsset(getAssetStrategy(asset), sharesHeld);

        return tokensInRio + tokensInEigenLayer;
    }

    function getETHBalanceInEigenLayer() public view returns (uint256 balance) {
        balance = ethBalanceInUnverifiedValidators;

        IRioLRTOperatorRegistry operatorRegistry_ = operatorRegistry();
        -> uint8 endAtID = operatorRegistry_.operatorCount() + 1; // Operator IDs start at 1.
        -> for (uint8 id = 1; id < endAtID; ++id) {
            -> balance += operatorDelegator(operatorRegistry_, id).getETHUnderManagement();
        }
    }
```

As we can see above, regardless of the operators cap the entire active validator counts are looped. 

```solidity
function getEigenPodShares() public view returns (int256) {
        return eigenPodManager.podOwnerShares(address(this));
    }

    function getETHQueuedForWithdrawal() public view returns (uint256) {
        uint256 ethQueuedSlotData;
        assembly {
            ethQueuedSlotData := sload(ethQueuedForUserSettlementGwei.slot)
        }

        uint64 userSettlementGwei = uint64(ethQueuedSlotData);
        uint64 operatorExitAndScrapeGwei = uint64(ethQueuedSlotData >> 64);

        return (userSettlementGwei + operatorExitAndScrapeGwei).toWei();
    }

    function getETHUnderManagement() external view returns (uint256) {
        int256 aum = getEigenPodShares() + int256(getETHQueuedForWithdrawal());
        if (aum < 0) return 0;

        return uint256(aum);
    }
```

Since the operator has eigen pod shares, the TVL will account it aswell. However, since the operator is not actively participating on ether deposits (not in the heap order) the withdrawals or deposits to this specific operator is impossible. Hence, the TVL is accounting an operators eigen pod share which the contract assumes that it is not in the heap. 

**Textual PoC:**
Assume there are 5 operators whereas only 4 of these operators are actively participating in BEACON_CHAIN_STRATEGY which means that 1 operator has no validator caps set hence, it is not in the heap order.
However, this operator can still have ether deposits and can verify them. Since the TVL accounting **loops over all the operators but not the operators that are actively participating in beacon chain strategy**, the TVL calculated will be wrong. 
## Impact
Miscalculation of total ether holdings of an LRT. Withdrawals can fail because the calculated ether is not existed in the heap but the TVL says there are ether to withdraw from the LRT.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L79-L114

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L101-L126
## Tool used

Manual Review

## Recommendation
put a check on `verifyWithdrawalCredentials` that is not possible to call the function if the operator is not actively participating in the BEACON_CHAIN_STRATEGY. 