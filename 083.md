Wide Laurel Skunk

high

# RioLRTOperatorRegistry::exited keys are accounted while calculating unallocated confirmed key

## Summary
Exited validator keys are accounted while calculating confirmed keys which have not received a deposit yet results less eth deposit to EigenLayer.
## Vulnerability Detail
Lets see the OperatorValidatorDetails struct:
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/interfaces/IRioLRTOperatorRegistry.sol#L40-L56 Here `exited` is part of `deposited`, when assets are withdrawn the `exited` is increased. We can see how `activeDeposits` are calculated:
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L417 The `validators.exited` are not active keys, that is why it was removed from `validators.deposited`, so we can say that `exited` is a part of `deposited` but it is inactive part so we had to cut it from `deposited` to get active part. This inactive part should not be accounted while calculating confirmed active keys which has not received a deposit yet i.e `unallocatedConfirmedKeys`:
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L431 But in this above snippet we can see that the inactive part was accounted.

Lets assume following assumptions:
validators.total = 50
validators.confirmed = 30
validators.deposited = 10
validators.exited = 5
Unconfirmed keys are = (50 - 30) = 20, we are not interested in this. We are interested in confirmed keys, which contains confirmed number of keys which received deposit and these keys [ which received deposit ] contains confirmed number of keys which exited means not active. 
As per current implementation of code the exited keys were accounted, if we follow current implementation we can see:
- activeDeposits = validators.deposited - validators.exited = 10 - 5 = 5
- unallocatedConfirmedKeys = validators.confirmed - validators.deposited = 30 - 10 = 20

But if we remove the inactive keys i.e the exited keys then we can see:
- unallocatedConfirmedKeys = validators.confirmed - activeDeposits = 30 - 5 = 25

Each key is chunk of 32 ETH so for first case total amount of ether = 20 x 32 = 640 ether
And for second case the amount of ether = 25 x 32 = 800 ether

As we can only allocate up to the number of unallocated confirmed keys so this amount of ether is supposed to sent to EigenLayer.

## Impact
Less amount of ether than desired amount will be sent to EigenLayer, see the Vulnerability details section.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L412-L463
## Tool used

Manual Review

## Recommendation
Calculate `unallocatedConfirmedKeys` like this: 
```solidity
unallocatedConfirmedKeys = validators.confirmed - activeDeposits;
```