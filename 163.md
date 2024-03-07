Plain Vinyl Cobra

high

# First depositor/attacker can manipulate the totalsupply of restaking token which will lead to later depositors to mint 0 restaking tokens.

## Summary
First depositor/attacker can manipulate the totalsupply of restaking token which will lead to later depositors to mint 0 restaking tokens.

## Vulnerability Detail
1. .attacker/first depositor mint 10 restaking token and immediately removes all but kept 1 wei.
2.  Attacker then directly transfer 10 ETH worth of an asset in depositPool contract.
3. When the second user calls the function depositAsset with 5 ETH worth of an asset amount(less than 10 ETH worth of an asset amount), no additional restaking tokens are minted since  convertFromUnitOfAccountToRestakingTokens is rounded down to 0 i.e as value(in unit of account) = 5e18, tvl(in unit of account) = 10e18,supply = 1 wei. So return value = 0.


## Impact
The first user that stakes can manipulate the total supply of restaking tokens and by doing so create a rounding error for each subsequent user. In the worst case, an attacker can steal all the funds of the next user.


## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L182
## Tool used

Manual Review

## Recommendation
