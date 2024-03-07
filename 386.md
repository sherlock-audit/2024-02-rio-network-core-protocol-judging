Sunny Licorice Pheasant

medium

# The current idea of ​​creating reETH and accepting several different assets in it exposes RIO users to losses


## Summary
After the release of LRT, which will include the ability to deposit native eth and wrapped staking tokens like cbETH or wstETH, Rio users will be exposed to additional economic risks that may lead to loss of capital. In case of a predictable price drop (e.g. caused by a slashing event in an external liquid staking provider), external users can deposit their funds into Rio before the price drop. They will receive the LRT (corresponding to the value before the price drop, as priceFeed displays the changed price only when it actually happens) and withdraw them once the price drops, sharing their loss with Rio users.

## Vulnerability Detail
Rio creates a network for issuing Liquid Restaking Tokens (LRTs) that have an underlying asset mix. The idea is to have multiple LRTs like: reUSD, reETH, reXXX, where for reUSD underlying asset mix will include e.g. USDC, DAI, USDT and for reETH underlying asset mix will include native ETH and e.g. cbETH (as it is used in tests), or wstETH.

Users depositing their funds into Rio are encouraged by the rewards of staking and re-staking through EigenLayer, but they also bear the risk of penalties and slashing of their deposited funds. However, in case of reETH, the 3rd party users who are not associated in any way with Rio ecosystem can take advantage of such LRT and make Rio users bear their losses.

Keeping in mind these things:
- value of assets like wstETH, cbETH generally increase over time,
- there are price drops for assets like wstETH, cbETH, but most of the time these are temporary,
- things that can cause price drops for assets like wstETH, cbETH include: slashing, lower demand / lack of trust for particular asset, withdrawal caused by people who accumulated big rewards over time,
- lower demand / lack of trust is unpredictable, however, big withdrawals can be monitored and slashing is a process spread over time, so there is a time when you know the value of asset will drop,
- liquid staking providers like LIDO etc., protects themselves from "withdrawal before slashing" by making withdrawal process long enough so that slashing can affect the users who request to withdraw,
- user within Rio ecosystem can deposit asset1 to get LRT, and then request to withdraw asset2.

Consider the following scenario (**values used for ease of calculation and to illustrate the attack**, real values will be presented later in this description):

Rio issues LRT (reETH) that supports two assets (cbETH and native ETH).

1. 200 ETH is deposited inside RIO by users and 200 reETH were minted.

2. The attacker (cbETH staker) has 100 cbETH (price is e.g. 1 cbETH = 2 ETH, their cbETH is worth 200 ETH)

The attacker knows through monitoring slashing events and big withdrawalas that price will drop soon.

3. The attacker deposit their 100 cbETH to Rio to get 200 reETH (as current price is still 1 cbETH = 2 ETH)

Total value locked on Rio will increase from 200 ETH to 400 ETH (200 eth and 100 cbETH)

Price of cbETH now drops by 50% (so now 1 cbETH = 1 ETH)

Total value locked on Rio will decrease from 400 ETH to 300 ETH (as 200cbETH is now worth only 100 ETH).

4. The attacker decides to request withdraw all of their cbETH by burning only 150 reETH and they also request to withdraw 50 ETH by burning another 100 reETH.

5. Attacker gets 200 cbETH back (current price is 100 ETH) and additional 50 ETH.

6. Attacker buys additional cbETH for their additional 50 ETH, so know they have 250 cbETH (from another source)

Now price recover, so its again 1 cbETH = 2 ETH.

Attacker now have 250 cbETH worth 500 ETH, and Rio users have 150 ETH (lost 50 ETH, as attacker delegeted their risk to rio users).


However, the price will not drop by 50%. The real numbers could be up to 10%.

Looking at 2 examples of assets that are considered to be added to reETH (cbETH and wstETH) we can observe the following:

1. cbETH (https://coinmarketcap.com/currencies/coinbase-wrapped-staked-eth/)

* there are price drops
* based on data from last 365 days the biggest percentage drop in price occurred on March 11, 2023, with a drop of approximately 8.25% (https://coinmarketcap.com/currencies/lido-finance-wsteth/historical-data/) (https://coinmarketcap.com/currencies/coinbase-wrapped-staked-eth/historical-data/)

2. wstETH (https://coinmarketcap.com/currencies/lido-finance-wsteth/)

* there are price drops
* based on data from last 365 days the biggest percentage drop in price occurred also on March 11, 2023, with a drop of approximately 9.28% (https://coinmarketcap.com/currencies/lido-finance-wsteth/historical-data/)


## Impact
MEDIUM - as it require conditions that needs to be satisfied (observed in advance price drop) and funds which cannot be possed in flash-loan to increase the impact of the vulnerability.

## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L99
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L101C22-L101C56

## Tool used

Manual Review

## Recommendation
The problem is not easy to fix and several security mechanisms can be used:
- users could be allowed to withdraw only the type of assets they deposit
- you can monitor price drop events and temporarily freeze deposits
- you can set a minimum period for the user between his deposit and withdrawal so that he cannot take advantage of price fluctuations
- single LRTs can be issued for assets that are subject to such events (price drops predicted some time in advance)
