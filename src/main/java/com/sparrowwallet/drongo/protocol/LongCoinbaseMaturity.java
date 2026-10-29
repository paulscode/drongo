package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;

/**
 * The temporary rule that holds newly mined coins for far longer than the usual hundred blocks.
 *
 * <p>Mirrors Bitcoin Knots' coinbase maturity schedule, read from {@code src/kernel/chainparams.cpp},
 * {@code src/consensus/params.h}, {@code src/consensus/tx_verify.cpp} and {@code src/validation.cpp} at the released tag
 * {@code v29.4.3.knots20260508}. A wallet that gets this wrong builds a transaction the network will not carry, and it
 * fails at broadcast with nothing to explain it. Being wrong in the permissive direction builds transactions the network
 * rejects; being wrong in the strict direction hides coins the owner could have spent.
 *
 * <h2>The schedule</h2>
 *
 * <p>The figure has moved twice. The first schedule held coinbases for 6480 blocks, the length of a window from 973440
 * to 979920. 29.4.3 replaced it with a rolling rule from {@code CoinbaseMaturityLongStartHeight} = 979919: a reward mined
 * there or later waits {@code CoinbaseMaturityLong} = 180 &times; 144 = 25920 blocks, about six months, until RDTS
 * expires. Rewards mined before 979919 keep the 6480 of the schedule they were mined under
 * ({@code CoinbaseMaturityBeforeRolling}). Testnet4 kept its original flat 6705.
 *
 * <h2>Why this is the relay rule and not the consensus one</h2>
 *
 * <p>Consensus and relay differ, and a wallet lives under relay, because a transaction nothing will carry is a
 * transaction that fails. {@code MemPoolAccept::PreChecks} calls {@code CheckTxInputs} with the long depth, the start
 * height, the RDTS end height and {@code CoinbaseMaturityBeforeRolling}, and that picks a depth for each coin by its
 * mining height: 25920 from 979919, 6480 below it, whatever the coin's age, and whether or not any window is open. So
 * every coinbase mined before 979919, even one mined long before the first schedule, is held to 6480 by relay, which is
 * stricter than consensus for the oldest of them. A depth chosen by mining height is never weaker than consensus at any
 * height, so a coin that clears it cannot be refused by either rule.
 *
 * <h2>What this does not know</h2>
 *
 * <p>A reward mined in a block whose parent's median time past is at or after {@code RdtsExpiryTime} (1 September 2027)
 * needs only the usual 100 again ({@code CoinbaseMaturityPolicy}). That boundary is a time, and this class is asked by
 * height, so it holds those rewards to 25920 too. That overstates, which is the safe direction: such a coin is held, never
 * offered early. It wants the mining block's parent median time past from the header store before that date.
 */
public class LongCoinbaseMaturity {
    /** The first coinbase height held to the rolling depth on mainnet, {@code CoinbaseMaturityLongStartHeight}. */
    public static final int MAINNET_ROLLING_START_HEIGHT = 979919;

    /** {@code CoinbaseMaturityLong} on mainnet from 29.4.3: 180 days of blocks. */
    public static final int MAINNET_ROLLING_DEPTH = 180 * 144;

    /** {@code CoinbaseMaturityBeforeRolling} on mainnet: the 6480 of the first schedule, 979920 - 973440. */
    public static final int MAINNET_DEPTH_BEFORE_ROLLING = 979920 - 973440;

    /**
     * The depth a coinbase mined at {@code coinbaseHeight} must reach before an upgraded node will relay a spend of it.
     *
     * <p>Networks without the deployment keep the hundred blocks they had, which is what makes every call below safe on a
     * chain that never sees this rule. Testnet4 derives its depth as 158111 - 151406.
     */
    public static int maturityDepth(Network network, int coinbaseHeight) {
        return switch(network) {
            case MAINNET -> coinbaseHeight >= MAINNET_ROLLING_START_HEIGHT ? MAINNET_ROLLING_DEPTH : MAINNET_DEPTH_BEFORE_ROLLING;
            case TESTNET4 -> 6705;
            default -> Transaction.COINBASE_MATURITY_THRESHOLD;
        };
    }

    /** Is the long rule deployed on this network, or is this the ordinary hundred blocks? */
    public static boolean isDeployed(Network network) {
        return maturityDepth(network, Integer.MAX_VALUE) > Transaction.COINBASE_MATURITY_THRESHOLD;
    }

    /** The first block height at which a coinbase mined at {@code coinbaseHeight} may be spent. */
    public static int spendableFromHeight(Network network, int coinbaseHeight) {
        return coinbaseHeight + maturityDepth(network, coinbaseHeight);
    }

    /**
     * Can a coinbase mined at {@code coinbaseHeight} be spent in a transaction built against this tip?
     *
     * <p>Asked of {@code currentBlockHeight + 1}, because the earliest block that could confirm the spend is
     * the one after the tip, and that is the height the rule is evaluated at. This matches the depth a node
     * requires to take the spend into its mempool; Knots' own wallet waits one block longer than that.
     */
    public static boolean isSpendable(Network network, int coinbaseHeight, int currentBlockHeight) {
        return currentBlockHeight + 1 >= spendableFromHeight(network, coinbaseHeight);
    }

    /** Is this coin held by the long rule rather than by ordinary maturity? Used to say so in the interface. */
    public static boolean isFrozenByLongRule(Network network, int coinbaseHeight, int currentBlockHeight) {
        return isDeployed(network) && !isSpendable(network, coinbaseHeight, currentBlockHeight);
    }
}
