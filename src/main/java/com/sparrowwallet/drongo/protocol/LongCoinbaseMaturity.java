package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;

/**
 * The temporary rule that freezes newly mined coins for far longer than the usual hundred blocks.
 *
 * <p>Mirrors Bitcoin Knots' {@code Consensus::Params::CoinbaseMaturityLong*}, read from
 * {@code src/kernel/chainparams.cpp} and {@code src/consensus/tx_verify.cpp} at tag
 * {@code v29.4.2.knots20260508rc2}. This is consensus rather than preference: a wallet that gets it wrong
 * spends a coinbase the network will not accept, and the transaction fails with nothing to explain it.
 *
 * <p><b>These heights came from a release candidate, not a shipped release.</b> The deployment was still an
 * open pull request when they were taken (bitcoinknots/bitcoin#419), and they had already moved once before
 * that: an earlier revision read 971712 / 972288 / 978768. Check them against the final release tag before
 * this goes out. Being wrong in the permissive direction builds transactions the network rejects; being
 * wrong in the strict direction hides coins the owner could have spent.
 *
 * <p>The rule is a window on the <em>spending</em> block rather than a rolling maturity, which is what makes
 * it behave unlike the hundred-block rule it sits beside. Knots gates it as
 * {@code CoinbaseMaturityLongActiveAt(spendHeight) ? CoinbaseMaturityLongStartHeight : INT_MAX}, and inside
 * the window requires {@code spendHeight - coinbaseHeight >= releaseHeight - startHeight}. A coinbase mined
 * at or after the start height therefore cannot reach the required depth until the window has already
 * closed, so every one of them unlocks together at the release height rather than each maturing on its own
 * schedule. Coins mined before the start height are never affected.
 *
 * <p>Part one of a stated three: the release notes say a full year is being considered, and then withholding
 * rewards entirely from blocks not produced through the miner's own DATUM Gateway. If either lands, the
 * heights here move and this class is where they move.
 */
public class LongCoinbaseMaturity {
    /** Not deployed on this network. */
    private static final int NOT_DEPLOYED = Integer.MAX_VALUE;

    /**
     * The first coinbase height the long rule applies to, or {@link #NOT_DEPLOYED}.
     *
     * <p>Knots carries a separate enforcement height, which is where nodes begin rejecting. On mainnet the two
     * are the same block, and a wallet only ever asks whether a coin it holds can be spent, so the enforcement
     * height is not modelled: a coin below the start height is unaffected whichever side of enforcement the
     * chain is on.
     */
    public static int startHeight(Network network) {
        return switch(network) {
            case MAINNET -> 973440;
            case TESTNET4 -> 151406;
            default -> NOT_DEPLOYED;
        };
    }

    /** The height at which the window closes and ordinary maturity resumes, or {@link #NOT_DEPLOYED}. */
    public static int releaseHeight(Network network) {
        return switch(network) {
            case MAINNET -> 979920;
            case TESTNET4 -> 158111;
            default -> NOT_DEPLOYED;
        };
    }

    /**
     * The first block height at which a coinbase mined at {@code coinbaseHeight} may be spent.
     *
     * <p>Both halves are needed, not just the release height. A coinbase mined near the end of the window
     * still has to clear the ordinary hundred blocks afterwards, so the answer is the later of the two.
     */
    public static int spendableFromHeight(Network network, int coinbaseHeight) {
        int ordinary = coinbaseHeight + Transaction.COINBASE_MATURITY_THRESHOLD;
        int start = startHeight(network);
        if(start == NOT_DEPLOYED || coinbaseHeight < start) {
            return ordinary;
        }

        return Math.max(releaseHeight(network), ordinary);
    }

    /**
     * Can a coinbase mined at {@code coinbaseHeight} be spent in a transaction built against this tip?
     *
     * <p>Asked of {@code currentBlockHeight + 1}, because the earliest block that could confirm the spend is
     * the one after the tip, and that is the height the rule is evaluated at.
     */
    public static boolean isSpendable(Network network, int coinbaseHeight, int currentBlockHeight) {
        return currentBlockHeight + 1 >= spendableFromHeight(network, coinbaseHeight);
    }

    /** Is this coin held by the long rule rather than by ordinary maturity? Used to say so in the interface. */
    public static boolean isFrozenByLongRule(Network network, int coinbaseHeight, int currentBlockHeight) {
        return !isSpendable(network, coinbaseHeight, currentBlockHeight)
                && spendableFromHeight(network, coinbaseHeight) > coinbaseHeight + Transaction.COINBASE_MATURITY_THRESHOLD;
    }
}
