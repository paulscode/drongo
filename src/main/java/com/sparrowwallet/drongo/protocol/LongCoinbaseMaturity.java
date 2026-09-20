package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;

/**
 * The temporary rule that holds newly mined coins for far longer than the usual hundred blocks.
 *
 * <p>Mirrors Bitcoin Knots' {@code Consensus::Params::CoinbaseMaturityLong}, read from
 * {@code src/kernel/chainparams.cpp}, {@code src/validation.cpp} and {@code src/wallet/wallet.cpp} at tag
 * {@code v29.4.2.knots20260508rc2}. A wallet that gets this wrong builds a transaction the network will not
 * carry, and it fails at broadcast with nothing to explain it.
 *
 * <p><b>These numbers came from a release candidate, not a shipped release.</b> The deployment was still an
 * open pull request when they were taken (bitcoinknots/bitcoin#419), and they had already moved once before
 * that. Check them against the final release tag before this goes out. Being wrong in the permissive
 * direction builds transactions the network rejects; being wrong in the strict direction hides coins the
 * owner could have spent.
 *
 * <h2>Why this is a depth and not a window</h2>
 *
 * <p>Knots carries three heights, and reading only their names suggests the rule is a window that opens at a
 * start height and closes at a release height, freeing everything caught inside it at once. That is true of
 * <em>consensus</em>, and it is not the rule a wallet lives under.
 *
 * <p>Relay is blunter. {@code MemPoolAccept::PreChecks} passes {@code long_maturity_start_height = 0}, so an
 * upgraded node requires {@code CoinbaseMaturityLong} depth of <em>every</em> coinbase spend it will accept,
 * whatever height that coinbase was mined at and whether or not the deployment window is open. It keeps
 * requiring it after the release height has passed. Knots' own wallet agrees with relay rather than with
 * consensus: {@code CWallet::GetTxBlocksToMaturity} asks {@code chain().coinbaseMaturity()}, which returns
 * {@code CoinbaseMaturityLong} flat.
 *
 * <p>So a coinbase mined well before the fork, buried two hundred blocks deep, is a consensus-valid spend
 * that no upgraded node will relay. Modelling this as a window gets that case wrong, and gets the testnet4
 * grace period wrong in the other direction. A flat depth is both simpler and right, and because it is never
 * weaker than consensus at any height, a coin that clears it cannot be refused by either rule.
 *
 * <p>The visible consequence is that coins mined in the roughly forty five days <em>before</em> the start
 * height, which were spendable, stop being spendable when the network upgrades.
 *
 * <p>Part one of a stated three: the release notes say a full year is being considered, and then withholding
 * rewards entirely from blocks not produced through the miner's own DATUM Gateway. If either lands, the
 * numbers here move and this class is where they move.
 */
public class LongCoinbaseMaturity {
    /**
     * The depth a coinbase must reach before an upgraded node will relay a spend of it.
     *
     * <p>Knots derives this as {@code releaseHeight - startHeight}: 979920 - 973440 on mainnet, and
     * 158111 - 151406 on testnet4. Networks without the deployment keep the hundred blocks they had, which is
     * what makes every call below safe on a chain that never sees this rule.
     */
    public static int maturityDepth(Network network) {
        return switch(network) {
            case MAINNET -> 6480;
            case TESTNET4 -> 6705;
            default -> Transaction.COINBASE_MATURITY_THRESHOLD;
        };
    }

    /** Is the long rule deployed on this network, or is this the ordinary hundred blocks? */
    public static boolean isDeployed(Network network) {
        return maturityDepth(network) > Transaction.COINBASE_MATURITY_THRESHOLD;
    }

    /** The first block height at which a coinbase mined at {@code coinbaseHeight} may be spent. */
    public static int spendableFromHeight(Network network, int coinbaseHeight) {
        return coinbaseHeight + maturityDepth(network);
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
