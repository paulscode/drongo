package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The temporary long coinbase maturity rule, checked against the two rules Knots actually runs.
 *
 * <p>Relay, which is the one a wallet lives under, from {@code MemPoolAccept::PreChecks} passing
 * {@code long_maturity_start_height = 0} into {@code Consensus::CheckTxInputs}:
 *
 * <pre>
 *   valid = (spendHeight - coinbaseHeight) &gt;= CoinbaseMaturityLong
 * </pre>
 *
 * <p>Consensus, from {@code Chainstate::ConnectBlock} passing the gated start height instead:
 *
 * <pre>
 *   active   = spendHeight &gt;= enforceHeight &amp;&amp; spendHeight &lt; releaseHeight
 *   required = (active &amp;&amp; coinbaseHeight &gt;= startHeight) ? CoinbaseMaturityLong : 100
 *   valid    = (spendHeight - coinbaseHeight) &gt;= required
 * </pre>
 *
 * <p>{@link #matchesKnotsRelayRule()} and {@link #relayIsNeverWeakerThanConsensus()} are the tests that
 * matter: they reimplement both expressions and walk every interesting height against them, so this stays
 * correct for reasons rather than because the cases below were chosen to agree with it.
 */
public class LongCoinbaseMaturityTest {
    private static final int START = 973440;
    private static final int ENFORCE = 973440;
    private static final int RELEASE = 979920;
    private static final int LONG = RELEASE - START;
    private static final int ORDINARY = Transaction.COINBASE_MATURITY_THRESHOLD;

    /** Knots' relay rule, transcribed. */
    private static boolean knotsRelaysSpendAt(int coinbaseHeight, int spendHeight) {
        return spendHeight - coinbaseHeight >= LONG;
    }

    /** Knots' consensus rule, transcribed. */
    private static boolean knotsAcceptsBlockSpendAt(int coinbaseHeight, int spendHeight) {
        boolean active = spendHeight >= ENFORCE && spendHeight < RELEASE;
        int required = active && coinbaseHeight >= START ? LONG : ORDINARY;
        return spendHeight - coinbaseHeight >= required;
    }

    /** Every coinbase height either side of the deployment, against every spend height either side of it. */
    @Test
    public void matchesKnotsRelayRule() {
        for(int coinbaseHeight : coinbaseHeights()) {
            for(int spendHeight = START - 12000; spendHeight <= RELEASE + 12000; spendHeight += 7) {
                if(spendHeight <= coinbaseHeight) {
                    continue;
                }
                //The wallet answers with a tip; the spend lands in the block after it
                boolean walletSaysSpendable =
                        LongCoinbaseMaturity.isSpendable(Network.MAINNET, coinbaseHeight, spendHeight - 1);
                assertEquals(knotsRelaysSpendAt(coinbaseHeight, spendHeight), walletSaysSpendable,
                        "coinbase " + coinbaseHeight + " spent at " + spendHeight);
            }
        }
    }

    /**
     * The property that lets the wallet ask one question instead of three: anything relay will carry, block
     * validation will also accept. Without it a flat depth could be permissive somewhere and the simpler
     * model would be unsafe rather than merely strict.
     */
    @Test
    public void relayIsNeverWeakerThanConsensus() {
        for(int coinbaseHeight : coinbaseHeights()) {
            for(int spendHeight = START - 12000; spendHeight <= RELEASE + 12000; spendHeight += 7) {
                if(spendHeight <= coinbaseHeight) {
                    continue;
                }
                if(knotsRelaysSpendAt(coinbaseHeight, spendHeight)) {
                    assertTrue(knotsAcceptsBlockSpendAt(coinbaseHeight, spendHeight),
                            "relay allows what consensus refuses: coinbase " + coinbaseHeight
                                    + " spent at " + spendHeight);
                }
            }
        }
    }

    private static int[] coinbaseHeights() {
        return new int[]{START - 12000, START - LONG - 1, START - LONG, START - 101, START - 100, START - 1,
                START, START + 1, START + 3000, RELEASE - 101, RELEASE - 1, RELEASE, RELEASE + 1,
                RELEASE + 5000};
    }

    /**
     * The retroactive bite, and the reason this is not modelled as a window. A coin mined well before the
     * deployment, already spendable under the hundred block rule, stops being spendable when the network
     * upgrades, because relay does not care when it was mined.
     */
    @Test
    public void coinsMinedBeforeTheDeploymentAreAlsoHeld() {
        int coinbaseHeight = START - 200;
        int tipWithTwoHundredConfirmations = coinbaseHeight + 199;

        //Consensus would allow it: mined below the start height, so the long rule never covers it
        assertTrue(knotsAcceptsBlockSpendAt(coinbaseHeight, tipWithTwoHundredConfirmations + 1));
        //Relay will not carry it, so neither will the wallet offer it
        assertFalse(LongCoinbaseMaturity.isSpendable(Network.MAINNET, coinbaseHeight,
                tipWithTwoHundredConfirmations));

        assertEquals(coinbaseHeight + LONG,
                LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, coinbaseHeight));
    }

    /** Each coin matures on its own schedule, which a cliff at the release height would get wrong. */
    @Test
    public void everyCoinbaseMaturesOnItsOwnSchedule() {
        assertEquals(RELEASE, LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, START));
        assertEquals(RELEASE + 1, LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, START + 1));
        assertEquals(RELEASE + 3000, LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, START + 3000));

        assertFalse(LongCoinbaseMaturity.isSpendable(Network.MAINNET, START + 1, RELEASE - 1));
        assertTrue(LongCoinbaseMaturity.isSpendable(Network.MAINNET, START + 1, RELEASE));
    }

    /** The rule does not expire: a coin mined after the release height waits just as long. */
    @Test
    public void theRuleDoesNotExpireAtTheReleaseHeight() {
        int coinbaseHeight = RELEASE + 5000;
        assertEquals(coinbaseHeight + LONG,
                LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, coinbaseHeight));
        assertFalse(LongCoinbaseMaturity.isSpendable(Network.MAINNET, coinbaseHeight,
                coinbaseHeight + ORDINARY));
    }

    /** Testnet4 has its own depth, and it is a different one rather than a copy of mainnet's. */
    @Test
    public void testnet4HasItsOwnSchedule() {
        assertEquals(158111 - 151406, LongCoinbaseMaturity.maturityDepth(Network.TESTNET4));
        assertNotEquals(LongCoinbaseMaturity.maturityDepth(Network.MAINNET),
                LongCoinbaseMaturity.maturityDepth(Network.TESTNET4));
        assertEquals(151406 + 6705, LongCoinbaseMaturity.spendableFromHeight(Network.TESTNET4, 151406));
    }

    /**
     * A network with no deployment must not inherit another's depth. Regtest and signet are where this would
     * otherwise freeze coins that consensus there matures at a hundred blocks.
     */
    @Test
    public void undeployedNetworksKeepOrdinaryMaturity() {
        for(Network network : new Network[]{Network.REGTEST, Network.SIGNET, Network.TESTNET}) {
            assertFalse(LongCoinbaseMaturity.isDeployed(network), network.toString());
            assertEquals(ORDINARY, LongCoinbaseMaturity.maturityDepth(network), network.toString());
            assertEquals(973540, LongCoinbaseMaturity.spendableFromHeight(network, 973440),
                    network + " must not take another network's depth");
            assertTrue(LongCoinbaseMaturity.isSpendable(network, 973440, 973539), network.toString());
            assertFalse(LongCoinbaseMaturity.isSpendable(network, 973440, 973538), network.toString());
        }
    }

    /** What the interface needs to tell the two cases apart, so it can say which one is holding a coin. */
    @Test
    public void theLongRuleIsDistinguishableFromOrdinaryImmaturity() {
        //Held by the long rule
        assertTrue(LongCoinbaseMaturity.isFrozenByLongRule(Network.MAINNET, START, START + 10));
        //Spendable, so held by nothing
        assertFalse(LongCoinbaseMaturity.isFrozenByLongRule(Network.MAINNET, START, START + LONG));
        //On a network without the deployment, ordinary immaturity is never attributed to the long rule
        assertFalse(LongCoinbaseMaturity.isFrozenByLongRule(Network.REGTEST, 500, 510));
    }
}
