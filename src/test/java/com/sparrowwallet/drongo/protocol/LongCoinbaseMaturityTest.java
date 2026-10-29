package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The long coinbase maturity schedule, checked against the two rules Knots actually runs, as of
 * {@code v29.4.3.knots20260508}.
 *
 * <p>Relay, which is the one a wallet lives under. {@code MemPoolAccept::PreChecks} passes the long depth, the rolling
 * start height and {@code CoinbaseMaturityBeforeRolling} into {@code Consensus::CheckTxInputs}, which picks a depth for
 * each coin by its mining height:
 *
 * <pre>
 *   required = coinbaseHeight &gt;= rollingStart ? rollingDepth : depthBeforeRolling
 *   valid    = (spendHeight - coinbaseHeight) &gt;= required
 * </pre>
 *
 * <p>Consensus, from the {@code CheckTxInputs} overload {@code ConnectBlock} uses. It runs the first schedule's window
 * while it is open, and then the rolling rule once it is active, and a spend has to pass both:
 *
 * <pre>
 *   if historicalStart &lt;= spendHeight &lt; historicalRelease:
 *       require (spendHeight - coinbaseHeight) &gt;= (coinbaseHeight &gt;= historicalStart ? depthBeforeRolling : 100)
 *   require (spendHeight - coinbaseHeight) &gt;= (spendHeight &gt;= rollingStart &amp;&amp; coinbaseHeight &gt;= rollingStart ? rollingDepth : 100)
 * </pre>
 *
 * <p>Both leave out the return to 100 once RDTS expires in September 2027, which is a time the wallet is not asked
 * about and where it overstates, the safe direction.
 *
 * <p>{@link #matchesKnotsRelayRule()} and {@link #relayIsNeverWeakerThanConsensus()} are the tests that matter: they
 * reimplement both expressions and walk every interesting height against them, so this stays correct for reasons rather
 * than because the cases below were chosen to agree with it.
 */
public class LongCoinbaseMaturityTest {
    private static final int HISTORICAL_START = 973440;
    private static final int HISTORICAL_RELEASE = 979920;
    private static final int BEFORE_ROLLING = HISTORICAL_RELEASE - HISTORICAL_START;
    private static final int ROLLING_START = 979919;
    private static final int ROLLING = 180 * 144;
    private static final int ORDINARY = Transaction.COINBASE_MATURITY_THRESHOLD;

    /** Knots' relay rule, transcribed. */
    private static boolean knotsRelaysSpendAt(int coinbaseHeight, int spendHeight) {
        int required = coinbaseHeight >= ROLLING_START ? ROLLING : BEFORE_ROLLING;
        return spendHeight - coinbaseHeight >= required;
    }

    /** Knots' consensus rule, transcribed. */
    private static boolean knotsAcceptsBlockSpendAt(int coinbaseHeight, int spendHeight) {
        int depth = spendHeight - coinbaseHeight;
        if(spendHeight >= HISTORICAL_START && spendHeight < HISTORICAL_RELEASE) {
            int required = coinbaseHeight >= HISTORICAL_START ? BEFORE_ROLLING : ORDINARY;
            if(depth < required) {
                return false;
            }
        }
        int required = spendHeight >= ROLLING_START && coinbaseHeight >= ROLLING_START ? ROLLING : ORDINARY;
        return depth >= required;
    }

    /** Every coinbase height either side of both schedules, against every spend height either side of them. */
    @Test
    public void matchesKnotsRelayRule() {
        for(int coinbaseHeight : coinbaseHeights()) {
            for(int spendHeight = HISTORICAL_START - 12000; spendHeight <= ROLLING_START + ROLLING + 12000; spendHeight += 7) {
                if(spendHeight <= coinbaseHeight) {
                    continue;
                }
                //The wallet answers with a tip; the spend lands in the block after it
                boolean walletSaysSpendable = LongCoinbaseMaturity.isSpendable(Network.MAINNET, coinbaseHeight, spendHeight - 1);
                assertEquals(knotsRelaysSpendAt(coinbaseHeight, spendHeight), walletSaysSpendable,
                        "coinbase " + coinbaseHeight + " spent at " + spendHeight);
            }
        }
    }

    /**
     * The property that lets the wallet ask one question instead of several: anything relay will carry, block validation
     * will also accept. Without it a depth chosen by mining height could be permissive somewhere, and the simpler model
     * would be unsafe rather than merely strict.
     */
    @Test
    public void relayIsNeverWeakerThanConsensus() {
        for(int coinbaseHeight : coinbaseHeights()) {
            for(int spendHeight = HISTORICAL_START - 12000; spendHeight <= ROLLING_START + ROLLING + 12000; spendHeight += 7) {
                if(spendHeight <= coinbaseHeight) {
                    continue;
                }
                if(knotsRelaysSpendAt(coinbaseHeight, spendHeight)) {
                    assertTrue(knotsAcceptsBlockSpendAt(coinbaseHeight, spendHeight),
                            "relay allows what consensus refuses: coinbase " + coinbaseHeight + " spent at " + spendHeight);
                }
            }
        }
    }

    private static int[] coinbaseHeights() {
        return new int[]{HISTORICAL_START - 12000, HISTORICAL_START - BEFORE_ROLLING - 1, HISTORICAL_START - 101, HISTORICAL_START - 1,
                HISTORICAL_START, HISTORICAL_START + 1, HISTORICAL_START + 3000, ROLLING_START - 101, ROLLING_START - 1, ROLLING_START,
                ROLLING_START + 1, HISTORICAL_RELEASE, HISTORICAL_RELEASE + 1, ROLLING_START + 5000, ROLLING_START + ROLLING};
    }

    /**
     * The line itself. A reward mined at 979918 keeps the first schedule's 6480 even with the tip far past 979919; one mined
     * at 979919 waits 25920, so the first is spendable in block 1005839.
     */
    @Test
    public void eachRewardKeepsTheDepthItWasMinedUnder() {
        assertEquals(BEFORE_ROLLING, LongCoinbaseMaturity.maturityDepth(Network.MAINNET, ROLLING_START - 1));
        assertEquals(ROLLING, LongCoinbaseMaturity.maturityDepth(Network.MAINNET, ROLLING_START));

        assertEquals(1005839, LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, ROLLING_START));
        assertFalse(LongCoinbaseMaturity.isSpendable(Network.MAINNET, ROLLING_START, 1005837), "a block short");
        assertTrue(LongCoinbaseMaturity.isSpendable(Network.MAINNET, ROLLING_START, 1005838), "spendable in block 1005839");

        assertEquals(979918 + 6480, LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, ROLLING_START - 1));
        assertTrue(LongCoinbaseMaturity.isSpendable(Network.MAINNET, ROLLING_START - 1, 979918 + 6479), "6480 deep, tip long past 979919");
        assertFalse(LongCoinbaseMaturity.isSpendable(Network.MAINNET, ROLLING_START - 1, 979918 + 6478));
    }

    /**
     * The retroactive bite, and the reason this is not modelled as a window. A coin mined well before the first schedule,
     * already spendable under the hundred block rule, is held by relay all the same, because relay asks every coinbase
     * mined before the rolling start for 6480.
     */
    @Test
    public void coinsMinedBeforeTheFirstScheduleAreAlsoHeld() {
        int coinbaseHeight = HISTORICAL_START - 200;
        int tipWithTwoHundredConfirmations = coinbaseHeight + 199;

        //Consensus would allow it: mined below the start height, so no long rule covers it
        assertTrue(knotsAcceptsBlockSpendAt(coinbaseHeight, tipWithTwoHundredConfirmations + 1));
        //Relay will not carry it, so neither will the wallet offer it
        assertFalse(LongCoinbaseMaturity.isSpendable(Network.MAINNET, coinbaseHeight, tipWithTwoHundredConfirmations));

        assertEquals(coinbaseHeight + BEFORE_ROLLING, LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, coinbaseHeight));
    }

    /** Each coin matures on its own schedule, which a cliff at a release height would get wrong. */
    @Test
    public void everyCoinbaseMaturesOnItsOwnSchedule() {
        assertEquals(HISTORICAL_RELEASE, LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, HISTORICAL_START));
        assertEquals(HISTORICAL_RELEASE + 3000, LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, HISTORICAL_START + 3000));
        assertEquals(ROLLING_START + 5000 + ROLLING, LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, ROLLING_START + 5000));

        assertFalse(LongCoinbaseMaturity.isSpendable(Network.MAINNET, HISTORICAL_START + 1, HISTORICAL_RELEASE - 1));
        assertTrue(LongCoinbaseMaturity.isSpendable(Network.MAINNET, HISTORICAL_START + 1, HISTORICAL_RELEASE));
    }

    /** The first schedule's release height frees nothing mined under the rolling rule. */
    @Test
    public void theRollingRuleDoesNotEndAtTheFirstSchedulesRelease() {
        int coinbaseHeight = HISTORICAL_RELEASE + 5000;
        assertEquals(coinbaseHeight + ROLLING, LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, coinbaseHeight));
        assertFalse(LongCoinbaseMaturity.isSpendable(Network.MAINNET, coinbaseHeight, coinbaseHeight + BEFORE_ROLLING));
    }

    /** Testnet4 kept its own flat depth, and it is a different one rather than a copy of mainnet's. */
    @Test
    public void testnet4HasItsOwnSchedule() {
        for(int coinbaseHeight : new int[]{100000, 151406, 158111, 200000}) {
            assertEquals(158111 - 151406, LongCoinbaseMaturity.maturityDepth(Network.TESTNET4, coinbaseHeight));
        }
        assertEquals(151406 + 6705, LongCoinbaseMaturity.spendableFromHeight(Network.TESTNET4, 151406));
    }

    /**
     * A network with no deployment must not inherit another's depth. Regtest and signet are where this would otherwise
     * freeze coins that consensus there matures at a hundred blocks.
     */
    @Test
    public void undeployedNetworksKeepOrdinaryMaturity() {
        for(Network network : new Network[]{Network.REGTEST, Network.SIGNET, Network.TESTNET}) {
            assertFalse(LongCoinbaseMaturity.isDeployed(network), network.toString());
            for(int coinbaseHeight : new int[]{973440, ROLLING_START, 2_000_000}) {
                assertEquals(ORDINARY, LongCoinbaseMaturity.maturityDepth(network, coinbaseHeight), network.toString());
            }
            assertEquals(973540, LongCoinbaseMaturity.spendableFromHeight(network, 973440), network + " must not take another network's depth");
            assertTrue(LongCoinbaseMaturity.isSpendable(network, 973440, 973539), network.toString());
            assertFalse(LongCoinbaseMaturity.isSpendable(network, 973440, 973538), network.toString());
        }
        assertTrue(LongCoinbaseMaturity.isDeployed(Network.MAINNET));
        assertTrue(LongCoinbaseMaturity.isDeployed(Network.TESTNET4));
    }

    /** What the interface needs to tell the two cases apart, so it can say which one is holding a coin. */
    @Test
    public void theLongRuleIsDistinguishableFromOrdinaryImmaturity() {
        //Held by the long rule, under each schedule
        assertTrue(LongCoinbaseMaturity.isFrozenByLongRule(Network.MAINNET, HISTORICAL_START, HISTORICAL_START + 10));
        assertTrue(LongCoinbaseMaturity.isFrozenByLongRule(Network.MAINNET, ROLLING_START, ROLLING_START + BEFORE_ROLLING));
        //Spendable, so held by nothing
        assertFalse(LongCoinbaseMaturity.isFrozenByLongRule(Network.MAINNET, HISTORICAL_START, HISTORICAL_START + BEFORE_ROLLING));
        assertFalse(LongCoinbaseMaturity.isFrozenByLongRule(Network.MAINNET, ROLLING_START, ROLLING_START + ROLLING));
        //On a network without the deployment, ordinary immaturity is never attributed to the long rule
        assertFalse(LongCoinbaseMaturity.isFrozenByLongRule(Network.REGTEST, 500, 510));
    }
}
