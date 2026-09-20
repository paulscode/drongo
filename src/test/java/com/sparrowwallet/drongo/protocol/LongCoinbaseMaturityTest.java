package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The temporary long coinbase maturity window, checked against the rule as Knots writes it.
 *
 * <p>Knots evaluates, for a spend landing in block {@code spendHeight}:
 *
 * <pre>
 *   start    = CoinbaseMaturityLongActiveAt(spendHeight) ? CoinbaseMaturityLongStartHeight : INT_MAX
 *   required = (coinbaseHeight &gt;= start) ? (releaseHeight - startHeight) : 100
 *   valid    = (spendHeight - coinbaseHeight) &gt;= required
 * </pre>
 *
 * <p>{@link #matchesKnotsAcrossTheWholeWindow()} is the test that matters: it reimplements that expression
 * and walks every interesting height against it, so this stays correct for reasons rather than because the
 * cases below were chosen to agree with it.
 */
public class LongCoinbaseMaturityTest {
    private static final int START = 973440;
    private static final int RELEASE = 979920;
    private static final int ORDINARY = Transaction.COINBASE_MATURITY_THRESHOLD;

    /** Knots' rule, transcribed, for the wallet's answer to be checked against. */
    private static boolean knotsAllowsSpendAt(int coinbaseHeight, int spendHeight) {
        boolean windowActive = spendHeight >= START && spendHeight < RELEASE;
        int start = windowActive ? START : Integer.MAX_VALUE;
        int required = coinbaseHeight >= start ? (RELEASE - START) : ORDINARY;
        return spendHeight - coinbaseHeight >= required;
    }

    /**
     * The whole point of the class. Every coinbase height either side of the window, against every spend
     * height either side of it, must agree with the consensus rule.
     */
    @Test
    public void matchesKnotsAcrossTheWholeWindow() {
        int[] coinbaseHeights = {START - 6480, START - 101, START - 100, START - 1, START, START + 1,
                START + 3000, RELEASE - 101, RELEASE - 100, RELEASE - 1, RELEASE, RELEASE + 1, RELEASE + 5000};

        for(int coinbaseHeight : coinbaseHeights) {
            for(int spendHeight = START - 200; spendHeight <= RELEASE + 5200; spendHeight += 7) {
                if(spendHeight <= coinbaseHeight) {
                    continue;
                }
                //The wallet answers with a tip; the spend lands in the block after it
                boolean walletSaysSpendable =
                        LongCoinbaseMaturity.isSpendable(Network.MAINNET, coinbaseHeight, spendHeight - 1);
                assertEquals(knotsAllowsSpendAt(coinbaseHeight, spendHeight), walletSaysSpendable,
                        "coinbase " + coinbaseHeight + " spent at " + spendHeight);
            }
        }
    }

    /** Coins mined before the window keep the rule they have always had, to the block. */
    @Test
    public void coinsMinedBeforeTheWindowAreUnaffected() {
        int coinbaseHeight = START - 1;
        assertEquals(coinbaseHeight + ORDINARY,
                LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, coinbaseHeight));

        //Spendable once a hundred blocks are buried, exactly as before, even though that lands inside the window
        assertFalse(LongCoinbaseMaturity.isSpendable(Network.MAINNET, coinbaseHeight, coinbaseHeight + ORDINARY - 2));
        assertTrue(LongCoinbaseMaturity.isSpendable(Network.MAINNET, coinbaseHeight, coinbaseHeight + ORDINARY - 1));
    }

    /**
     * The shape that makes this rule unlike ordinary maturity: everything mined inside the window unlocks at
     * one height rather than each on its own schedule.
     */
    @Test
    public void theWindowUnlocksAsOneCliff() {
        assertEquals(RELEASE, LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, START));
        assertEquals(RELEASE, LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, START + 1));
        assertEquals(RELEASE, LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, RELEASE - ORDINARY - 1));

        //One block before the cliff, nothing mined in the window can move
        assertFalse(LongCoinbaseMaturity.isSpendable(Network.MAINNET, START, RELEASE - 2));
        assertTrue(LongCoinbaseMaturity.isSpendable(Network.MAINNET, START, RELEASE - 1));
    }

    /**
     * A coin mined near the end of the window still owes the ordinary hundred blocks afterwards. Taking the
     * release height alone would call it spendable before consensus does.
     */
    @Test
    public void aCoinMinedLateInTheWindowStillOwesTheOrdinaryHundred() {
        int coinbaseHeight = RELEASE - 10;
        assertEquals(coinbaseHeight + ORDINARY,
                LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, coinbaseHeight));
        assertTrue(coinbaseHeight + ORDINARY > RELEASE);

        assertFalse(LongCoinbaseMaturity.isSpendable(Network.MAINNET, coinbaseHeight, RELEASE));
        assertTrue(LongCoinbaseMaturity.isSpendable(Network.MAINNET, coinbaseHeight, coinbaseHeight + ORDINARY - 1));
    }

    /** Coins mined after the window has closed are ordinary again. */
    @Test
    public void coinsMinedAfterTheWindowAreOrdinaryAgain() {
        int coinbaseHeight = RELEASE + 5000;
        assertEquals(coinbaseHeight + ORDINARY,
                LongCoinbaseMaturity.spendableFromHeight(Network.MAINNET, coinbaseHeight));
    }

    /** Testnet4 has its own schedule, and it is a different one rather than a copy of mainnet's. */
    @Test
    public void testnet4HasItsOwnSchedule() {
        assertEquals(151406, LongCoinbaseMaturity.startHeight(Network.TESTNET4));
        assertEquals(158111, LongCoinbaseMaturity.releaseHeight(Network.TESTNET4));
        assertEquals(158111, LongCoinbaseMaturity.spendableFromHeight(Network.TESTNET4, 151406));
        assertNotEquals(LongCoinbaseMaturity.startHeight(Network.MAINNET),
                LongCoinbaseMaturity.startHeight(Network.TESTNET4));
    }

    /**
     * A network with no deployment must not inherit another's heights. Regtest and signet are where this
     * would otherwise freeze coins that consensus there matures at a hundred blocks.
     */
    @Test
    public void undeployedNetworksKeepOrdinaryMaturity() {
        for(Network network : new Network[]{Network.REGTEST, Network.SIGNET, Network.TESTNET}) {
            assertEquals(973540, LongCoinbaseMaturity.spendableFromHeight(network, 973440),
                    network + " must not take another network's window");
            assertTrue(LongCoinbaseMaturity.isSpendable(network, 973440, 973539), network.toString());
            assertFalse(LongCoinbaseMaturity.isSpendable(network, 973440, 973538), network.toString());
        }
    }

    /** What the interface needs to tell the two cases apart, so it can say which one is holding a coin. */
    @Test
    public void theLongRuleIsDistinguishableFromOrdinaryImmaturity() {
        //Held by the window
        assertTrue(LongCoinbaseMaturity.isFrozenByLongRule(Network.MAINNET, START, START + 10));
        //Held by the ordinary hundred, mined before the window
        assertFalse(LongCoinbaseMaturity.isFrozenByLongRule(Network.MAINNET, START - 200, START - 150));
        //Spendable, so held by neither
        assertFalse(LongCoinbaseMaturity.isFrozenByLongRule(Network.MAINNET, START, RELEASE));
    }
}
