package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The filter that decides whether a coin may be offered for spending.
 *
 * <p>This is the change that matters: it is what stops the wallet building a transaction the network will
 * reject as a premature coinbase spend. {@link com.sparrowwallet.drongo.protocol.LongCoinbaseMaturityTest}
 * covers the arithmetic; this covers the filter around it, including the cases that are not arithmetic at
 * all, which is where it went wrong first.
 */
public class CoinbaseTxoFilterTest {
    private static final int START = 973440;
    private static final int RELEASE = 979920;
    private static final int LONG = RELEASE - START;
    private static final int ORDINARY = Transaction.COINBASE_MATURITY_THRESHOLD;

    @AfterEach
    public void tearDown() {
        Network.set(null);
    }

    private static Transaction coinbaseTransaction() {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new com.sparrowwallet.drongo.protocol.Script(new byte[0]));
        return transaction;
    }

    private static Transaction ordinaryTransaction() {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.wrap(Utils.hexToBytes("bb".repeat(32))), 0,
                new com.sparrowwallet.drongo.protocol.Script(new byte[0]));
        return transaction;
    }

    /** A wallet holding one transaction at the given height, with the chain at the given tip. */
    private static Wallet walletHolding(Transaction transaction, int height, Integer storedBlockHeight) {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_HD);
        wallet.setScriptType(ScriptType.P2WPKH);
        wallet.setStoredBlockHeight(storedBlockHeight);
        wallet.updateTransactions(Map.of(transaction.getTxId(),
                new BlockTransaction(transaction.getTxId(), height, null, 0L, transaction)));
        return wallet;
    }

    private static BlockTransactionHashIndex txo(Transaction transaction, int height) {
        return new BlockTransactionHashIndex(transaction.getTxId(), height, null, 0L, 0, 100000L);
    }

    private static boolean eligible(Transaction transaction, int height, Integer tip) {
        Wallet wallet = walletHolding(transaction, height, tip);
        return new CoinbaseTxoFilter(wallet).isEligible(txo(transaction, height));
    }

    /** Sanity: the transaction shapes are what the filter keys on. */
    @Test
    public void theTestTransactionsAreWhatTheyClaim() {
        assertTrue(coinbaseTransaction().isCoinBase());
        assertFalse(ordinaryTransaction().isCoinBase());
    }

    /** An ordinary coin is never held back, whatever height it is at. */
    @Test
    public void ordinaryCoinsAreAlwaysEligible() {
        Network.set(Network.MAINNET);
        assertTrue(eligible(ordinaryTransaction(), START, START));
        assertTrue(eligible(ordinaryTransaction(), START + 1, START + 1));
    }

    /**
     * A coin mined before the deployment is held too. The hundred block rule would have released it long
     * ago, but relay will not carry the spend, so offering it would only produce a send that fails.
     */
    @Test
    public void coinsMinedBeforeTheDeploymentAreAlsoHeld() {
        Network.set(Network.MAINNET);
        int height = START - 5000;
        assertFalse(eligible(coinbaseTransaction(), height, height + ORDINARY));
        assertFalse(eligible(coinbaseTransaction(), height, height + LONG - 2));
        assertTrue(eligible(coinbaseTransaction(), height, height + LONG - 1));
    }

    /** Each coin waits the long depth from its own block, rather than to a shared unlock height. */
    @Test
    public void eachCoinWaitsTheLongDepthFromItsOwnBlock() {
        Network.set(Network.MAINNET);
        assertFalse(eligible(coinbaseTransaction(), START, START + ORDINARY));
        assertFalse(eligible(coinbaseTransaction(), START, RELEASE - 2));
        assertTrue(eligible(coinbaseTransaction(), START, RELEASE - 1));

        //One block later mined is one block later spendable, which a cliff would get wrong
        assertFalse(eligible(coinbaseTransaction(), START + 1, RELEASE - 1));
        assertTrue(eligible(coinbaseTransaction(), START + 1, RELEASE));
    }

    /**
     * The regression this nearly shipped with. The old filter asked for confirmations, and
     * getConfirmations() returns zero for an entry with no height, so an unconfirmed coinbase was refused
     * for free. Asking by height does not: a height of zero reads as a coin mined at the genesis block and
     * matured long ago.
     */
    @Test
    public void aCoinbaseWithNoHeightIsNotEligible() {
        Network.set(Network.MAINNET);
        assertFalse(eligible(coinbaseTransaction(), 0, START));
        assertFalse(eligible(coinbaseTransaction(), -1, START));
    }

    /**
     * A known coinbase whose maturity cannot be evaluated is refused. This is the fail-open the filter used
     * to have: every guard sat inside the condition, so an unknown tip fell through to spendable. The blast
     * radius of refusing is coinbases only, and the alternative is offering a coin the network will not
     * accept a spend of.
     */
    @Test
    public void aKnownCoinbaseWithNoTipIsNotEligible() {
        Network.set(Network.MAINNET);
        assertFalse(eligible(coinbaseTransaction(), START, null));
    }

    /**
     * An ordinary coin with no tip is still eligible. The tightening above must not reach beyond coinbases,
     * or a wallet goes unspendable whenever the tip is briefly unknown.
     */
    @Test
    public void anOrdinaryCoinWithNoTipIsStillEligible() {
        Network.set(Network.MAINNET);
        assertTrue(eligible(ordinaryTransaction(), START, null));
    }

    /**
     * A txo whose transaction the wallet does not hold stays eligible, because we cannot tell whether it is
     * a coinbase and failing closed would make an ordinary wallet unspendable over one missing transaction.
     * Recorded rather than endorsed: it is safe only because ElectrumServer throws rather than admitting a
     * txo it could not fetch the transaction for.
     */
    @Test
    public void aTxoWithNoTransactionFallsThroughToEligible() {
        Network.set(Network.MAINNET);
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_HD);
        wallet.setScriptType(ScriptType.P2WPKH);
        wallet.setStoredBlockHeight(START);
        //Nothing added to the wallet's transactions, so the lookup misses
        Transaction transaction = coinbaseTransaction();
        assertTrue(new CoinbaseTxoFilter(wallet).isEligible(txo(transaction, START)));
    }

    /** A network with no deployment keeps the hundred block rule and is not frozen to mainnet's heights. */
    @Test
    public void undeployedNetworksKeepTheHundredBlockRule() {
        Network.set(Network.REGTEST);
        assertFalse(eligible(coinbaseTransaction(), START, START + ORDINARY - 2));
        assertTrue(eligible(coinbaseTransaction(), START, START + ORDINARY - 1));
    }
}
