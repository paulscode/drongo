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

    /** Below the window, the hundred block rule, unchanged to the block. */
    @Test
    public void belowTheWindowTheHundredBlockRuleIsUnchanged() {
        Network.set(Network.MAINNET);
        int height = START - 5000;
        assertFalse(eligible(coinbaseTransaction(), height, height + ORDINARY - 2));
        assertTrue(eligible(coinbaseTransaction(), height, height + ORDINARY - 1));
    }

    /** Inside the window, nothing is spendable until the release height, however deep it is buried. */
    @Test
    public void insideTheWindowNothingIsSpendableUntilRelease() {
        Network.set(Network.MAINNET);
        assertFalse(eligible(coinbaseTransaction(), START, START + ORDINARY));
        assertFalse(eligible(coinbaseTransaction(), START, RELEASE - 2));
        assertTrue(eligible(coinbaseTransaction(), START, RELEASE - 1));
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
     * An unknown tip leaves the coin eligible, which is the behaviour this filter has always had. Recorded
     * rather than endorsed: every guard here sits inside the condition, so anything it cannot answer falls
     * through to spendable. It is safe today only because a wallet cannot hold a transaction it failed to
     * fetch, ElectrumServer throwing rather than admitting one.
     */
    @Test
    public void anUnknownTipFallsThroughToEligible() {
        Network.set(Network.MAINNET);
        assertTrue(eligible(coinbaseTransaction(), START, null));
    }

    /** A network with no deployment keeps the hundred block rule and is not frozen to mainnet's heights. */
    @Test
    public void undeployedNetworksKeepTheHundredBlockRule() {
        Network.set(Network.REGTEST);
        assertFalse(eligible(coinbaseTransaction(), START, START + ORDINARY - 2));
        assertTrue(eligible(coinbaseTransaction(), START, START + ORDINARY - 1));
    }
}
