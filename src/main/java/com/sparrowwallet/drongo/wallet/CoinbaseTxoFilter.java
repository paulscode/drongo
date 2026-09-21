package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.protocol.LongCoinbaseMaturity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CoinbaseTxoFilter implements TxoFilter {
    private static final Logger log = LoggerFactory.getLogger(CoinbaseTxoFilter.class);

    private static boolean loggedUnknownTransaction;

    private final Wallet wallet;

    public CoinbaseTxoFilter(Wallet wallet) {
        this.wallet = wallet;
    }

    @Override
    public boolean isEligible(BlockTransactionHashIndex candidate) {
        BlockTransaction blockTransaction = wallet.getWalletTransaction(candidate.getHash());

        //Cannot tell whether this is a coinbase at all, so allow it, as this filter always has. Failing
        //closed here would make an ordinary wallet unspendable over one missing transaction, which is a far
        //larger harm than the case being guarded against. It is safe today because a wallet cannot hold a
        //txo whose transaction it failed to fetch: ElectrumServer throws rather than admitting one. That is
        //an invariant this filter depends on and does not enforce, so say so once if it ever breaks.
        if(blockTransaction == null || blockTransaction.getTransaction() == null) {
            if(!loggedUnknownTransaction) {
                loggedUnknownTransaction = true;
                log.warn("Cannot determine whether txo " + candidate.getHash() + ":" + candidate.getIndex()
                        + " is a coinbase, as its transaction is not present in the wallet. Allowing it to be "
                        + "spent. If this txo is an immature coinbase the spend will be rejected by the network.");
            }

            return true;
        }

        if(!blockTransaction.getTransaction().isCoinBase()) {
            return true;
        }

        //A known coinbase whose maturity cannot be evaluated is refused rather than allowed. The blast radius
        //is coinbases only, so an ordinary wallet is untouched, and the alternative is offering a coin the
        //network will not let us spend. A coinbase with no height is not in a block yet; a null tip means we
        //have nothing to measure depth against.
        if(candidate.getHeight() <= 0 || wallet.getStoredBlockHeight() == null) {
            return false;
        }

        //Asked by height rather than by confirmations, because the rule this chain deploys is a depth that
        //relay applies to every coinbase whatever height it was mined at. Below a deployed network this is
        //the same hundred blocks it has always been.
        return LongCoinbaseMaturity.isSpendable(Network.get(), candidate.getHeight(), wallet.getStoredBlockHeight());
    }
}
