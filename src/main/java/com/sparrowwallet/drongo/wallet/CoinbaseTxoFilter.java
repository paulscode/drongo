package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.protocol.LongCoinbaseMaturity;

public class CoinbaseTxoFilter implements TxoFilter {
    private final Wallet wallet;

    public CoinbaseTxoFilter(Wallet wallet) {
        this.wallet = wallet;
    }

    @Override
    public boolean isEligible(BlockTransactionHashIndex candidate) {
        //Disallow immature coinbase outputs
        BlockTransaction blockTransaction = wallet.getWalletTransaction(candidate.getHash());
        if(blockTransaction != null && blockTransaction.getTransaction() != null && blockTransaction.getTransaction().isCoinBase()
                && wallet.getStoredBlockHeight() != null) {
            //A coinbase with no height yet is not in a block yet, so it is not spendable whatever the rule says.
            //getConfirmations() used to fold this in by returning zero; asking by height does not, and a height of
            //zero would otherwise read as an ancient coin that matured long ago.
            if(candidate.getHeight() <= 0) {
                return false;
            }

            //Asked by height rather than by confirmations, because this chain's temporary long maturity rule is
            //a window on the spending block rather than a depth: coins mined inside it all unlock at one height,
            //so a count of confirmations cannot answer it. Below the window this is the same hundred blocks it
            //has always been.
            return LongCoinbaseMaturity.isSpendable(Network.get(), candidate.getHeight(), wallet.getStoredBlockHeight());
        }

        return true;
    }
}
