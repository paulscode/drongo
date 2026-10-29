package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Block extends Message {
    private BlockHeader blockHeader;
    private Sha256Hash hash;
    private List<Transaction> transactions;

    public Block(byte[] payload) {
        super(payload, 0);
    }

    public void parse() {
        blockHeader = new BlockHeader(payload, cursor);
        cursor += blockHeader.getMessageSize();

        //The header's own hash, which is BLAKE2b above the fork: hashing the serialized bytes twice with SHA256 names no
        //block on this chain for a v2 header
        hash = blockHeader.getHash();
        if(cursor != payload.length) {
            long numTransactions = readVarInt();
            if(numTransactions < 0) {
                throw new ProtocolException("Invalid transaction count: " + numTransactions);
            }
            transactions = new ArrayList<>((int)Math.min(numTransactions, Utils.MAX_INITIAL_ARRAY_LENGTH));
            for(long i = 0; i < numTransactions; i++) {
                Transaction tx = new Transaction(payload, cursor);
                transactions.add(tx);
                cursor += tx.getMessageSize();
            }
        } else {
            transactions = Collections.emptyList();
        }
    }

    public BlockHeader getBlockHeader() {
        return blockHeader;
    }

    public Sha256Hash getHash() {
        return hash;
    }

    public List<Transaction> getTransactions() {
        return transactions;
    }
}
