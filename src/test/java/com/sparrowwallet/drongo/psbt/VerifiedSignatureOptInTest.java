package com.sparrowwallet.drongo.psbt;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A claim about replay protection has to be counted from signatures, not from things shaped like them.
 *
 * <p>The opt-in is carried in a signature's hash type byte. Reading that byte off whatever sits in the
 * witness is not enough, because the witness holds other pushes of the same length, and this is the one
 * direction the reading must never fail in: saying "protected" over a transaction that is not.
 */
public class VerifiedSignatureOptInTest {
    private static final ECKey KEY = ECKey.fromPrivate(Utils.hexToBytes("11".repeat(32)));
    private static final ECKey OTHER_KEY = ECKey.fromPrivate(Utils.hexToBytes("22".repeat(32)));

    private static ECKey outputKey(ECKey key) {
        return ScriptType.P2WPKH.getOutputKey(PolicyType.SINGLE_HD, key);
    }

    private PSBT signedPsbt(SigHash sigHash) {
        Script spk = ScriptType.P2WPKH.getOutputScript(PolicyType.SINGLE_HD, KEY);
        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.addInput(Sha256Hash.wrap(Utils.hexToBytes("aa".repeat(32))), 0, new Script(new byte[0]));
        transaction.addOutput(90000L, spk);

        PSBT psbt = new PSBT(transaction);
        PSBTInput psbtInput = psbt.getPsbtInputs().getFirst();
        psbtInput.setWitnessUtxo(new TransactionOutput(null, 100000L, spk.getProgram()));
        psbtInput.setSigHash(sigHash);
        psbtInput.sign(outputKey(KEY));
        return psbt;
    }

    @Test
    public void arealOptedInSignatureVerifiesAgainstTheKeyThatMadeIt() {
        PSBTInput psbtInput = signedPsbt(SigHash.UNIFIED_ALL).getPsbtInputs().getFirst();

        Map<ECKey, TransactionSignature> verified = psbtInput.getVerifiedSignatures(Set.of(outputKey(KEY)));
        Assertions.assertEquals(1, verified.size(), "the signature this key made must be found");
        Assertions.assertEquals(SigHash.UNIFIED_ALL.byteValue(), verified.values().iterator().next().sighashFlags);
    }

    @Test
    public void aLegacySignatureIsFoundAndReadsAsNotOptedIn() {
        PSBTInput psbtInput = signedPsbt(SigHash.ALL).getPsbtInputs().getFirst();

        Map<ECKey, TransactionSignature> verified = psbtInput.getVerifiedSignatures(Set.of(outputKey(KEY)));
        Assertions.assertEquals(1, verified.size());
        Assertions.assertEquals(0, verified.values().iterator().next().sighashFlags & SigHash.UNIFIED_FLAG,
                "a signature made the old way must not read as an opt-in");
    }

    /**
     * A signature nobody in this wallet made counts for nothing.
     *
     * <p>Otherwise a PSBT could vouch for itself: it would carry both a signature and the key said to
     * have made it, and agreeing with itself is not evidence.
     */
    @Test
    public void aSignatureFromAKeyThisWalletDoesNotHoldIsNotCounted() {
        PSBTInput psbtInput = signedPsbt(SigHash.UNIFIED_ALL).getPsbtInputs().getFirst();

        Assertions.assertTrue(psbtInput.getVerifiedSignatures(Set.of(outputKey(OTHER_KEY))).isEmpty(),
                "a key that did not sign must vouch for nothing");
        Assertions.assertTrue(psbtInput.getVerifiedSignatures(Set.of()).isEmpty(),
                "no keys means nothing was checked, so nothing is counted");
    }

    /**
     * The defect this exists to stop.
     *
     * <p>Any 64 or 65 byte push decodes as a Schnorr signature whose hash type is its own last byte. A
     * taproot control block with a single merkle step is 65 bytes and ends in the tail of a hash, so it
     * reads as a signature, and as an opted-in one about half the time. An uncompressed public key is
     * the same length. Counting by shape therefore reported replay protection over transactions that
     * had none, and this asserts both halves: that the blob really does read as an opt-in by shape, and
     * that verification refuses it anyway.
     */
    @Test
    public void aPushThatMerelyLooksLikeAnOptedInSignatureIsRefused() {
        byte[] controlBlock = new byte[65];
        controlBlock[0] = (byte)0xc0;
        for(int i = 1; i < 64; i++) {
            controlBlock[i] = (byte)i;
        }
        //The byte a shape-based reading would take for the hash type, with the opt-in bit set
        controlBlock[64] = (byte)0x21;

        ScriptChunk chunk = ScriptChunk.fromData(controlBlock);
        Assertions.assertTrue(chunk.isSignature(),
                "this is the confusion being guarded against: the blob does decode as a signature");
        Assertions.assertNotEquals(0, chunk.getSignature().sighashFlags & SigHash.UNIFIED_FLAG,
                "and by shape alone it reads as opted in");

        PSBT psbt = signedPsbt(SigHash.ALL);
        PSBTInput psbtInput = psbt.getPsbtInputs().getFirst();
        psbtInput.setFinalScriptWitness(new TransactionWitness(null, List.of(controlBlock)));

        Assertions.assertTrue(psbtInput.getVerifiedSignatures(Set.of(outputKey(KEY))).isEmpty(),
                "nothing verified, so nothing may be counted as an opt-in");
    }

    /**
     * Without a spent output there is no amount and no script to commit to, so nothing can be hashed and
     * nothing can be checked. That reads as no opt-in rather than as an unchecked one.
     */
    @Test
    public void anInputWithNoSpentOutputVerifiesNothing() {
        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.addInput(Sha256Hash.wrap(Utils.hexToBytes("bb".repeat(32))), 0, new Script(new byte[0]));
        transaction.addOutput(90000L, ScriptType.P2WPKH.getOutputScript(PolicyType.SINGLE_HD, KEY));

        PSBTInput psbtInput = new PSBT(transaction).getPsbtInputs().getFirst();
        Assertions.assertTrue(psbtInput.getVerifiedSignatures(Set.of(outputKey(KEY))).isEmpty());
    }
}
