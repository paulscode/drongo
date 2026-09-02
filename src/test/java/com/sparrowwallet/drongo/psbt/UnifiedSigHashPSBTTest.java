package com.sparrowwallet.drongo.psbt;

import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Signing and verification through a PSBT that opts in, which is the path the wallet actually takes.
 *
 * UnifiedSigHashTest establishes that the digest agrees with the reference. What is left to show is
 * that a PSBT declaring an opted-in hash type reaches that digest rather than the legacy one, that the
 * hash type byte on the signature says so, and that the two messages are genuinely distinct, so a
 * signature made under one does not verify under the other.
 */
public class UnifiedSigHashPSBTTest {
    private static final ECKey KEY_ONE = ECKey.fromPrivate(Utils.hexToBytes("11".repeat(32)));
    private static final ECKey KEY_TWO = ECKey.fromPrivate(Utils.hexToBytes("22".repeat(32)));
    private static final long VALUE_ONE = 100000L;
    private static final long VALUE_TWO = 250000L;

    private PSBT twoInputPsbt(SigHash sigHash) {
        Script spkOne = ScriptType.P2WPKH.getOutputScript(PolicyType.SINGLE_HD, KEY_ONE);
        Script spkTwo = ScriptType.P2WPKH.getOutputScript(PolicyType.SINGLE_HD, KEY_TWO);

        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.addInput(Sha256Hash.wrap(Utils.hexToBytes("aa".repeat(32))), 0, new Script(new byte[0]));
        transaction.addInput(Sha256Hash.wrap(Utils.hexToBytes("bb".repeat(32))), 1, new Script(new byte[0]));
        transaction.addOutput(VALUE_ONE + VALUE_TWO - 1000L, spkOne);

        PSBT psbt = new PSBT(transaction);
        List<PSBTInput> inputs = psbt.getPsbtInputs();
        inputs.get(0).setWitnessUtxo(new TransactionOutput(null, VALUE_ONE, spkOne.getProgram()));
        inputs.get(1).setWitnessUtxo(new TransactionOutput(null, VALUE_TWO, spkTwo.getProgram()));
        for(PSBTInput input : inputs) {
            input.setSigHash(sigHash);
        }

        return psbt;
    }

    private ECKey outputKey(ECKey privKey) {
        return ScriptType.P2WPKH.getOutputKey(PolicyType.SINGLE_HD, privKey);
    }

    @Test
    public void testSigningAnOptedInPsbtCarriesTheHashTypeByte() {
        PSBT psbt = twoInputPsbt(SigHash.UNIFIED_ALL);
        List<PSBTInput> inputs = psbt.getPsbtInputs();
        inputs.get(0).sign(outputKey(KEY_ONE));
        inputs.get(1).sign(outputKey(KEY_TWO));

        for(PSBTInput input : inputs) {
            Assertions.assertFalse(input.getPartialSignatures().isEmpty(), "Input produced no signature");
            for(TransactionSignature signature : input.getPartialSignatures().values()) {
                Assertions.assertEquals(SigHash.UNIFIED_ALL.byteValue(), signature.sighashFlags,
                        "Signature does not carry the opt-in hash type");
            }
        }
    }

    /**
     * The signature must verify against the unified digest, which is what proves signing and verification
     * agree on which message was signed rather than only that a signature was produced.
     */
    @Test
    public void testAnOptedInSignatureVerifies() {
        PSBT psbt = twoInputPsbt(SigHash.UNIFIED_ALL);
        List<PSBTInput> inputs = psbt.getPsbtInputs();
        inputs.get(0).sign(outputKey(KEY_ONE));
        inputs.get(1).sign(outputKey(KEY_TWO));

        Map<ECKey, TransactionSignature> first = inputs.get(0).getSigningKeys(Set.of(ECKey.fromPublicOnly(outputKey(KEY_ONE))));
        Assertions.assertEquals(1, first.size(), "The opted-in signature did not verify");
        Map<ECKey, TransactionSignature> second = inputs.get(1).getSigningKeys(Set.of(ECKey.fromPublicOnly(outputKey(KEY_TWO))));
        Assertions.assertEquals(1, second.size(), "The opted-in signature did not verify");
    }

    /**
     * The PSBT path must reach the same digest as calling the algorithm directly, with the segwit v0
     * script type byte and the BIP143 script code. Anything else would verify here and be rejected by a node.
     */
    @Test
    public void testPsbtDigestMatchesTheAlgorithmDirectly() {
        PSBT psbt = twoInputPsbt(SigHash.UNIFIED_ALL);
        List<PSBTInput> inputs = psbt.getPsbtInputs();
        inputs.get(0).sign(outputKey(KEY_ONE));

        List<TransactionOutput> spentUtxos = inputs.stream().map(PSBTInput::getUtxo).toList();
        byte[] scriptCode = ScriptType.P2PKH.getOutputScript(PolicyType.SINGLE_HD, outputKey(KEY_ONE)).getProgram();
        Sha256Hash expected = psbt.getTransaction().hashForUnifiedSignature(spentUtxos, 0, UnifiedScriptType.WITNESS_V0,
                scriptCode, SigHash.UNIFIED_ALL.byteValue(), null, null, null);

        ECKey pubKey = ECKey.fromPublicOnly(outputKey(KEY_ONE));
        TransactionSignature signature = inputs.get(0).getPartialSignatures().get(pubKey);
        Assertions.assertNotNull(signature, "No signature for the signing key");
        Assertions.assertTrue(pubKey.verify(expected, signature), "The PSBT signed a different message than the algorithm produces");
    }

    /**
     * Opting in must change which message is signed. If a legacy signature verified against the unified
     * digest the opt-in would be doing nothing, and the replay protection it exists for would be absent.
     */
    @Test
    public void testALegacySignatureDoesNotVerifyAsUnified() {
        PSBT legacyPsbt = twoInputPsbt(SigHash.ALL);
        legacyPsbt.getPsbtInputs().get(0).sign(outputKey(KEY_ONE));
        TransactionSignature legacySignature = legacyPsbt.getPsbtInputs().get(0).getPartialSignatures().get(ECKey.fromPublicOnly(outputKey(KEY_ONE)));
        Assertions.assertNotNull(legacySignature);
        Assertions.assertEquals(SigHash.ALL.byteValue(), legacySignature.sighashFlags);

        PSBT unifiedPsbt = twoInputPsbt(SigHash.UNIFIED_ALL);
        List<PSBTInput> inputs = unifiedPsbt.getPsbtInputs();
        List<TransactionOutput> spentUtxos = inputs.stream().map(PSBTInput::getUtxo).toList();
        byte[] scriptCode = ScriptType.P2PKH.getOutputScript(PolicyType.SINGLE_HD, outputKey(KEY_ONE)).getProgram();
        Sha256Hash unifiedDigest = unifiedPsbt.getTransaction().hashForUnifiedSignature(spentUtxos, 0, UnifiedScriptType.WITNESS_V0,
                scriptCode, SigHash.UNIFIED_ALL.byteValue(), null, null, null);

        Assertions.assertFalse(ECKey.fromPublicOnly(outputKey(KEY_ONE)).verify(unifiedDigest, legacySignature),
                "A legacy signature verified against the unified message");
    }

    /**
     * A PSBT carrying an opted-in hash type must survive serialisation, or a signing device is handed a
     * request it cannot read.
     */
    @Test
    public void testAnOptedInHashTypeRoundTripsThroughSerialisation() throws PSBTParseException {
        PSBT psbt = twoInputPsbt(SigHash.UNIFIED_ALL);
        PSBT parsed = new PSBT(psbt.serialize());
        for(PSBTInput input : parsed.getPsbtInputs()) {
            Assertions.assertEquals(SigHash.UNIFIED_ALL, input.getSigHash());
        }
    }
}
