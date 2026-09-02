package com.sparrowwallet.drongo.psbt;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

/**
 * The guards around the opt-in, rather than the digest itself.
 *
 * Every defect these cover came from adding six constants to SigHash without auditing what switches on
 * it or masks it. The digest was right the whole time; the edges were not.
 */
public class UnifiedSigHashSafetyTest {
    private static final ECKey KEY = ECKey.fromPrivate(Utils.hexToBytes("11".repeat(32)));

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
        psbtInput.sign(ScriptType.P2WPKH.getOutputKey(PolicyType.SINGLE_HD, KEY));
        return psbt;
    }

    /**
     * A PSBT carrying an opted-in ECDSA signature must be readable again.
     *
     * The hash type byte is the last byte of the encoded signature, and the canonical encoding check
     * range-checks it. Without masking the opt-in bit off first, 0x21 reads as 33, the signature is
     * called non-canonical, and an unchecked VerificationException escapes the PSBT constructor. That
     * breaks every co-signer and airgapped round trip, and no amount of node-side testing sees it,
     * because the failure is in reading the PSBT back rather than in the transaction.
     */
    @Test
    public void testAnOptedInSignatureSurvivesAPsbtRoundTrip() throws PSBTParseException {
        PSBT parsed = new PSBT(signedPsbt(SigHash.UNIFIED_ALL).serialize());
        PSBTInput psbtInput = parsed.getPsbtInputs().getFirst();
        Assertions.assertEquals(1, psbtInput.getPartialSignatures().size(),
                "The opted-in signature did not survive serialisation");
        Assertions.assertEquals(SigHash.UNIFIED_ALL, psbtInput.getSigHash());

        TransactionSignature signature = psbtInput.getPartialSignatures().values().iterator().next();
        Assertions.assertEquals(SigHash.UNIFIED_ALL.byteValue(), signature.sighashFlags);
    }

    /**
     * The legacy round trip must keep working, so the masking above cannot have widened what counts as
     * canonical for signatures that did not opt in.
     */
    @Test
    public void testALegacySignatureStillRoundTrips() throws PSBTParseException {
        PSBT parsed = new PSBT(signedPsbt(SigHash.ALL).serialize());
        Assertions.assertEquals(1, parsed.getPsbtInputs().getFirst().getPartialSignatures().size());
    }

    /**
     * A hash type that is unsafe without the opt-in is exactly as unsafe with it, so it must reach the
     * same warning. A statement switch over an enum is not exhaustiveness checked, so the six opt-in
     * constants fell straight through and the gate silently stopped applying to them.
     *
     * Driving this from SigHash.values() rather than a fixed list means the next constant added to the
     * enum is covered without anyone remembering to come back here.
     */
    @Test
    public void testEveryUnsafeHashTypeIsRefusedWithOrWithoutTheOptIn() {
        for(SigHash sigHash : SigHash.values()) {
            if(sigHash.withoutUnified() == SigHash.ALL || sigHash.withoutUnified() == SigHash.DEFAULT) {
                continue;
            }

            PSBT psbt = signedPsbt(sigHash);
            Assertions.assertThrows(PSBTSignatureException.class, () -> psbt.verifySigHashes(),
                    sigHash + " (0x" + Integer.toHexString(Byte.toUnsignedInt(sigHash.byteValue()))
                            + ") was not refused by the sighash gate");
        }
    }

    /**
     * ALL and DEFAULT are the safe types, with or without the opt-in, and must not be refused.
     */
    @Test
    public void testTheSafeHashTypesAreAccepted() {
        for(SigHash sigHash : List.of(SigHash.ALL, SigHash.UNIFIED_ALL)) {
            Assertions.assertDoesNotThrow(() -> signedPsbt(sigHash).verifySigHashes(), sigHash.toString());
        }
    }

    /**
     * withUnified() must be total over the enum. It threw on ANYONECANPAY, whose opted-in form 0xA0 had
     * no constant, so a caller iterating SigHash.values() hit an exception from a method whose whole job
     * is to map between the two forms.
     */
    @Test
    public void testTheOptInMappingIsTotal() {
        for(SigHash sigHash : SigHash.values()) {
            SigHash unified = Assertions.assertDoesNotThrow(sigHash::withUnified, sigHash.toString());

            //Total in the sense that matters: it never throws and never leaves an unusable value. It is not total in
            //mapping every type to an opted-in one, because a type naming no output type has no opted-in form, and
            //giving it the bit would produce a byte consensus refuses.
            boolean namesAnOutputType = (sigHash.byteValue() & 0x1f) >= SigHash.ALL.byteValue()
                    && (sigHash.byteValue() & 0x1f) <= SigHash.SINGLE.byteValue();
            if(namesAnOutputType || sigHash == SigHash.DEFAULT) {
                Assertions.assertTrue(unified.isUnified(), sigHash + " did not map to an opted-in type");
            } else {
                Assertions.assertSame(sigHash, unified, sigHash + " has no opted-in form and must be left alone");
            }

            Assertions.assertDoesNotThrow(unified::withoutUnified, unified.toString());
        }
    }

    /**
     * A PSBT declaring a hash type this enum does not model must fail as a parse error. Consensus accepts
     * any byte for bare, P2SH and segwit v0, so such a PSBT is not necessarily malformed, and an unchecked
     * exception escaping a constructor that declares PSBTParseException defeats a caller's error handling.
     */
    @Test
    public void testAnUnmodelledHashTypeFailsAsAParseError() {
        PSBT psbt = signedPsbt(SigHash.ALL);
        byte[] serialized = psbt.serialize();
        //PSBT_IN_SIGHASH_TYPE carries the type as four little endian bytes; 0x24 is signable for segwit v0
        int index = indexOf(serialized, new byte[] {0x01, 0x00, 0x00, 0x00});
        Assertions.assertTrue(index > 0, "Could not locate the sighash type field in the fixture");
        serialized[index] = 0x24;

        Assertions.assertThrows(PSBTParseException.class, () -> new PSBT(serialized));
    }

    /**
     * Silent payments need the signature to commit to every input and every output, which is exactly what
     * the unified message does, so the guard must compare the base hash type rather than reject the
     * opt-in outright. Rejecting it would push wallets into either failing those sends or silently
     * dropping the replay protection for them.
     */
    @Test
    public void testSilentPaymentsAcceptTheOptIn() {
        for(SigHash sigHash : List.of(SigHash.ALL, SigHash.DEFAULT, SigHash.UNIFIED_ALL)) {
            Assertions.assertEquals(SigHash.ALL, sigHash == SigHash.DEFAULT ? SigHash.ALL : sigHash.withoutUnified(),
                    sigHash + " should reduce to an ALL-equivalent base type");
        }

        for(SigHash sigHash : List.of(SigHash.NONE, SigHash.UNIFIED_NONE, SigHash.SINGLE, SigHash.UNIFIED_SINGLE)) {
            Assertions.assertNotEquals(SigHash.ALL, sigHash.withoutUnified(),
                    sigHash + " must not reduce to ALL");
        }
    }

    private int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for(int i = 0; i <= haystack.length - needle.length; i++) {
            for(int j = 0; j < needle.length; j++) {
                if(haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
