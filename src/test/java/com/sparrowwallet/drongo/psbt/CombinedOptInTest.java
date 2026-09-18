package com.sparrowwallet.drongo.psbt;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Whether to opt in is this wallet's decision, and a combine must not move it.
 *
 * <p>The opt-in is declared per input, and a signer that cannot produce it is handed a copy asking for the
 * base type instead. What comes back therefore declares the base type while the wallet's own PSBT still
 * asks for the opt-in, and a plain overwrite adopts it. Every signer that has not signed yet is then asked
 * for the legacy digest, so a transaction the screen reported as replay protected can finish with none of
 * it, decided by nothing more than which signer went first.
 *
 * <p>The other direction matters too, for a different reason. A co-signer's PSBT is somebody else's file,
 * and letting its byte add the opt-in hands an outside party control of what this wallet signs. On a chain
 * that has not reached the activation height that produces a transaction the network will never mine.
 *
 * <p>The signatures already gathered are unaffected either way: each names the type it was made over.
 */
public class CombinedOptInTest {
    /** A one-input PSBT declaring the given hash type, with no signatures. */
    private static PSBT psbt(SigHash sigHash) {
        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.addInput(Sha256Hash.wrap(Utils.hexToBytes("ab".repeat(32))), 0, new Script(new byte[0]));
        Script spk = new Script(Utils.hexToBytes("0014" + "11".repeat(20)));
        transaction.addOutput(90000L, spk);

        PSBT psbt = new PSBT(transaction);
        PSBTInput psbtInput = psbt.getPsbtInputs().getFirst();
        psbtInput.setWitnessUtxo(new TransactionOutput(null, 100000L, spk.getProgram()));
        psbtInput.setSigHash(sigHash);
        return psbt;
    }

    private static SigHash combinedSigHash(SigHash mine, SigHash incoming) {
        PSBT ours = psbt(mine);
        ours.combine(psbt(incoming));
        return ours.getPsbtInputs().getFirst().getSigHash();
    }

    /**
     * The damaging direction, and the one an unmarked signer produces on every multisig spend.
     *
     * <p>This is what {@code psbtForDevice} hands a device that cannot opt in, so it is not a hypothetical
     * shape: it is what comes back from the signer every time.
     */
    @Test
    public void aCoSignerCannotClearTheOptInThisWalletDeclared() {
        Assertions.assertEquals(SigHash.UNIFIED_ALL, combinedSigHash(SigHash.UNIFIED_ALL, SigHash.ALL),
                "the signers that have not signed yet must still be asked for the opt-in");
    }

    /** And it cannot add one this wallet did not ask for. */
    @Test
    public void aCoSignerCannotAddAnOptInThisWalletDeclined() {
        Assertions.assertEquals(SigHash.ALL, combinedSigHash(SigHash.ALL, SigHash.UNIFIED_ALL),
                "opting in is decided from the chain this wallet follows, not from somebody else's file");
    }

    /**
     * The output type is still the incoming one. Only the opt-in bit is this wallet's to keep, and a signer
     * that answers with a different output type than it was handed is reporting something real.
     */
    @Test
    public void theIncomingOutputTypeIsStillAdopted() {
        Assertions.assertEquals(SigHash.UNIFIED_NONE, combinedSigHash(SigHash.UNIFIED_ALL, SigHash.NONE));
        Assertions.assertEquals(SigHash.SINGLE, combinedSigHash(SigHash.ALL, SigHash.UNIFIED_SINGLE));
    }

    /**
     * DEFAULT carries no hash type byte, so there is no unified form of it to move the decision onto. A
     * taproot signer answering DEFAULT where ALL was asked for is the ordinary case, and the opt-in this
     * wallet declared has to survive it rather than being silently dropped.
     */
    @Test
    public void aDefaultAnswerCannotCarryTheOptInAndSoDoesNotTakeIt() {
        Assertions.assertEquals(SigHash.UNIFIED_ALL, combinedSigHash(SigHash.UNIFIED_ALL, SigHash.DEFAULT));
    }

    /** Nothing declared here means there is no decision of this wallet's to preserve. */
    @Test
    public void anUndeclaredInputTakesWhateverArrives() {
        PSBT ours = psbt(SigHash.ALL);
        ours.getPsbtInputs().getFirst().setSigHash(null);
        ours.combine(psbt(SigHash.UNIFIED_ALL));

        Assertions.assertEquals(SigHash.UNIFIED_ALL, ours.getPsbtInputs().getFirst().getSigHash());
    }
}
