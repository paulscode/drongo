package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.*;

/**
 * Upstream checks the wallet-input signatures of an unconfirmed transaction before it reaches the wallet's history, and
 * leaves out anything not shown to be signed. An opted-in signature is made over the unified message, so checking it
 * against the legacy one fails every time: without this, the wallet's own opted-in sends read as unsigned, vanish from
 * its history until they confirm, and the server is blamed for them.
 */
public class UnifiedUnsignedInputsTest {
    private static final int FUNDING_HEIGHT = 980000;

    private static final List<ScriptType> SINGLE_SIG_TYPES = List.of(ScriptType.P2PKH, ScriptType.P2SH_P2WPKH, ScriptType.P2WPKH, ScriptType.P2TR);

    @Test
    public void anOptedInSpendIsSignedForEveryScriptType() throws Exception {
        for(ScriptType scriptType : SINGLE_SIG_TYPES) {
            Wallet wallet = singleSigWallet(scriptType);
            Transaction funding = fund(wallet);
            Transaction spend = spend(wallet, SigHash.UNIFIED_ALL);

            Assertions.assertTrue(carriesUnified(spend), scriptType + ": the spend must actually carry an opted-in signature");
            Assertions.assertTrue(wallet.getUnsignedInputs(spend, lookup(funding)).isEmpty(), scriptType + ": an opted-in spend must read as signed");
        }
    }

    @Test
    public void aLegacySpendIsStillSigned() throws Exception {
        for(ScriptType scriptType : SINGLE_SIG_TYPES) {
            Wallet wallet = singleSigWallet(scriptType);
            Transaction funding = fund(wallet);
            Transaction spend = spend(wallet, null);

            Assertions.assertFalse(carriesUnified(spend), scriptType + ": a legacy spend must carry no opt-in");
            Assertions.assertTrue(wallet.getUnsignedInputs(spend, lookup(funding)).isEmpty(), scriptType + ": a legacy spend must read as signed");
        }
    }

    /**
     * The check has to keep catching what it exists to catch: an opted-in signature over different outputs is not a
     * signature for these.
     */
    @Test
    public void anOptedInSpendWithAlteredOutputsIsStillUnsigned() throws Exception {
        for(ScriptType scriptType : SINGLE_SIG_TYPES) {
            Wallet wallet = singleSigWallet(scriptType);
            Transaction funding = fund(wallet);
            Transaction altered = alterOutputs(spend(wallet, SigHash.UNIFIED_ALL));

            Assertions.assertEquals(1, wallet.getUnsignedInputs(altered, lookup(funding)).size(), scriptType + ": altered outputs must read as unsigned");
        }
    }

    /**
     * The unified message commits to every spent output, so one that cannot be looked up leaves the input unchecked,
     * which is reported as unsigned rather than guessed at.
     */
    @Test
    public void anOptedInSpendWhoseOtherSpentOutputIsUnknownCannotBeChecked() throws Exception {
        Wallet wallet = singleSigWallet(ScriptType.P2WPKH);
        Transaction funding = fund(wallet);
        Transaction spend = spend(wallet, SigHash.UNIFIED_ALL);

        Transaction withForeignInput = new Transaction(spend.bitcoinSerialize());
        Sha256Hash foreign = Sha256Hash.wrap("11".repeat(32));
        withForeignInput.addInput(foreign, 0, new Script(new byte[0]));

        Assertions.assertEquals(1, wallet.getUnsignedInputs(withForeignInput, lookup(funding)).size());
    }

    /**
     * A quorum where one signer opted in and the other did not, which is how a transaction signed by a marked device
     * and a stock one arrives. Each signature is checked under its own message.
     */
    @Test
    public void aQuorumWithOneOptedInAndOneLegacySignatureIsSigned() throws Exception {
        Wallet wallet = multisigWallet();
        Transaction funding = fund(wallet);

        PSBT psbt = createPsbt(wallet);
        Map<PSBTInput, WalletNode> signingNodes = wallet.getSigningNodes(psbt);
        for(Map.Entry<PSBTInput, WalletNode> entry : signingNodes.entrySet()) {
            PSBTInput psbtInput = entry.getKey();
            psbtInput.setSigHash(SigHash.UNIFIED_ALL);
            psbtInput.sign(wallet.getScriptType().getOutputKey(wallet.getPolicyType(), wallet.getKeystores().get(0).getKey(entry.getValue())));
            psbtInput.setSigHash(SigHash.ALL);
            psbtInput.sign(wallet.getScriptType().getOutputKey(wallet.getPolicyType(), wallet.getKeystores().get(1).getKey(entry.getValue())));
        }
        wallet.finalise(psbt);
        Transaction spend = psbt.extractTransaction();

        Assertions.assertTrue(carriesUnified(spend), "one of the two signatures must be opted in");
        Assertions.assertTrue(wallet.getUnsignedInputs(spend, lookup(funding)).isEmpty(), "both signatures must be counted");
    }

    /**
     * A quorum signed by every cosigner holds more signatures than it needs, and finalising drops the surplus. Taking them
     * in key order dropped the one that opted in whenever its key sorted last, and the transaction went out with no
     * protection having had it. Each cosigner takes a turn as the one that opts in, so every position in key order is
     * covered.
     */
    @Test
    public void finalisingAnOverSignedQuorumKeepsTheOptedInSignature() throws Exception {
        for(int optedIn = 0; optedIn < 3; optedIn++) {
            Wallet wallet = multisigWallet();
            fund(wallet);

            PSBT psbt = createPsbt(wallet);
            for(Map.Entry<PSBTInput, WalletNode> entry : wallet.getSigningNodes(psbt).entrySet()) {
                PSBTInput psbtInput = entry.getKey();
                for(int i = 0; i < 3; i++) {
                    psbtInput.setSigHash(i == optedIn ? SigHash.UNIFIED_ALL : SigHash.ALL);
                    psbtInput.sign(wallet.getScriptType().getOutputKey(wallet.getPolicyType(), wallet.getKeystores().get(i).getKey(entry.getValue())));
                }
                Assertions.assertEquals(3, psbtInput.getPartialSignatures().size());
            }
            wallet.finalise(psbt);

            Assertions.assertTrue(carriesUnified(psbt.extractTransaction()), "cosigner " + optedIn + "'s opted-in signature must survive finalising");
        }
    }

    private static boolean carriesUnified(Transaction transaction) {
        return transaction.getInputs().stream()
                .flatMap(input -> (input.hasWitness() ? input.getWitness().getSignatures() : input.getScriptSig().getSignatures()).stream())
                .anyMatch(signature -> (signature.sighashFlags & SigHash.UNIFIED_FLAG) != 0);
    }

    private static Transaction spend(Wallet wallet, SigHash unified) throws Exception {
        PSBT psbt = createPsbt(wallet);
        if(unified != null) {
            //As AppServices.applyUnifiedSigHash does for a wallet that opts in
            for(PSBTInput psbtInput : psbt.getPsbtInputs()) {
                SigHash sigHash = psbtInput.getSigHash();
                psbtInput.setSigHash(sigHash == null ? unified : sigHash.withUnified());
            }
        }
        wallet.sign(psbt);
        wallet.finalise(psbt);
        return psbt.extractTransaction();
    }

    private static PSBT createPsbt(Wallet wallet) throws Exception {
        WalletNode addressNode = wallet.getNode(KeyPurpose.RECEIVE).getChildren().iterator().next();
        TransactionParameters params = new TransactionParameters(List.of(new PriorityUtxoSelector(FUNDING_HEIGHT + 6)), Collections.emptyList(),
                List.of(new Payment(wallet.getAddress(addressNode), "test", 500_000L, false)), Collections.emptyList(),
                Collections.emptySet(), 10.0d, 1.0d, 1.0d, null, FUNDING_HEIGHT + 6, false, false, true);
        return wallet.createWalletTransaction(params).createPSBT();
    }

    private static Transaction alterOutputs(Transaction signed) {
        Transaction altered = new Transaction(signed.bitcoinSerialize());
        altered.getOutputs().getFirst().setScriptBytes(ScriptType.P2WPKH.getOutputScript(Utils.hexToBytes("bb00000000000000000000000000000000000022")).getProgram());
        altered = new Transaction(altered.bitcoinSerialize());
        Assertions.assertNotEquals(signed.getTxId(), altered.getTxId());
        return altered;
    }

    private static Transaction fund(Wallet wallet) {
        WalletNode addressNode = wallet.getNode(KeyPurpose.RECEIVE).getChildren().iterator().next();
        Transaction funding = new Transaction();
        funding.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        funding.addOutput(1_000_000L, wallet.getAddress(addressNode));
        wallet.updateTransactions(Map.of(funding.getTxId(), new BlockTransaction(funding.getTxId(), FUNDING_HEIGHT, new Date(), 0L, funding)));
        addressNode.getTransactionOutputs().add(new BlockTransactionHashIndex(funding.getTxId(), FUNDING_HEIGHT, new Date(), 0L, 0, 1_000_000L));
        return funding;
    }

    private static java.util.function.Function<Sha256Hash, Transaction> lookup(Transaction funding) {
        return txid -> txid.equals(funding.getTxId()) ? funding : null;
    }

    private static Wallet singleSigWallet(ScriptType scriptType) throws Exception {
        Wallet wallet = new Wallet("test");
        wallet.setPolicyType(PolicyType.SINGLE_HD);
        wallet.setScriptType(scriptType);
        DeterministicSeed seed = new DeterministicSeed(Utils.hexToBytes(String.format("%032x", 1)), "", 0);
        wallet.getKeystores().add(Keystore.fromSeed(seed, PolicyType.SINGLE_HD, scriptType.getDefaultDerivation()));
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, scriptType, wallet.getKeystores(), null));
        wallet.setStoredBlockHeight(FUNDING_HEIGHT + 6);
        wallet.getNode(KeyPurpose.RECEIVE).fillToIndex(0);
        return wallet;
    }

    private static Wallet multisigWallet() throws Exception {
        Wallet wallet = new Wallet("quorum");
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2WSH);
        for(int i = 1; i <= 3; i++) {
            DeterministicSeed seed = new DeterministicSeed(Utils.hexToBytes(String.format("%032x", i)), "", 0);
            Keystore keystore = Keystore.fromSeed(seed, PolicyType.MULTI_HD, ScriptType.P2WSH.getDefaultDerivation());
            keystore.setLabel("Keystore " + i);
            wallet.getKeystores().add(keystore);
        }
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), 2));
        wallet.setStoredBlockHeight(FUNDING_HEIGHT + 6);
        wallet.getNode(KeyPurpose.RECEIVE).fillToIndex(0);
        return wallet;
    }
}
