package com.sparrowwallet.drongo.psbt;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;

/**
 * Signs one P2WPKH input with drongo and prints the finalised transaction, so a node can be asked
 * whether it accepts it. Driven by the interop script rather than by the test suite.
 *
 * The private key is read from UNIFIED_HARNESS_KEY rather than argv, since a command line is world
 * readable through /proc for the lifetime of the process.
 *
 * scriptpubkey
 *     prints the p2wpkh scriptPubKey drongo derives, so the funding side and the signing side cannot
 *     disagree about which key is being tested
 *
 * sign privKeyHex prevTxid prevVout prevValue destScriptHex destValue stampHex [digestHex]
 *     stampHex is the hash type byte written on the signature; digestHex is the one the digest is
 *     computed under, defaulting to stampHex. Passing them separately builds the control case: a
 *     signature over the legacy message that claims to be an opted-in one, which must not verify.
 */
public class UnifiedSignHarness {
    private static String privateKeyHex() {
        String key = System.getenv("UNIFIED_HARNESS_KEY");
        if(key == null || key.isEmpty()) {
            throw new IllegalStateException("Set UNIFIED_HARNESS_KEY to the private key hex");
        }

        return key;
    }

    public static void main(String[] args) throws Exception {
        if(args.length == 0) {
            throw new IllegalArgumentException("Usage: scriptpubkey | sign <args>");
        }

        if("scriptpubkey".equals(args[0])) {
            ECKey privKey = ECKey.fromPrivate(Utils.hexToBytes(privateKeyHex()));
            System.out.println(Utils.bytesToHex(ScriptType.P2WPKH.getOutputScript(PolicyType.SINGLE_HD, privKey).getProgram()));
            return;
        }

        if(!"sign".equals(args[0])) {
            throw new IllegalArgumentException("Unknown mode " + args[0]);
        }

        ECKey privKey = ECKey.fromPrivate(Utils.hexToBytes(privateKeyHex()));
        Sha256Hash prevTxid = Sha256Hash.wrap(args[1]);
        int prevVout = Integer.parseInt(args[2]);
        long prevValue = Long.parseLong(args[3]);
        byte[] destScript = Utils.hexToBytes(args[4]);
        long destValue = Long.parseLong(args[5]);
        byte stamp = (byte)Integer.parseInt(args[6], 16);
        byte digestType = args.length > 7 ? (byte)Integer.parseInt(args[7], 16) : stamp;

        ECKey outputKey = ScriptType.P2WPKH.getOutputKey(PolicyType.SINGLE_HD, privKey);
        Script spk = ScriptType.P2WPKH.getOutputScript(PolicyType.SINGLE_HD, privKey);

        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.addInput(prevTxid, prevVout, new Script(new byte[0]));
        transaction.getInputs().getFirst().setSequenceNumber(0xFFFFFFFEL);
        transaction.addOutput(destValue, new Script(destScript));

        PSBT psbt = new PSBT(transaction);
        PSBTInput psbtInput = psbt.getPsbtInputs().getFirst();
        psbtInput.setWitnessUtxo(new TransactionOutput(null, prevValue, spk.getProgram()));
        psbtInput.setSigHash(SigHash.fromByte(digestType));
        psbtInput.sign(outputKey);

        TransactionSignature signature = psbtInput.getPartialSignatures().get(ECKey.fromPublicOnly(outputKey));
        if(signature == null) {
            throw new IllegalStateException("drongo produced no signature");
        }
        if(signature.sighashFlags != digestType) {
            throw new IllegalStateException("Signature carries hash type " + Integer.toHexString(Byte.toUnsignedInt(signature.sighashFlags)));
        }

        //Restamp only when the control case asks for it, leaving the digest as it was signed. The hash
        //type is the last byte of the encoded signature, so rewriting it there needs no access to r and s.
        TransactionSignature stamped = signature;
        if(stamp != digestType) {
            byte[] encoded = signature.encodeToBitcoin();
            encoded[encoded.length - 1] = stamp;
            stamped = TransactionSignature.decodeFromBitcoin(encoded, false);
        }

        //Finalise the witness by hand so the harness stays independent of the wallet finaliser. The
        //segwit flag has to be set explicitly: the PSBT constructor clears it, and without it the
        //witness is simply left out of the serialisation.
        Transaction finalTx = new Transaction(psbt.getTransaction().bitcoinSerialize());
        finalTx.setSegwitFlag(1);
        finalTx.getInputs().getFirst().setWitness(new TransactionWitness(finalTx, ECKey.fromPublicOnly(outputKey), stamped));

        System.out.println("SIGHASH_BYTE=" + String.format("%02x", stamped.sighashFlags));
        System.out.println("DIGEST_BYTE=" + String.format("%02x", digestType));
        System.out.println("RAWTX=" + Utils.bytesToHex(finalTx.bitcoinSerialize()));
    }
}
