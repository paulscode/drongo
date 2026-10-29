package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;

import java.util.ArrayList;
import java.util.List;

/**
 * The output size limits of RDTS (BIP110, the ReducedData Temporary Softfork), which this chain enforces from the BLAKE2b
 * activation until RDTS expires and the chain that kept SHA256d does not.
 *
 * <p>Read from Bitcoin Knots at {@code v29.4.3.knots20260508}: {@code Consensus::CheckOutputSizes} in
 * {@code src/consensus/tx_verify.cpp} refuses any output script over {@code MAX_OUTPUT_SCRIPT_SIZE} (34) bytes, or over
 * {@code MAX_OUTPUT_DATA_SIZE} (83) where it begins with OP_RETURN, while {@code Params::RdtsActiveAt} holds, which is from
 * {@code Blake2bHeight} until the parent's median time past reaches {@code RdtsExpiryTime}.
 *
 * <p>RDTS also limits pushes and witness elements to 256 bytes (the P2SH redeem script push and the P2WSH witness script
 * excepted), forbids the taproot annex, limits taproot control blocks to seven levels and forbids OP_IF in tapscript.
 * Those need the outputs being spent to judge, and nothing this wallet builds comes near them: its witness scripts are
 * exempt, it adds no annex, and its taproot spends are key path only. What it can be handed is a transaction built
 * elsewhere, and the output rule is the one that can be read off such a transaction alone.
 *
 * <p>A transaction breaking it is valid on the chain that kept SHA256d and refused here, which matters both ways: it will
 * never confirm on this chain, and broadcast elsewhere it moves the coins on the other one.
 */
public final class ReducedDataRules {
    public static final int MAX_OUTPUT_SCRIPT_SIZE = 34;
    public static final int MAX_OUTPUT_DATA_SIZE = 83;

    /** {@code RdtsExpiryTime}: 1 September 2027 00:00 UTC on mainnet, 1 April 2027 on testnet4. */
    private static final long MAINNET_EXPIRY_TIME = 1819756800L;
    private static final long TESTNET4_EXPIRY_TIME = 1806537600L;

    private ReducedDataRules() {
    }

    /**
     * Whether the rules hold for a transaction confirming at about this time. Measured against the clock rather than the
     * median time past, which lags it by about an hour, so this keeps enforcing for that hour past expiry: refusing a
     * transaction that would by then confirm, never offering one that would not.
     */
    public static boolean isActive(Network network, long nowSeconds) {
        return switch(network) {
            case MAINNET -> nowSeconds < MAINNET_EXPIRY_TIME + 2 * 60 * 60;
            case TESTNET4 -> nowSeconds < TESTNET4_EXPIRY_TIME + 2 * 60 * 60;
            default -> false;
        };
    }

    /** The outputs of this transaction the rules refuse, each described for a person. Empty where there are none. */
    public static List<String> outputViolations(Transaction transaction) {
        List<String> violations = new ArrayList<>();
        List<TransactionOutput> outputs = transaction.getOutputs();
        for(int i = 0; i < outputs.size(); i++) {
            byte[] script = outputs.get(i).getScriptBytes();
            if(script == null || script.length == 0) {
                continue;
            }

            boolean opReturn = (script[0] & 0xff) == ScriptOpCodes.OP_RETURN;
            int limit = opReturn ? MAX_OUTPUT_DATA_SIZE : MAX_OUTPUT_SCRIPT_SIZE;
            if(script.length > limit) {
                violations.add("Output " + i + (opReturn ? " is an OP_RETURN of " : " has a script of ") + script.length
                        + " bytes, over the " + limit + " this chain allows");
            }
        }

        return violations;
    }
}
