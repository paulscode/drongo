package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

/**
 * Knots' CheckOutputSizes, against the outputs this wallet builds and the ones it can be handed.
 */
public class ReducedDataRulesTest {
    private static Transaction with(Script... scripts) {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        for(Script script : scripts) {
            transaction.addOutput(1000L, script);
        }
        return transaction;
    }

    private static Script opReturn(int payload) {
        return new Script(List.of(ScriptChunk.fromOpcode(ScriptOpCodes.OP_RETURN), ScriptChunk.fromData(new byte[payload])));
    }

    @Test
    public void everyOutputTypeThisWalletPaysIsWithinTheLimit() {
        ECKey key = new ECKey();
        Transaction transaction = with(ScriptType.P2PKH.getOutputScript(PolicyType.SINGLE_HD, key), ScriptType.P2SH_P2WPKH.getOutputScript(PolicyType.SINGLE_HD, key),
                ScriptType.P2WPKH.getOutputScript(PolicyType.SINGLE_HD, key), ScriptType.P2WSH.getOutputScript(Sha256Hash.hash(new byte[] {0x51})),
                ScriptType.P2TR.getOutputScript(PolicyType.SINGLE_HD, key));
        Assertions.assertEquals(List.of(), ReducedDataRules.outputViolations(transaction));
    }

    /** The PayNym notification payload is 80 bytes, which pushes to an 83 byte script: exactly the limit. */
    @Test
    public void thePayNymNotificationOpReturnIsExactlyAtTheLimit() {
        Assertions.assertEquals(83, opReturn(80).getProgram().length);
        Assertions.assertEquals(List.of(), ReducedDataRules.outputViolations(with(opReturn(80))));
        Assertions.assertEquals(1, ReducedDataRules.outputViolations(with(opReturn(81))).size(), "one byte more is refused");
    }

    @Test
    public void anOversizedOutputScriptIsRefused() {
        //A witness v2 program of 40 bytes, which BIP350 allows an address to carry: a 42 byte script
        byte[] program = new byte[42];
        program[0] = 0x52;
        program[1] = 40;
        List<String> violations = ReducedDataRules.outputViolations(with(new Script(program)));
        Assertions.assertEquals(1, violations.size());
        Assertions.assertTrue(violations.getFirst().contains("42 bytes, over the 34"), violations.getFirst());
    }

    @Test
    public void theRulesEndWithRdts() {
        Assertions.assertTrue(ReducedDataRules.isActive(Network.MAINNET, 1793000000L), "2026-10");
        Assertions.assertFalse(ReducedDataRules.isActive(Network.MAINNET, 1819756800L + 3 * 60 * 60), "past 2027-09-01");
        Assertions.assertFalse(ReducedDataRules.isActive(Network.TESTNET4, 1806537600L + 3 * 60 * 60), "past 2027-04-01");
        Assertions.assertFalse(ReducedDataRules.isActive(Network.REGTEST, 0L), "no schedule here");
    }
}
