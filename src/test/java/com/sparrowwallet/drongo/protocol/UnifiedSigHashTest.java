package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * The unified opt-in signature hash, checked against the reference implementation's own vectors.
 *
 * The fixture is copied unmodified from src/test/data/unified_sighash.json in the hf-sighash-opt-in
 * branch, at commit 4a180066, and covers all four script types: bare and P2SH, segwit v0, taproot key
 * path and tapscript. Hashes there are raw bytes rather than the reversed display order, so they are
 * compared against getBytes() rather than toString().
 *
 * Vector coverage is what makes this meaningful: the digest is a consensus rule, so agreeing with the
 * reference on every defined case is the only claim worth making about it. Two negative tests guard
 * the suite itself, since a check that passes for the wrong reason is worse than no check.
 *
 * For tapscript rows the scriptCode column holds the leaf script rather than a script code, and the
 * leaf hash is derived from it, as the reference's own vector test does. The rows assume no annex and
 * no executed OP_CODESEPARATOR.
 */
public class UnifiedSigHashTest {
    private static final String FIXTURE = "/unified_sighash.json";
    private static final int EXPECTED_VECTORS = 166;

    @Test
    public void testMatchesReferenceVectors() throws IOException {
        List<Vector> vectors = loadVectors();
        Assertions.assertEquals(EXPECTED_VECTORS, vectors.size(), "Unexpected number of vectors in " + FIXTURE);

        for(int i = 0; i < vectors.size(); i++) {
            Vector v = vectors.get(i);
            Assertions.assertArrayEquals(Utils.hexToBytes(v.sigHash), digest(v).getBytes(),
                    "Vector " + i + ": scriptType=" + v.scriptType + " hashType=0x" + Integer.toHexString(v.hashType));
        }
    }

    @Test
    public void testAllFourScriptTypesAreCovered() throws IOException {
        List<UnifiedScriptType> seen = loadVectors().stream().map(v -> v.scriptType).distinct().toList();
        for(UnifiedScriptType scriptType : UnifiedScriptType.values()) {
            Assertions.assertTrue(seen.contains(scriptType), "No vector covers " + scriptType);
        }
    }

    /**
     * Guards the vector test: if signing under the wrong script type produced the same digest, the
     * domain separation byte would not be doing anything and the check above would be vacuous.
     */
    @Test
    public void testScriptTypeSeparatesDomains() throws IOException {
        Vector bare = loadVectors().stream().filter(v -> v.scriptType == UnifiedScriptType.BARE).findFirst().orElseThrow();
        Vector wrong = new Vector(bare);
        wrong.scriptType = UnifiedScriptType.WITNESS_V0;
        Assertions.assertNotEquals(Utils.bytesToHex(digest(bare).getBytes()), Utils.bytesToHex(digest(wrong).getBytes()));
    }

    /**
     * A hash type without the opt-in bit does not describe this message and must be refused rather than
     * silently producing one, or a caller could believe it opted in when it did not.
     */
    @Test
    public void testHashTypeWithoutTheOptInIsRefused() throws IOException {
        Vector v = loadVectors().getFirst();
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            Transaction tx = new Transaction(Utils.hexToBytes(v.rawTx));
            tx.hashForUnifiedSignature(v.spentOutputs, v.inIdx, v.scriptType, Utils.hexToBytes(v.scriptCode),
                    (byte)(v.hashType & ~SigHash.UNIFIED_FLAG), null, null, null);
        });
    }

    /**
     * BIP341's reading is kept for taproot and tapscript, so a hash type it does not define is refused at
     * the digest rather than accepted the way bare and segwit v0 accept every byte.
     */
    @Test
    public void testTaprootRefusesAnUndefinedHashType() throws IOException {
        Vector v = loadVectors().stream().filter(x -> x.scriptType == UnifiedScriptType.TAPROOT).findFirst().orElseThrow();
        Transaction tx = new Transaction(Utils.hexToBytes(v.rawTx));
        for(int hashType : List.of(0x24, 0x25, 0x30, 0x60)) {
            Assertions.assertThrows(IllegalArgumentException.class,
                    () -> tx.hashForUnifiedSignature(v.spentOutputs, v.inIdx, v.scriptType, null, (byte)hashType, null, null, null),
                    "Hash type 0x" + Integer.toHexString(hashType) + " should not be defined for taproot");
        }
    }

    /**
     * The fixture column is the wire byte the message commits to, so look it up by that rather than by
     * the enum's declaration order. Reordering the enum would otherwise silently pair every vector with
     * the wrong script type, in the one test whose job is to catch exactly that.
     */
    private static UnifiedScriptType scriptTypeFor(int wireByte) {
        for(UnifiedScriptType scriptType : UnifiedScriptType.values()) {
            if(scriptType.byteValue() == wireByte) {
                return scriptType;
            }
        }

        throw new IllegalArgumentException("No script type for wire byte " + wireByte);
    }

    /**
     * The annex and codeseparator commitments, which no vector on either side of the interop covers: the
     * fixture has no column for either, so the reference's own vector test does not exercise them and
     * neither did this one. These do not prove the layout matches the reference, only that the bytes are
     * committed to at all, so a field that was accidentally dropped from the message cannot pass. The
     * layout itself was checked by reading it against SignatureHashUnified.
     */
    @Test
    public void testTheTaprootTailIsCommittedTo() throws IOException {
        Vector v = loadVectors().stream().filter(x -> x.scriptType == UnifiedScriptType.TAPROOT).findFirst().orElseThrow();
        Transaction tx = new Transaction(Utils.hexToBytes(v.rawTx));
        Sha256Hash noAnnex = tx.hashForUnifiedSignature(v.spentOutputs, v.inIdx, v.scriptType, null, (byte)v.hashType, null, null, null);

        byte[] annex = Utils.hexToBytes("5001020304");
        Sha256Hash withAnnex = tx.hashForUnifiedSignature(v.spentOutputs, v.inIdx, v.scriptType, null, (byte)v.hashType, annex, null, null);
        Assertions.assertNotEquals(noAnnex, withAnnex, "The annex is not committed to");

        byte[] otherAnnex = Utils.hexToBytes("5004030201");
        Assertions.assertNotEquals(withAnnex,
                tx.hashForUnifiedSignature(v.spentOutputs, v.inIdx, v.scriptType, null, (byte)v.hashType, otherAnnex, null, null),
                "The annex contents are not committed to");
    }

    @Test
    public void testTheTapscriptTailIsCommittedTo() throws IOException {
        Vector v = loadVectors().stream().filter(x -> x.scriptType == UnifiedScriptType.TAPSCRIPT).findFirst().orElseThrow();
        Transaction tx = new Transaction(Utils.hexToBytes(v.rawTx));
        byte[] leaf = Utils.hexToBytes("ab".repeat(32));
        byte[] otherLeaf = Utils.hexToBytes("cd".repeat(32));

        Sha256Hash noCodeSep = tx.hashForUnifiedSignature(v.spentOutputs, v.inIdx, v.scriptType, null, (byte)v.hashType, null, leaf, null);
        Assertions.assertNotEquals(noCodeSep,
                tx.hashForUnifiedSignature(v.spentOutputs, v.inIdx, v.scriptType, null, (byte)v.hashType, null, otherLeaf, null),
                "The tapleaf hash is not committed to, so a signature for one leaf would serve another");

        Assertions.assertNotEquals(noCodeSep,
                tx.hashForUnifiedSignature(v.spentOutputs, v.inIdx, v.scriptType, null, (byte)v.hashType, null, leaf, 0),
                "The codeseparator position is not committed to");
        Assertions.assertNotEquals(
                tx.hashForUnifiedSignature(v.spentOutputs, v.inIdx, v.scriptType, null, (byte)v.hashType, null, leaf, 0),
                tx.hashForUnifiedSignature(v.spentOutputs, v.inIdx, v.scriptType, null, (byte)v.hashType, null, leaf, 1),
                "The codeseparator position value is not committed to");
    }

    private Sha256Hash digest(Vector v) {
        Transaction tx = new Transaction(Utils.hexToBytes(v.rawTx));
        byte[] scriptCode = null;
        byte[] tapLeafHash = null;
        if(v.scriptType == UnifiedScriptType.BARE || v.scriptType == UnifiedScriptType.WITNESS_V0) {
            scriptCode = Utils.hexToBytes(v.scriptCode);
        } else if(v.scriptType == UnifiedScriptType.TAPSCRIPT) {
            ByteArrayOutputStream leafStream = new ByteArrayOutputStream();
            byte[] leafScript = Utils.hexToBytes(v.scriptCode);
            leafStream.write(Transaction.LEAF_VERSION_TAPSCRIPT);
            leafStream.writeBytes(new VarInt(leafScript.length).encode());
            leafStream.writeBytes(leafScript);
            tapLeafHash = Utils.taggedHash("TapLeaf", leafStream.toByteArray());
        }

        return tx.hashForUnifiedSignature(v.spentOutputs, v.inIdx, v.scriptType, scriptCode, (byte)v.hashType, null, tapLeafHash, null);
    }

    private static final class Vector {
        private String scriptCode;
        private String rawTx;
        private int inIdx;
        private int hashType;
        private UnifiedScriptType scriptType;
        private List<TransactionOutput> spentOutputs;
        private String sigHash;

        private Vector() {
        }

        private Vector(Vector other) {
            this.scriptCode = other.scriptCode;
            this.rawTx = other.rawTx;
            this.inIdx = other.inIdx;
            this.hashType = other.hashType;
            this.scriptType = other.scriptType;
            this.spentOutputs = other.spentOutputs;
            this.sigHash = other.sigHash;
        }
    }

    @SuppressWarnings("unchecked")
    private List<Vector> loadVectors() throws IOException {
        String json;
        try(InputStream inputStream = getClass().getResourceAsStream(FIXTURE)) {
            Assertions.assertNotNull(inputStream, "Missing fixture " + FIXTURE);
            json = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }

        Object parsed = new JsonParser(json).parse();
        Assertions.assertInstanceOf(List.class, parsed, "Expected a JSON array of rows");
        List<Object> rows = (List<Object>)parsed;

        //The first row names the columns, exactly as the reference's own test reads it
        List<Object> header = (List<Object>)rows.getFirst();
        Assertions.assertEquals(List.of("scriptCode", "rawTx", "inIdx", "hashType", "scriptType", "spentOutputs", "sighash"), header,
                "Fixture columns are not the ones this test reads");

        List<Vector> vectors = new ArrayList<>();
        for(Object row : rows.subList(1, rows.size())) {
            List<Object> columns = (List<Object>)row;
            Vector vector = new Vector();
            vector.scriptCode = (String)columns.get(0);
            vector.rawTx = (String)columns.get(1);
            vector.inIdx = ((Number)columns.get(2)).intValue();
            vector.hashType = ((Number)columns.get(3)).intValue();
            vector.scriptType = scriptTypeFor(((Number)columns.get(4)).intValue());
            vector.spentOutputs = new ArrayList<>();
            for(Object spent : (List<Object>)columns.get(5)) {
                List<Object> valueAndScript = (List<Object>)spent;
                long value = ((Number)valueAndScript.get(0)).longValue();
                byte[] scriptBytes = Utils.hexToBytes((String)valueAndScript.get(1));
                vector.spentOutputs.add(new TransactionOutput(null, value, scriptBytes));
            }
            vector.sigHash = (String)columns.get(6);
            vectors.add(vector);
        }

        return vectors;
    }

    /**
     * A minimal reader for the fixture, present for the same reason BlockHeaderPoWHashTest carries one:
     * so reading a test fixture does not add a JSON dependency to the library.
     */
    private static final class JsonParser {
        private final String json;
        private int pos;

        private JsonParser(String json) {
            this.json = json;
        }

        private Object parse() {
            Object value = readValue();
            skipWhitespace();
            if(pos != json.length()) {
                throw new IllegalArgumentException("Trailing content at position " + pos);
            }

            return value;
        }

        private Object readValue() {
            skipWhitespace();
            char c = json.charAt(pos);
            if(c == '[') {
                return readArray();
            }
            if(c == '"') {
                return readString();
            }

            return readNumber();
        }

        private List<Object> readArray() {
            List<Object> values = new ArrayList<>();
            pos++; //[
            skipWhitespace();
            if(json.charAt(pos) == ']') {
                pos++;
                return values;
            }

            while(true) {
                values.add(readValue());
                skipWhitespace();
                char c = json.charAt(pos++);
                if(c == ']') {
                    return values;
                }
                if(c != ',') {
                    throw new IllegalArgumentException("Expected , or ] at position " + (pos - 1));
                }
            }
        }

        private String readString() {
            pos++; //opening quote
            StringBuilder builder = new StringBuilder();
            while(true) {
                char c = json.charAt(pos++);
                if(c == '"') {
                    return builder.toString();
                }
                if(c == '\\') {
                    throw new IllegalArgumentException("Escapes are not used in this fixture");
                }
                builder.append(c);
            }
        }

        private Number readNumber() {
            int start = pos;
            while(pos < json.length() && "-+.eE0123456789".indexOf(json.charAt(pos)) >= 0) {
                pos++;
            }
            String text = json.substring(start, pos);
            if(text.isEmpty()) {
                throw new IllegalArgumentException("Expected a value at position " + start);
            }

            return Long.valueOf(text);
        }

        private void skipWhitespace() {
            while(pos < json.length() && Character.isWhitespace(json.charAt(pos))) {
                pos++;
            }
        }
    }

    /**
     * 0x20 and 0xa0 name no output type and consensus refuses both. Excluding them from the valid signing types is
     * not the same as making them unreachable: withUnified computes base | 0x20, so a bare ANYONECANPAY would reach
     * 0xa0 by that route. It is left alone instead.
     */
    @Test
    public void testTheTypesWithNoOutputTypeAreNeverProduced() {
        Assertions.assertEquals(SigHash.ANYONECANPAY, SigHash.ANYONECANPAY.withUnified(),
                "a bare ANYONECANPAY has no output type to opt in for");

        //Parsing one is not producing one: a PSBT may declare any byte, and 0xa0 is modelled so it can be read.
        //What must never happen is computing one from a type that did not already carry it.
        for(SigHash sigHash : SigHash.values()) {
            if(sigHash.isUnified()) {
                continue;
            }
            SigHash opted = sigHash.withUnified();
            Assertions.assertNotEquals((byte)0x20, opted.byteValue(), sigHash + " produced 0x20");
            Assertions.assertNotEquals((byte)0xa0, opted.byteValue(), sigHash + " produced 0xa0");
        }

        //The six that are valid still round trip through the opt-in
        for(SigHash sigHash : List.of(SigHash.ALL, SigHash.NONE, SigHash.SINGLE,
                SigHash.ANYONECANPAY_ALL, SigHash.ANYONECANPAY_NONE, SigHash.ANYONECANPAY_SINGLE)) {
            Assertions.assertTrue(SigHash.UNIFIED_SIGNING_TYPES.contains(sigHash.withUnified()),
                    sigHash + " must opt in to a valid type");
        }

        //DEFAULT carries no byte at all, so it opts in as ALL does
        Assertions.assertEquals(SigHash.UNIFIED_ALL, SigHash.DEFAULT.withUnified());
    }
}
