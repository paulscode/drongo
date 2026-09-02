package com.sparrowwallet.drongo;

import com.sparrowwallet.drongo.protocol.Sha256Hash;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Random;

/**
 * Proves that {@link Utils#taggedHash(String, byte[])} implements the BIP-340 tagged hash
 * construction: SHA256(SHA256(tag) || SHA256(tag) || msg).
 */
public class TaggedHashAgreementTest {
    @Test
    public void testAgreesWithBip340ConstructionForVariousMessages() {
        String tag = "Bitcoin block header 1";

        byte[] empty = new byte[0];
        assertMatchesBip340Construction(tag, empty);

        byte[] sequential = new byte[32];
        for(int i = 0; i < sequential.length; i++) {
            sequential[i] = (byte)i;
        }
        assertMatchesBip340Construction(tag, sequential);

        byte[] fixedRandom = new byte[100];
        new Random(42).nextBytes(fixedRandom);
        assertMatchesBip340Construction(tag, fixedRandom);
    }

    @Test
    public void testBip0340ChallengeTagAgreesWithConstruction() {
        assertMatchesBip340Construction("BIP0340/challenge", new byte[0]);
    }

    private void assertMatchesBip340Construction(String tag, byte[] msg) {
        byte[] tagHash = Sha256Hash.hash(tag.getBytes(StandardCharsets.UTF_8));
        ByteBuffer buffer = ByteBuffer.allocate(tagHash.length + tagHash.length + msg.length);
        buffer.put(tagHash);
        buffer.put(tagHash);
        buffer.put(msg);
        byte[] expected = Sha256Hash.hash(buffer.array());

        Assertions.assertArrayEquals(expected, Utils.taggedHash(tag, msg));
    }
}
