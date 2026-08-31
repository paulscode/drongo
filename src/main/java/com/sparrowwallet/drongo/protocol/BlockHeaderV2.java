package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Utils;
import org.bouncycastle.crypto.digests.Blake2bDigest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The extra fields of a BLAKE2b block header, and the hash that identifies it.
 *
 * Introduced by Bitcoin Knots PR #359. A v2 header is 164 bytes rather than 80,
 * and its block hash is a staged BLAKE2b computation rather than SHA256d over
 * the header bytes. Both are consensus, so on a chain that has activated it
 * neither length nor hash can be assumed.
 *
 * <p>Everything specific to the format lives in this class so that removing it
 * later is a file deletion plus a handful of small reverts in {@link BlockHeader},
 * rather than unpicking changes spread across the protocol package. The first
 * six fields of a v2 header are byte-for-byte a v1 header, which is what lets
 * {@link BlockHeader} own them and this class own only the remainder.
 *
 * <p>The format is self-describing: bit 31 of the version field, in the first
 * four bytes, marks v2. A stream mixing both versions is therefore walkable
 * without anyone agreeing an activation height, and Bitcoin Knots itself
 * branches on exactly that bit with no height gate.
 *
 * <p>This is a port of a Rust implementation checked against two independent
 * oracles: the five vectors Knots publishes in {@code block_header_v2.json},
 * compared stage by stage, and headers taken off the live testnet4 chain.
 */
public class BlockHeaderV2 {
    /** Bit 31 of the version field. Knots' {@code VERSION_HEADER_V2_FLAG}. */
    public static final long VERSION_HEADER_V2_FLAG = 0x80000000L;

    public static final int HEADER_V1_LENGTH = 80;
    public static final int HEADER_V2_LENGTH = 164;

    /** Bit 2 of {@code m_flags}: the miner rolls nTime via {@code m_time_offset}. */
    private static final int FLAG_USE_TIME_OFFSET = 0x04;

    private final long nonce2;
    private final long nonce3;
    private final byte[] extranonce;    //16
    private final long timeOffset;
    private final int txcount;
    private final int flags;
    private final int xorKeyMaskClearBits;
    private final byte[] xorKey;        //16
    private final long height;
    private final byte[] mmRhs;         //32

    private BlockHeaderV2(long nonce2, long nonce3, byte[] extranonce, long timeOffset, int txcount,
                          int flags, int xorKeyMaskClearBits, byte[] xorKey, long height, byte[] mmRhs) {
        this.nonce2 = nonce2;
        this.nonce3 = nonce3;
        this.extranonce = extranonce;
        this.timeOffset = timeOffset;
        this.txcount = txcount;
        this.flags = flags;
        this.xorKeyMaskClearBits = xorKeyMaskClearBits;
        this.xorKey = xorKey;
        this.height = height;
        this.mmRhs = mmRhs;
    }

    /** Is the header starting at this offset a v2 one? Reads only the version field. */
    public static boolean isV2(byte[] data, int offset) {
        if(data.length < offset + 4) {
            return false;
        }
        long version = Utils.readUint32(data, offset);
        return (version & VERSION_HEADER_V2_FLAG) != 0;
    }

    /** The length of the header starting at this offset: 80 or 164, from its version field alone. */
    public static int headerLength(byte[] data, int offset) {
        return isV2(data, offset) ? HEADER_V2_LENGTH : HEADER_V1_LENGTH;
    }

    /**
     * Parse the fields that follow the first 80 bytes.
     *
     * @param offset the offset of the header itself, not of the extra fields
     */
    static BlockHeaderV2 parse(byte[] data, int offset) throws ProtocolException {
        if(data.length < offset + HEADER_V2_LENGTH) {
            throw new ProtocolException("Truncated v2 block header: need " + HEADER_V2_LENGTH
                    + " bytes at offset " + offset + ", have " + (data.length - offset));
        }
        int p = offset + HEADER_V1_LENGTH;
        long nonce2 = Utils.readUint32(data, p);
        long nonce3 = Utils.readUint32(data, p + 4);
        byte[] extranonce = slice(data, p + 8, 16);
        long timeOffset = Utils.readUint32(data, p + 24);
        int txcount = (data[p + 28] & 0xff) | ((data[p + 29] & 0xff) << 8);
        int flags = data[p + 30] & 0xff;
        int clearBits = data[p + 31] & 0xff;
        byte[] xorKey = slice(data, p + 32, 16);
        long height = Utils.readUint32(data, p + 48);
        byte[] mmRhs = slice(data, p + 52, 32);
        return new BlockHeaderV2(nonce2, nonce3, extranonce, timeOffset, txcount, flags, clearBits, xorKey, height, mmRhs);
    }

    void serializeToStream(OutputStream stream) throws IOException {
        Utils.uint32ToByteStreamLE(nonce2, stream);
        Utils.uint32ToByteStreamLE(nonce3, stream);
        stream.write(extranonce);
        Utils.uint32ToByteStreamLE(timeOffset, stream);
        stream.write(txcount & 0xff);
        stream.write((txcount >> 8) & 0xff);
        stream.write(flags);
        stream.write(xorKeyMaskClearBits);
        stream.write(xorKey);
        Utils.uint32ToByteStreamLE(height, stream);
        stream.write(mmRhs);
    }

    /** The consensus-committed height, which a v1 header does not carry. */
    public long getHeight() {
        return height;
    }

    /** The consensus-committed transaction count. Fixes CVE-2017-12842. */
    public int getTxCount() {
        return txcount;
    }

    /** Low two bits of {@code m_flags}: which layout the mining hardware sees. */
    public int getAsicProfile() {
        return flags & 3;
    }

    /**
     * nTime, which on a v2 header may be the wire value plus an offset.
     *
     * @param timeOnWire the time field as serialized
     */
    public long getTime(long timeOnWire) {
        if((flags & FLAG_USE_TIME_OFFSET) != 0) {
            return (timeOnWire + timeOffset) & 0xffffffffL;
        }
        return timeOnWire;
    }

    /**
     * The block hash, in display order.
     *
     * <p>Mirrors {@code CBlockHeader::GetHash()} in {@code src/primitives/block.cpp}.
     * Not SHA256d over the header bytes: a staged computation ending in two
     * BLAKE2b passes, XORed with a mask derived from the miner's key.
     *
     * @param completeVersion the version field including bit 31
     * @param prevBlockHashDisplay the previous block hash, display order
     * @param merkleRootWire the merkle root in wire (little-endian) order
     * @param timeOnWire the time field as serialized
     * @param difficultyTarget nBits
     * @param nonce nNonce
     */
    byte[] computeHashDisplayOrder(long completeVersion, byte[] prevBlockHashDisplay, byte[] merkleRootWire,
                                   long timeOnWire, long difficultyTarget, long nonce) {
        byte[] xorKeyHash = tagged("Bitcoin block hash PoW XOR key", xorKey);

        byte[] mask = new byte[32];
        if(!isAllZero(xorKey)) {
            mask = tagged("Bitcoin block hash PoW XOR mask", xorKey);
            int clearBytes = xorKeyMaskClearBits / 8;
            for(int i = 0; i < clearBytes; i++) {
                mask[i] = 0;
            }
            mask[clearBytes] &= (byte)(0xff >>> (xorKeyMaskClearBits % 8));
        }

        //Reserved byte after the time field, for a future 40-bit time.
        ByteArrayOutputStream h1p = new ByteArrayOutputStream(119);
        writeUint32LE(h1p, completeVersion);
        h1p.write(prevBlockHashDisplay, 0, 32);
        writeUint32LE(h1p, height);
        h1p.write(merkleRootWire, 0, 32);
        writeUint32LE(h1p, timeOnWire);
        h1p.write(0);
        writeUint32LE(h1p, difficultyTarget);
        writeUint32LE(h1p, txcount);
        h1p.write(flags);
        h1p.write(xorKeyMaskClearBits);
        h1p.write(xorKeyHash, 0, 32);
        byte[] h1 = tagged("Bitcoin block header 1", h1p.toByteArray());

        ByteArrayOutputStream h2p = new ByteArrayOutputStream(0x60);
        h2p.write(h1, 0, 32);
        h2p.write(new byte[32], 0, 32);     //two null uint128s
        h2p.write(mmRhs, 0, 32);
        byte[] h2 = tagged("Merge-mining hook", h2p.toByteArray());

        ByteArrayOutputStream ss = new ByteArrayOutputStream(52);
        writeUint32LE(ss, 0);
        ss.write(h2, 0, 32);
        ss.write(extranonce, 0, 16);
        byte[] blake1 = blake2b256(ss.toByteArray());

        //The layout the mining hardware sees. Four profiles, because different
        //vendors' devices expect the fields in different orders.
        ByteArrayOutputStream asic = new ByteArrayOutputStream(160);
        int profile = getAsicProfile();
        if(profile == 0) {
            byte[] prevHidden = tagged("Bitcoin prevblock header, hashed", prevBlockHashDisplay);
            for(int i = 0; i < 6; i++) {
                prevHidden[i] = 0;
            }
            asic.write(prevHidden, 0, 32);
            writeUint32LE(asic, nonce);
            writeUint32LE(asic, nonce2);
            writeUint32LE(asic, timeOffset);
            writeUint32LE(asic, nonce3);
            asic.write(blake1, 0, 32);
        } else if(profile == 1) {
            writeUint32LE(asic, nonce);
            writeUint32LE(asic, nonce2);
            writeUint32LE(asic, nonce3);
            writeUint32LE(asic, timeOffset);
            asic.write(blake1, 0, 32);
            asic.write(h2, 0, 32);
        } else {
            if(profile == 3) {
                asic.write(new byte[32], 0, 32);
            }
            asic.write(new byte[48], 0, 48);
            asic.write(h2, 0, 32);
            writeUint32LE(asic, nonce);
            writeUint32LE(asic, nonce2);
            writeUint32LE(asic, timeOffset);
            writeUint32LE(asic, nonce3);
            asic.write(blake1, 0, 32);
        }
        byte[] blake2 = blake2b256(asic.toByteArray());

        byte[] out = new byte[32];
        for(int i = 0; i < 32; i++) {
            out[i] = (byte)(blake2[i] ^ mask[i]);
        }
        return out;
    }

    /**
     * BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || payload).
     *
     * <p>The doubled tag digest is what Knots' {@code BytesWritten() == 0x40 + n}
     * assertion pins.
     */
    private static byte[] tagged(String tag, byte[] payload) {
        MessageDigest sha = sha256();
        byte[] t = sha.digest(tag.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        sha.reset();
        sha.update(t);
        sha.update(t);
        sha.update(payload);
        return sha.digest();
    }

    /**
     * Unkeyed BLAKE2b with a 32-byte digest.
     *
     * <p>The digest length is part of BLAKE2b's parameter block, so this is not
     * a truncation of the 64-byte variant and the two do not agree.
     */
    private static byte[] blake2b256(byte[] data) {
        Blake2bDigest digest = new Blake2bDigest(256);
        digest.update(data, 0, data.length);
        byte[] out = new byte[32];
        digest.doFinal(out, 0);
        return out;
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch(NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  //every JRE has SHA-256
        }
    }

    private static void writeUint32LE(ByteArrayOutputStream out, long value) {
        out.write((int)(value & 0xff));
        out.write((int)((value >> 8) & 0xff));
        out.write((int)((value >> 16) & 0xff));
        out.write((int)((value >> 24) & 0xff));
    }

    private static byte[] slice(byte[] data, int offset, int length) {
        byte[] out = new byte[length];
        System.arraycopy(data, offset, out, 0, length);
        return out;
    }

    private static boolean isAllZero(byte[] data) {
        for(byte b : data) {
            if(b != 0) {
                return false;
            }
        }
        return true;
    }
}
