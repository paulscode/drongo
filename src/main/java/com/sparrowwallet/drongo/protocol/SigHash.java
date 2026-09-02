package com.sparrowwallet.drongo.protocol;

import java.util.List;

/**
 * These constants are a part of a scriptSig signature on the inputs. They define the details of how a
 * transaction can be redeemed, specifically, they control how the hash of the transaction is calculated.
 */
public enum SigHash {
    ALL("All", (byte)1),
    NONE("None", (byte)2),
    SINGLE("Single", (byte)3),
    ANYONECANPAY("Anyone Can Pay", (byte)0x80), // Caution: Using this type in isolation is non-standard. Treated similar to ANYONECANPAY_ALL.
    ANYONECANPAY_ALL("All + Anyone Can Pay", (byte)0x81),
    ANYONECANPAY_NONE("None + Anyone Can Pay", (byte)0x82),
    ANYONECANPAY_SINGLE("Single + Anyone Can Pay", (byte)0x83),
    DEFAULT("Default", (byte)0),
    UNIFIED_ANYONECANPAY("Anyone Can Pay + Unified", (byte)0xA0),
    UNIFIED_ALL("All + Unified", (byte)0x21),
    UNIFIED_NONE("None + Unified", (byte)0x22),
    UNIFIED_SINGLE("Single + Unified", (byte)0x23),
    UNIFIED_ANYONECANPAY_ALL("All + Anyone Can Pay + Unified", (byte)0xA1),
    UNIFIED_ANYONECANPAY_NONE("None + Anyone Can Pay + Unified", (byte)0xA2),
    UNIFIED_ANYONECANPAY_SINGLE("Single + Anyone Can Pay + Unified", (byte)0xA3);

    private final String name;
    public final byte value;

    /**
     * The opt-in bit selecting the unified signature hash. It is committed to with the rest of the byte,
     * so it cannot be added or removed by a third party without invalidating the signature.
     */
    public static final byte UNIFIED_FLAG = (byte)0x20;

    public static final List<SigHash> LEGACY_SIGNING_TYPES = List.of(ALL, NONE, SINGLE, ANYONECANPAY_ALL, ANYONECANPAY_NONE, ANYONECANPAY_SINGLE);
    public static final List<SigHash> TAPROOT_SIGNING_TYPES = List.of(DEFAULT, ALL, NONE, SINGLE, ANYONECANPAY_ALL, ANYONECANPAY_NONE, ANYONECANPAY_SINGLE);
    public static final List<SigHash> UNIFIED_SIGNING_TYPES = List.of(UNIFIED_ALL, UNIFIED_NONE, UNIFIED_SINGLE, UNIFIED_ANYONECANPAY_ALL, UNIFIED_ANYONECANPAY_NONE, UNIFIED_ANYONECANPAY_SINGLE);

    private SigHash(final String name, final byte value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
        return name;
    }

    /**
     * @return the value as a byte
     */
    public byte byteValue() {
        return this.value;
    }

    public int intValue() {
        return Byte.toUnsignedInt(value);
    }

    public boolean anyoneCanPay() {
        return (value & SigHash.ANYONECANPAY.value) != 0;
    }

    /**
     * @return whether this hash type opts in to the unified signature hash
     */
    public boolean isUnified() {
        return (value & UNIFIED_FLAG) != 0;
    }

    /**
     * @return this hash type with the opt-in bit set, or itself if it already carries it
     */
    public SigHash withUnified() {
        if(isUnified()) {
            return this;
        }

        //DEFAULT appends no hash type byte, so there is nothing to carry the bit. It means the same
        //signature as ALL once a byte is present, which is what an opted-in taproot spend uses.
        byte base = (this == DEFAULT ? ALL.value : value);

        //0x20 and 0xa0 name no output type and consensus refuses both, so a bare ANYONECANPAY is left as it is
        //rather than handed a bit that would make it invalid under either rule set. Keeping them out of the list of
        //valid signing types is not the same as making them unreachable, and this is the path that reaches them.
        int outputType = base & 0x1f;
        if(outputType < ALL.value || outputType > SINGLE.value) {
            return this;
        }

        return fromByte((byte)(base | UNIFIED_FLAG));
    }

    /**
     * @return this hash type with the opt-in bit cleared, or itself if it does not carry it
     */
    public SigHash withoutUnified() {
        return isUnified() ? fromByte((byte)(value & ~UNIFIED_FLAG)) : this;
    }

    public static SigHash fromByte(byte sigHashByte) {
        for(SigHash value : SigHash.values()) {
            if(sigHashByte == value.byteValue()) {
                return value;
            }
        }

        throw new IllegalArgumentException("No defined sighash value for byte " + sigHashByte);
    }

    @Override
    public String toString() {
        return getName();
    }
}
