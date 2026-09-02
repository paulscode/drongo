package com.sparrowwallet.drongo.protocol;

/**
 * The script type byte the unified signature hash commits to, which domain separates the four script
 * types so a signature made for one can never be valid for another.
 *
 * Deliberately not defaulted anywhere it is switched on: a script version added later must be given
 * its own value rather than silently sharing the one for bare inputs, which would be a cross type
 * collision of exactly the kind this byte exists to prevent.
 */
public enum UnifiedScriptType {
    /**
     * Bare and P2SH.
     */
    BARE((byte)0),
    WITNESS_V0((byte)1),
    /**
     * Taproot key path.
     */
    TAPROOT((byte)2),
    TAPSCRIPT((byte)3);

    private final byte value;

    UnifiedScriptType(byte value) {
        this.value = value;
    }

    public byte byteValue() {
        return value;
    }

    /**
     * @return whether this script type reads the hash type byte under BIP341's rule rather than the legacy one
     */
    public boolean isTaproot() {
        return this == TAPROOT || this == TAPSCRIPT;
    }
}
