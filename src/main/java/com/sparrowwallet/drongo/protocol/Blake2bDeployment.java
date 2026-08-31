package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;

import java.math.BigInteger;

/**
 * Where the BLAKE2b proof-of-work change activates on each network, and the one-off target shift that comes with it.
 *
 * <p>Mirrors Bitcoin Knots' {@code Consensus::Params::Blake2bHeight} and {@code Blake2bTargetShift}, read from
 * {@code src/kernel/chainparams.cpp} at tag {@code v29.4.1.knots20260508rc4}. The values are consensus, not preference:
 * getting the shift wrong means rejecting the real chain or accepting a chain with less work than it claims.
 *
 * <p>The activation height is not used to decide whether a header is v2 — that is read from bit 31 of the version field,
 * which is self-describing, so a client does not need to know the height to parse. It is needed here because the
 * difficulty rule changes exactly once, at that height.
 */
public class Blake2bDeployment {
    /** Not deployed on this network. */
    private static final int NOT_DEPLOYED = Integer.MAX_VALUE;

    /**
     * The height of the first block mined under BLAKE2b, or {@link #NOT_DEPLOYED}.
     *
     * <p>Mainnet activated at 961640 on 30 August 2026. The two mainnet chains part earlier than this, at 961632, where
     * BIP110 activated; 961640 is where the proof of work changes.
     *
     * <p>Regtest sets its own with {@code -testactivationheight} and a wallet cannot know it, so the shift is not applied
     * there. That costs nothing: regtest uses the relaxed difficulty rule, which accepts each header's own target.
     */
    public static int activationHeight(Network network) {
        return switch(network) {
            case MAINNET -> 961640;
            case TESTNET4 -> 150308;
            default -> NOT_DEPLOYED;
        };
    }

    /**
     * How far left the target moves at the activation height, as a power of two.
     *
     * <p>Knots defaults this to 20 and overrides it to 22 for mainnet, so testnet4 takes the default. Only mainnet's
     * value is reachable today: {@code HeaderChainState} applies the full difficulty rule to mainnet and signet alone,
     * and signet has no BLAKE2b deployment. Testnet4's is recorded so that enabling the full rule there later is a
     * change of one condition rather than a hunt for a constant.
     */
    public static int targetShift(Network network) {
        return network == Network.MAINNET ? 22 : 20;
    }

    /** Is this the height of the first block mined under BLAKE2b on this network? */
    public static boolean isActivationHeight(Network network, int height) {
        return height == activationHeight(network);
    }

    /**
     * The target a block at the activation height is required to use, given what the ordinary rule produced.
     *
     * <p>A direct port of {@code ApplyBlake2bTargetShift} in Knots' {@code src/pow.cpp}. The proof of work changes
     * algorithm at this height, so the difficulty carried over from SHA256d no longer describes the work available, and
     * the target is eased once by a fixed amount rather than waiting for a retarget to discover it.
     *
     * <p>The clamp is the reason this cannot be written as a plain shift. Knots works in 256-bit arithmetic, where
     * shifting a large target left would wrap; it tests against {@code powLimit >> shift} first and pins the result to
     * {@code powLimit} when the shift would exceed it. Reproducing the test rather than the overflow is what keeps this
     * faithful on a network whose target is already near the limit.
     *
     * <p>Applied after the ordinary rule, not instead of it, exactly as Knots does: at a period boundary the retarget is
     * computed first and the shift lands on its result.
     */
    public static long applyTargetShift(Network network, long compactBits) {
        int shift = targetShift(network);
        BigInteger powLimit = network.getProofOfWorkLimit();
        BigInteger target = Utils.decodeCompactBits(compactBits);

        BigInteger shifted = target.compareTo(powLimit.shiftRight(shift)) > 0 ? powLimit : target.shiftLeft(shift);

        return Utils.encodeCompactBits(shifted);
    }
}
