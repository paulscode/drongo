package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The one-off target shift at the BLAKE2b activation height.
 *
 * <p>The first test is the one that matters, and it is not a description of the code: the two compact targets in it were
 * read off the live BLAKE2b mainnet chain either side of block 961640. If the shift is wrong in any way the chain rejects,
 * this fails, because the value it produces has to be the value miners actually used.
 */
public class Blake2bDeploymentTest {
    /** The target in force for 961632-961639, the last blocks before the proof of work changed. */
    private static final long BITS_BEFORE_ACTIVATION = 0x1702353dL;

    /** The target block 961640 and everything after it actually carries, read from the chain. */
    private static final long BITS_AT_ACTIVATION = 0x1a008d4fL;

    @Test
    public void shiftReproducesTheLiveMainnetTarget() {
        assertEquals(BITS_AT_ACTIVATION, Blake2bDeployment.applyTargetShift(Network.MAINNET, BITS_BEFORE_ACTIVATION));
    }

    @Test
    public void shiftIsTwentyTwoDoublingsOfTheTarget() {
        BigInteger before = Utils.decodeCompactBits(BITS_BEFORE_ACTIVATION);
        BigInteger after = Utils.decodeCompactBits(BITS_AT_ACTIVATION);

        //Compact encoding keeps 23 bits of mantissa, so the ratio is 2^22 only up to that rounding. Comparing the shifted
        //value against the decoded result rather than dividing avoids asserting on the rounding itself.
        assertEquals(after, Utils.decodeCompactBits(Utils.encodeCompactBits(before.shiftLeft(22))));
    }

    @Test
    public void mainnetShiftsBy22AndTestnet4TakesKnotsDefaultOf20() {
        assertEquals(22, Blake2bDeployment.targetShift(Network.MAINNET));
        assertEquals(20, Blake2bDeployment.targetShift(Network.TESTNET4));
    }

    @Test
    public void activationHeightIsExactlyOneBlock() {
        assertFalse(Blake2bDeployment.isActivationHeight(Network.MAINNET, 961639));
        assertTrue(Blake2bDeployment.isActivationHeight(Network.MAINNET, 961640));
        assertFalse(Blake2bDeployment.isActivationHeight(Network.MAINNET, 961641));
    }

    @Test
    public void networksWithoutTheDeploymentNeverReachTheActivationHeight() {
        //Integer.MAX_VALUE rather than a flag, matching Knots, so no real height can equal it.
        assertFalse(Blake2bDeployment.isActivationHeight(Network.TESTNET, 961640));
        assertFalse(Blake2bDeployment.isActivationHeight(Network.SIGNET, 961640));
        assertFalse(Blake2bDeployment.isActivationHeight(Network.REGTEST, 961640));
    }

    @Test
    public void aTargetTooLargeToShiftIsPinnedToTheProofOfWorkLimit() {
        //Knots tests against powLimit >> shift and pins to powLimit rather than letting a 256-bit shift wrap. A target one
        //doubling above that threshold is the case the test is guarding: shifting it would exceed the limit.
        BigInteger powLimit = Network.MAINNET.getProofOfWorkLimit();
        long justOverThreshold = Utils.encodeCompactBits(powLimit.shiftRight(21));

        long shifted = Blake2bDeployment.applyTargetShift(Network.MAINNET, justOverThreshold);

        assertEquals(Utils.encodeCompactBits(powLimit), shifted);
        assertTrue(Utils.decodeCompactBits(shifted).compareTo(powLimit) <= 0, "a shifted target must never exceed the proof of work limit");
    }

    @Test
    public void aTargetAtTheThresholdStillShiftsRatherThanClamping() {
        BigInteger powLimit = Network.MAINNET.getProofOfWorkLimit();
        long atThreshold = Utils.encodeCompactBits(powLimit.shiftRight(22));

        long shifted = Blake2bDeployment.applyTargetShift(Network.MAINNET, atThreshold);

        assertTrue(Utils.decodeCompactBits(shifted).compareTo(powLimit) <= 0);
        assertEquals(Utils.decodeCompactBits(Utils.encodeCompactBits(Utils.decodeCompactBits(atThreshold).shiftLeft(22))),
                Utils.decodeCompactBits(shifted));
    }
}
