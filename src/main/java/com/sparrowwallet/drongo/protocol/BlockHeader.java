package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Date;

import static com.sparrowwallet.drongo.Utils.uint32ToByteStreamLE;

public class BlockHeader extends Message {
    private long version;
    private Sha256Hash prevBlockHash;
    private Sha256Hash merkleRoot, witnessRoot;
    private long time;
    private long difficultyTarget; // "nBits"
    private long nonce;

    //Null on a v1 header, which is every header on a chain that has not
    //activated BLAKE2b. Set when bit 31 of the version field is, which is the
    //only signal the format gives and the same one Bitcoin Knots branches on.
    //All of the format's specifics live in BlockHeaderV2; see that class.
    private BlockHeaderV2 v2;

    //The time field as serialized. Equal to nTime except on a v2 header whose
    //miner rolls time, where nTime is this plus an offset. Kept rather than
    //recomputed so serialization round-trips exactly.
    private long timeOnWire;

    public BlockHeader(byte[] rawheader) {
        super(rawheader, 0);
    }

    public BlockHeader(byte[] blockdata, int offset) {
        super(blockdata, offset);
    }

    public BlockHeader(long version, Sha256Hash prevBlockHash, Sha256Hash merkleRoot, Sha256Hash witnessRoot, long time, long difficultyTarget, long nonce) {
        this.version = version;
        this.prevBlockHash = prevBlockHash;
        this.merkleRoot = merkleRoot;
        this.witnessRoot = witnessRoot;
        this.time = time;
        this.difficultyTarget = difficultyTarget;
        this.nonce = nonce;
    }

    @Override
    protected void parse() throws ProtocolException {
        version = readUint32();
        prevBlockHash = readHash();
        merkleRoot = readHash();
        time = readUint32();
        difficultyTarget = readUint32();
        nonce = readUint32();

        //A v2 header's first 80 bytes are byte-for-byte a v1 header, so the
        //fields above are already correct and only the remainder is new. Bit 31
        //of the version is the marker; it is not part of the version number, so
        //it is stripped from what callers see.
        if((version & BlockHeaderV2.VERSION_HEADER_V2_FLAG) != 0) {
            v2 = BlockHeaderV2.parse(payload, offset);
            version &= ~BlockHeaderV2.VERSION_HEADER_V2_FLAG;
            cursor = offset + BlockHeaderV2.HEADER_V2_LENGTH;
            //nTime may be the wire value plus an offset on a v2 header, so keep
            //both: nTime is what consensus and the median-time-past rule use,
            //the wire value is what is serialized and hashed.
            timeOnWire = time;
            time = v2.getTime(timeOnWire);
        }

        length = cursor - offset;
    }

    /** The BLAKE2b extras, or null on an ordinary 80 byte header. */
    public BlockHeaderV2 getV2() {
        return v2;
    }

    public boolean isV2() {
        return v2 != null;
    }

    /** The version field as serialized, including the v2 marker bit. */
    private long getCompleteVersion() {
        return v2 == null ? version : (version | BlockHeaderV2.VERSION_HEADER_V2_FLAG);
    }

    public long getVersion() {
        return version;
    }

    public Sha256Hash getPrevBlockHash() {
        return prevBlockHash;
    }

    public Sha256Hash getMerkleRoot() {
        return merkleRoot;
    }

    public Sha256Hash getWitnessRoot() {
        return witnessRoot;
    }

    public long getTime() {
        return time;
    }

    public Date getTimeAsDate() {
        return new Date(time * 1000);
    }

    public long getDifficultyTarget() {
        return difficultyTarget;
    }

    public long getNonce() {
        return nonce;
    }

    public Sha256Hash getHash() {
        if(v2 != null) {
            //Not SHA256d over the header bytes: on this chain the block hash is
            //a staged BLAKE2b computation. Returned in display order, which is
            //what Sha256Hash.wrap expects, hence wrap rather than wrapReversed.
            return Sha256Hash.wrap(v2.computeHashDisplayOrder(getCompleteVersion(),
                    prevBlockHash.getBytes(), merkleRoot.getReversedBytes(), getTimeOnWire(),
                    difficultyTarget, nonce));
        }
        return Sha256Hash.wrapReversed(Sha256Hash.hashTwice(bitcoinSerialize()));
    }

    /** The time field as serialized, which differs from nTime only on a v2 header that rolls time. */
    private long getTimeOnWire() {
        return v2 == null ? time : timeOnWire;
    }

    public BigInteger getDifficultyTargetAsInteger() {
        return Utils.decodeCompactBits(difficultyTarget);
    }

    /**
     * Checks the header hash meets its own claimed difficulty target, and that the target does not exceed the network proof of work limit.
     */
    public boolean verifyProofOfWork() {
        BigInteger target = getDifficultyTargetAsInteger();
        if(target.signum() <= 0 || target.compareTo(Network.get().getProofOfWorkLimit()) > 0) {
            return false;
        }

        return getHash().toBigInteger().compareTo(target) <= 0;
    }

    public byte[] bitcoinSerialize() {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            bitcoinSerializeToStream(outputStream);
            return outputStream.toByteArray();
        } catch(IOException e) {
            //can't happen
        }

        return null;
    }

    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        uint32ToByteStreamLE(getCompleteVersion(), stream);
        stream.write(prevBlockHash.getReversedBytes());
        stream.write(merkleRoot.getReversedBytes());
        uint32ToByteStreamLE(getTimeOnWire(), stream);
        uint32ToByteStreamLE(difficultyTarget, stream);
        uint32ToByteStreamLE(nonce, stream);
        if(v2 != null) {
            v2.serializeToStream(stream);
        }
    }
}
