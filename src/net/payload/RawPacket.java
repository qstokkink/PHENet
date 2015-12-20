package net.payload;

import java.math.BigInteger;

/**
 * Class used to store received partial packets
 */
public class RawPacket {

	private final int sequenceNumber;
	private final BigInteger partKey;
	private final BigInteger keyHash;
	private final byte[] channelid;
	private final byte[] block;
	
	public RawPacket(int sequenceNumber, BigInteger partKey, BigInteger keyHash, byte[] channelid, byte[] block){
		this.sequenceNumber = sequenceNumber;
		this.partKey = partKey;
		this.keyHash = keyHash;
		this.channelid = channelid;
		this.block = block;
	}

	public int getSequenceNumber() {
		return sequenceNumber;
	}

	public BigInteger getPartKey() {
		return partKey;
	}
	
	public BigInteger getKeyHash() {
		return keyHash;
	}
	
	public byte[] getEncChannelId() {
		return channelid;
	}

	public byte[] getBlock() {
		return block;
	}
	
}
