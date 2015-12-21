package net.payload;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import crypto.impl.AES;
import crypto.impl.AESKey;
import crypto.impl.Paillier;
import crypto.impl.PaillierPrivateKey;
import crypto.impl.SHA256;

/**
 * Class to combine RawPackets and decode them into a message
 */
public class PacketCombiner {

	private final int sequenceNumber;
	private List<RawPacket> packets = new ArrayList<RawPacket>();
	private BigInteger Kt = BigInteger.ONE;
	private BigInteger Khash = null;
	
	private BigInteger n2;
	private Paillier paillier;
	
	/**
	 * Link this combiner to a certain sequence number
	 */
	public PacketCombiner(PaillierPrivateKey key, int sequenceNumber){
		this.sequenceNumber = sequenceNumber;
		this.paillier = new Paillier(key);
		this.n2 = key.getN().multiply(key.getN());
	}
	
	/**
	 * Combine another raw packet and see if the message can be constructed yet
	 * 
	 * @param p The packet to add
	 * @return Whether the block of this sequence number is complete
	 * @throws IllegalPacketException If the packet is malformed
	 */
	public boolean read(RawPacket p) throws IllegalPacketException{
		if (sequenceNumber != p.getSequenceNumber())
			throw new IllegalPacketException("Tried to combine packet with seq.no. " + p.getSequenceNumber() + 
												" into " + sequenceNumber);
		if (Khash != null && !Khash.equals(p.getKeyHash()))
			throw new IllegalPacketException("Tried to combine packet with different hash");
		if (Khash == null){
			Khash = p.getKeyHash();
		}
		
		Kt = Kt.multiply(p.getPartKey()).mod(n2);
		packets.add(p);
		return SHA256.test(paillier.decode(Kt).toByteArray(), Khash.toByteArray());
	}
	
	/**
	 * Decrypt the message formed by all read partial packets
	 * 
	 * @return The decrypted message
	 * @throws InvalidKeyException If the AES key decoded incorrectly
	 * @throws IllegalBlockSizeException If the data blocks were malformed
	 * @throws BadPaddingException If the data blocks were malformed
	 */
	public byte[] finish() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		AESKey K = new AESKey(paillier.decode(Kt));
		// Reorder the encrypted message
		RawPacket[] ordered = new RawPacket[packets.size()];
		int size = 0;
		for (RawPacket packet : packets){
			int i = ByteBuffer.wrap(AES.decode(K, packet.getEncChannelId())).getInt();
			ordered[i] = packet;
			size += packet.getBlock().length;
		}
		// Then decode the actual message
		byte[] enc = new byte[size];
		int enci = 0;
		for (int i = 0; i < ordered.length; i++){
			byte[] eblock = ordered[i].getBlock();
			System.arraycopy(eblock, 0, enc, enci, eblock.length);
			enci += eblock.length;
		}
		return AES.decode(K, enc);
	}
}
