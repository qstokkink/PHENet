package net.payload;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import crypto.impl.AES;
import crypto.impl.AESKey;
import crypto.impl.AESSplitter;
import crypto.impl.Paillier;
import crypto.impl.PaillierPrivateKey;
import crypto.impl.PaillierPublicKey;
import crypto.impl.PaillierSplitter;
import crypto.impl.SHA256;

public class Packer {

	/**
	 * This must be the same on the sending and receiving end
	 */
	private static int SYMM_KEY_SIZE = 256; 
	
	/**
	 * Pack and homomorphically partition data payloaded under AES
	 *  
	 * @param key The Public Key of the receiver
	 * @param partitions The amount of channels to partition for
	 * @param sequenceNumber The sequence number of this message block
	 * @param datablock The message (block)
	 * @return The shuffled homomorphically partitioned encrypted message set
	 * @throws IllegalBlockSizeException If the datablock is too big or small
	 */
	public static byte[][] pack(PaillierPublicKey key, int partitions, int sequenceNumber, byte[] datablock) throws IllegalBlockSizeException {
		// Generate a block key, partition and hash it
		AESKey K = new AESKey(SYMM_KEY_SIZE);
		BigInteger[] parts = PaillierSplitter.split(K.getKeyBigInteger(), key.getBitspace(), partitions, key.getN());
		for (int i = 0; i < parts.length; i++)
			parts[i] = Paillier.encode(key, parts[i]);
		BigInteger Khash = SHA256.hash(K.getKeyBigInteger());
		
		// Encode and split the data
		byte[] EKM = new byte[0];
		try {
			EKM = AES.encode(K, datablock);
		} catch (InvalidKeyException | BadPaddingException e1) {
			e1.printStackTrace();
		}
		byte[][] Mparts = AESSplitter.splitUniform(EKM, partitions);
		
		// Create packets equal to the requested amount of partitions
		List<byte[]> out = new ArrayList<>();
		for (int i = 0; i < partitions; i++){
			byte[] EKi = new byte[] {};
			try {
				EKi = AES.encode(K, ByteBuffer.allocate(4).putInt(i).array());
			} catch (InvalidKeyException | IllegalBlockSizeException
					| BadPaddingException e) {
				e.printStackTrace();
			}
			
			ByteBuffer bSeq = ByteBuffer.allocate(4).putInt(sequenceNumber);
			ByteBuffer bHomo = ByteBuffer.allocate(key.getBitspace()+1).put(packBigInteger(parts[i], key.getBitspace()+1));
			ByteBuffer bHash = ByteBuffer.allocate(32).put(packBigInteger(Khash, 32));
			ByteBuffer bKi = ByteBuffer.allocate(16).put(EKi);
			ByteBuffer bEKMi = ByteBuffer.wrap(Mparts[i]);
			
			int size = 4 + bSeq.capacity() +
					bHomo.capacity() +
					bHash.capacity() +
					bKi.capacity() +
					bEKMi.capacity();
			
			ByteBuffer bOut = ByteBuffer.allocate(size).putInt(size)
										.put(bSeq.array())
										.put(bHomo.array())
										.put(bHash.array())
										.put(bKi.array())
										.put(bEKMi.array());
			out.add(bOut.array());
		}
		// Finally shuffle the array, such that reordering the partitions of 
		// an encrypted message M is not dependent on timing
		Collections.shuffle(out);
		return out.toArray(new byte[partitions][]);
	}
	
	/**
	 * Read in a single RawPacket from a stream
	 * 
	 * @param key The Private Key for decoding
	 * @param is The stream
	 * @return The container for the read packet
	 * @throws IOException If the stream could not be read/was corrupted
	 */
	public static RawPacket read(PaillierPrivateKey key, InputStream is) throws IOException{
		byte[] bSize = new byte[4];
		if (is.read(bSize) != 4)
			throw new EOFException("Reached end of stream while parsing packet size");
		int iSize = ByteBuffer.wrap(bSize).getInt();
		
		byte[] bSeq = new byte[4];
		if (is.read(bSeq) != 4)
			throw new EOFException("Reached end of stream while parsing packet sequence number");
		int iSeq = ByteBuffer.wrap(bSeq).getInt();
		
		byte[] bHomo = new byte[key.getBitspace()+1];
		if (is.read(bHomo) != bHomo.length)
			throw new EOFException("Reached end of stream while parsing homomorphicly encrypted key");
		BigInteger biHomo = new BigInteger(bHomo);
		
		byte[] bHash = new byte[32];
		if (is.read(bHash) != 32)
			throw new EOFException("Reached end of stream while parsing key hash");
		BigInteger biHash = new BigInteger(bHash);
		
		byte[] bKi = new byte[16];
		if (is.read(bKi) != 16)
			throw new EOFException("Reached end of stream while parsing encrypted sequence number");
		
		int remainder = iSize - bSize.length - bSeq.length - bHomo.length - bHash.length - bKi.length;
		byte[] bEKMi = new byte[remainder];
		if (is.read(bEKMi) != remainder)
			throw new EOFException("Reached end of stream while parsing encrypted data block");
		
		return new RawPacket(iSeq, biHomo, biHash, bKi, bEKMi);
	}
	
	/**
	 * Pack a BigInteger into a certain amount of bytes
	 */
	private static byte[] packBigInteger(BigInteger bi, int bytes){
		byte[] rep = bi.toByteArray();
		byte[] out = new byte[bytes];
		byte sign = (byte)(rep[0] & (byte) 0x80);
		if (sign > 0){
			// Expand by shifting the sign bit to the leftmost position
			rep[0] &= 0x7F;
			System.arraycopy(rep, 0, out, out.length - rep.length, rep.length);
			out[0] |= 0x80;
		} else {
			System.arraycopy(rep, 0, out, out.length - rep.length, rep.length);
		}
		return out;
	}
	
}
