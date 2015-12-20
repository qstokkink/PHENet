package crypto.impl;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Class to store and generate AES keys
 */
public class AESKey {

	private SecretKey key;
	
	/**
	 * Generate a new AES key with a certain key size
	 */
	public AESKey(int keysize){
		this.key = generate(keysize);
	}
	
	/**
	 * Construct an AES key from a key in byte form
	 */
	public AESKey(byte[] key){
		this.key = new SecretKeySpec(key, "AES");
	}
	
	/**
	 * Construct an AES key from a key in BigInteger form
	 * 
	 * Keys can be too long because they were padded for Paillier
	 * Keys can also be too short because the BigInteger throws away redundant bits
	 */
	public AESKey(BigInteger key){
		byte[] brep = key.toByteArray();
		if (brep.length > 32){
			byte[] rkey = new byte[32];
			System.arraycopy(brep, 1, rkey, 0, 32);
			this.key = new SecretKeySpec(rkey, "AES");
		} else if (brep.length == 32)  {
			this.key = new SecretKeySpec(brep, "AES");
		} else {
			byte[] rkey = new byte[32];
			System.arraycopy(brep, 0, rkey, rkey.length - brep.length, brep.length);
			this.key = new SecretKeySpec(rkey, "AES");
		}
	}
	
	/**
	 * Fetch the actual key, which can be used with Java's Cipher implementation
	 * @return
	 */
	public SecretKey getKey(){
		return key;
	}
	
	/**
	 * Retrieve the key as a BigInteger
	 * 
	 * Because hashing "doesn't work" with negative numbers
	 * pad the BigInteger such that the sign bit is "removed"
	 */
	public BigInteger getKeyBigInteger(){
		byte[] bytes = key.getEncoded();
		if ((bytes[0] & 0x80) > 0){
			byte[] out = new byte[bytes.length + 1];
			System.arraycopy(bytes, 0, out, 1, bytes.length);
			return new BigInteger(out);
		}
		return new BigInteger(bytes);
	}
	
	/**
	 * Generate an AES key with a certain bit size
	 */
	private static SecretKey generate(int bits){
		KeyGenerator generator;
		try {
			generator = KeyGenerator.getInstance("AES");
			generator.init(bits);
			return generator.generateKey();
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoSupportError("AES");
		}
	}
	
}
