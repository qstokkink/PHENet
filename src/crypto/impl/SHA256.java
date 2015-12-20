package crypto.impl;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Class to hash data.
 * Wraps the default Java SHA-256 implementation.
 */
public class SHA256 {

	/**
	 * Calculate the SHA-256 hash of some number
	 */
	public static BigInteger hash(BigInteger data){
		return new BigInteger(hash(data.toByteArray()));
	}
	
	/**
	 * Calculate the SHA-256 hash of some data
	 */
	public static byte[] hash(byte[] data){
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			return digest.digest(data);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoSupportError("SHA-256");
		}
	}
	
	/**
	 * Test whether the hash of the given data matches the given hash
	 */
	public static boolean test(byte[] data, byte[] hash){
		return Arrays.equals(hash(data), hash);
	}
	
}
