package crypto.impl;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Class to encrypt and decrypt AES data.
 * Wraps the default Java AES implementation.
 */
public class AES {

	/**
	 * Encrypt data using a key
	 * @param key The secret key
	 * @param data The data to encrypt
	 */
	public static byte[] encode(AESKey key, byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		Cipher cipher;
		byte[] out;
		try {
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, key.getKey());
			out = cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new CryptoSupportError("AES");
		}
        return out;
	}
	
	/**
	 * Decrypt data using a key
	 * @param key The secret key
	 * @param data The data to decrypt
	 */
	public static byte[] decode(AESKey key, byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		Cipher cipher;
		byte[] out;
		try {
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, key.getKey());
			out = cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new CryptoSupportError("AES");
		}
        return out;
	}
	
}
