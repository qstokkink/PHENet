package crypto.impl;

import java.math.BigInteger;
import java.security.SecureRandom;

public class MultiplicativeSplitter {

	/**
	 * Split plaintext into multiple plaintexts for multiplicative homomorphism
	 * 
	 * @param data The plaintext to split
	 * @param keysize The keysize in bits, of the modulus
	 * @param amount The amount of partitions to create
	 * @param n The modulus
	 * @return The partial plaintexts 
	 */
	public static BigInteger[] split(BigInteger data, int keysize, int amount, BigInteger n){
		assert(amount > 1);
		BigInteger[] out = new BigInteger[amount];
		BigInteger total = BigInteger.ONE;
		SecureRandom sr = new SecureRandom();
		for (int i = 1; i < amount; i++){
			out[i] = new BigInteger(keysize, sr);
			if (i < amount - 1)
				total = total.multiply(out[i]).mod(n);
		}
		out[0] = BigInteger.ONE.add(data.modInverse(n).multiply(out[amount - 1])).multiply(total).modInverse(n);
		out[amount - 1] = out[amount - 1].add(data).mod(n); 
		return out;
	}
	
	/**
	 * Given multiple homomorphically partitioned ciphertexts, combine these (multiplication)
	 * 
	 * @param split The homomorphic partitions
	 * @param n The modulus
	 */
	public static BigInteger combine(BigInteger[] split, BigInteger n){
		BigInteger total = BigInteger.ONE;
		for(BigInteger bi : split)
			total = total.multiply(bi).mod(n.multiply(n));
		return total;
	}
	
}
