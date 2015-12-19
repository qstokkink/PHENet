package crypto.impl;

import java.math.BigInteger;
import java.util.Random;

/**
 * Class for creating an additively homomorphic split of a message
 * and to combine ciphertexts
 */
public class PaillierSplitter {

	/**
	 * Split plaintext into multiple plaintexts for additive homomorphism
	 * 
	 * @param data The plaintext to split
	 * @param keysize The keysize (modulo)
	 * @param amount The amount of partitions to create
	 * @param n The modulus
	 * @return The partial plaintexts 
	 */
	public static BigInteger[] split(BigInteger data, int keysize, int amount, BigInteger n){
		assert(amount > 1);
		BigInteger[] out = new BigInteger[amount];
		BigInteger total = BigInteger.ZERO;
		for (int i = 1; i < amount; i++){
			out[i] = new BigInteger(keysize, new Random());
			total = total.add(out[i]).mod(n);
		}
		out[0] = data.subtract(total);
		if (out[0].compareTo(n) <= 0)
			out[0].add(n);
		return out;
	}
	
	/**
	 * Given multiple homomorphicly partitioned ciphertexts, combine these (multiplication)
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
