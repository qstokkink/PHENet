package crypto.impl;

import java.math.BigInteger;
import java.util.Random;

/**
 * Utility methods for Paillier calculations
 */
public class PaillierUtil {

	/**
	 * Some might recognize these as prime numbers
	 */
	private static long[] FASTGIT = new long[] {2L, 3L, 5L, 7L, 11L}; 
	
	/**
	 * lcm(a,b) = (a/gcd(a,b))*b
	 */
	public static BigInteger lcm(BigInteger a, BigInteger b){
		return a.divide(a.gcd(b)).multiply(b);
	}
	
	/**
	 * L(u) = (u-1)/n
	 */
	public static BigInteger L(BigInteger u, BigInteger n){
		return u.subtract(BigInteger.ONE).divide(n);
	}
	
	/**
	 * g in Z*n2
	 * generate with random number r in bitspace of n
	 * g = r^(lcm(r, n2)) mod n2 + 1
	 */
	public static BigInteger generateG(BigInteger n){
		BigInteger a = new BigInteger(n.bitLength(), new Random());
		return a.modPow(lcm(a,n.multiply(n)), n.multiply(n)).add(BigInteger.ONE);
	}
	
	/**
	 * g in Z*n2
	 * as small as possible
	 */
	public static BigInteger generateGFast(BigInteger n){
		int testi = 0;
		BigInteger test = BigInteger.ZERO;
		BigInteger n2 = n.multiply(n);
		boolean pass = false;
		while (!pass && testi < FASTGIT.length){
			test = BigInteger.valueOf(FASTGIT[testi]);
			// See if the next small prime can pass as G
			try {
				n2.modInverse(test);
				pass = true;
			} catch (ArithmeticException e){
				pass = false;
			}
			testi++;
		}
		// If we fail too much, use the expensive method
		// This is extremely unlikely though
		if (testi == FASTGIT.length){
			test = generateG(n);
		}
		return test;
	}
	
	/**
	 * r in Z*n
	 * generate with random number r' in bitspace of n
	 * r = r'^(lcm(r, n)) mod n + 1 mod n
	 */
	public static BigInteger generateR(BigInteger n){
		BigInteger r_ = new BigInteger(n.bitLength(), new Random());
		BigInteger r = r_.modPow(lcm(r_,n), n).add(BigInteger.ONE).mod(n);
		if ("0".equals(r.toString()) || "1".equals(r.toString()))
			return BigInteger.valueOf(2L);
		else
			return r;
	}
	
}
