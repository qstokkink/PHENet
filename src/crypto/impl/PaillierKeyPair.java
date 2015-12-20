package crypto.impl;

import java.math.BigInteger;
import java.util.Random;

import static crypto.impl.PaillierUtil.lcm;
import static crypto.impl.PaillierUtil.generateG;
import static crypto.impl.PaillierUtil.generateGFast;
import static crypto.impl.PaillierUtil.L;

/**
 * Class used to generate and store Paillier key pairs
 */
public class PaillierKeyPair {

	private final PaillierPublicKey pubKey;
	private final PaillierPrivateKey privKey;
	private final PaillierEPrivateKey extendedPrivKey;
	
	public static final int DEFAULT_BITS = 1024;
	
	private PaillierKeyPair(PaillierPublicKey pubKey, PaillierPrivateKey privKey, PaillierEPrivateKey extendedPrivKey){
		this.pubKey = pubKey;
		this.privKey = privKey;
		this.extendedPrivKey = extendedPrivKey;
	}
	
	public PaillierPublicKey getPublicKey(){
		return pubKey;
	}
	
	public PaillierPrivateKey getPrivateKey(){
		return privKey;
	}
	
	protected PaillierEPrivateKey getExtendedPrivateKey(){
		return extendedPrivKey;
	}

	/**
	 * Generate a new PaillierKeyPair with a 1024 bit key
	 * @param fast Whether G should be generated for faster encryption
	 * @throws ArithmeticException If generation failed
	 */
	public static PaillierKeyPair generate(boolean fast) throws ArithmeticException{
		return generate(DEFAULT_BITS, fast);
	}
	
	/**
	 * Generate a new PaillierKeyPair with a key of a certain length
	 * @param bits Bit size of the keys
	 * @param fast Whether G should be generated for faster encryption
	 * @throws ArithmeticException If generation failed
	 */
	public static PaillierKeyPair generate(int bits, boolean fast) throws ArithmeticException{
		BigInteger p = BigInteger.probablePrime(bits, new Random());
		BigInteger q = BigInteger.probablePrime(bits, new Random());
		
		BigInteger n = p.multiply(q);
		BigInteger n2 = n.multiply(n);

		BigInteger lambda = lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
		BigInteger g = fast ? generateGFast(n) : generateG(n);
		BigInteger mu = L(g.modPow(lambda, n2), n).modInverse(n);
		
		return new PaillierKeyPair(new PaillierPublicKey(bits, n, g), new PaillierPrivateKey(bits, lambda, mu, n), new PaillierEPrivateKey(bits, lambda, mu, n, p, q, g));
	}

	/**
	 * Force the generation of a new PaillierKeyPair with a key of a certain length 
	 * Could infinitely loop if the random number generation gets stuck in the wrong spot
	 * @param fast Whether G should be generated for faster encryption
	 */
	public static PaillierKeyPair forceGenerate(boolean fast){
		return forceGenerate(DEFAULT_BITS, fast);
	}
	
	/**
	 * Force the generation of a new PaillierKeyPair with a key of a certain length 
	 * Could infinitely loop if the random number generation gets stuck in the wrong spot
	 * @param bits Bit size of the keys
	 * @param fast Whether G should be generated for faster encryption
	 */
	public static PaillierKeyPair forceGenerate(int bits, boolean fast){
		PaillierKeyPair pk = null;
		do {
			try {
				pk = generate(bits, fast);
			} catch (ArithmeticException e){
				pk = null;
			}
		} while (pk == null);
		return pk;
	}
}
