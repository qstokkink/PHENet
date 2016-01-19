package test.crypto;

import static org.junit.Assert.*;
import static crypto.impl.AdditiveSplitter.*;

import java.math.BigInteger;

import org.junit.Test;

import crypto.impl.Paillier;
import crypto.impl.PaillierKeyPair;

public class TestPaillier {

	/**
	 * The keysize to use PaillierKeyPair.DEFAULT_BITS = 1024
	 */
	private int KEYSIZE = PaillierKeyPair.DEFAULT_BITS;
	
	/**
	 * A keypair to use for these tests (use a fast choice of g)
	 */
	private PaillierKeyPair keyPair = PaillierKeyPair.forceGenerate(KEYSIZE, true);
	
	/**
	 * The amount of partitions to create
	 */
	private int HOMOMORPHISMLEVEL = 8;
	
	/**
	 * The data to encrypt
	 */
	private BigInteger data = new BigInteger("1234567890987654321123456789098765432112345678909876543211234567890987654321");

	@Test
	public void testStatic() {
		BigInteger cipher = Paillier.encode(keyPair.getPublicKey(), data);
		BigInteger test = Paillier.decode(keyPair.getPrivateKey(), cipher);
		assertEquals(data, test);
	}

	@Test
	public void testOptimized() {
		Paillier encoder = new Paillier(keyPair.getPublicKey());
		Paillier decoder = new Paillier(keyPair.getPrivateKey());
		BigInteger cipher = encoder.encode(data);
		BigInteger test = decoder.decode(cipher);
		assertEquals(data, test);
	}
	
	@Test
	public void testOptimizedCRT() {
		Paillier system = new Paillier(keyPair);
		BigInteger cipher = system.encode(data);
		BigInteger test = system.decode(cipher);
		assertEquals(data, test);
	}
	
	
	@Test
	public void testStaticHomomorphism() {
		BigInteger[] split = split(data, KEYSIZE, HOMOMORPHISMLEVEL, keyPair.getPublicKey().getN());
		BigInteger[] cipher = new BigInteger[HOMOMORPHISMLEVEL];
		for (int i = 0; i < HOMOMORPHISMLEVEL; i++)
			cipher[i] = Paillier.encode(keyPair.getPublicKey(), split[i]);
		BigInteger test = Paillier.decode(keyPair.getPrivateKey(), combine(cipher, keyPair.getPrivateKey().getN()));
		assertEquals(data, test);
	}
	
	@Test
	public void testOptimizedHomomorphism() {
		Paillier encoder = new Paillier(keyPair.getPublicKey());
		Paillier decoder = new Paillier(keyPair.getPrivateKey());
		BigInteger[] split = split(data, KEYSIZE, HOMOMORPHISMLEVEL, keyPair.getPublicKey().getN());
		BigInteger[] cipher = new BigInteger[HOMOMORPHISMLEVEL];
		for (int i = 0; i < HOMOMORPHISMLEVEL; i++)
			cipher[i] = encoder.encode(split[i]);
		BigInteger test = decoder.decode(combine(cipher, keyPair.getPrivateKey().getN()));
		assertEquals(data, test);
	}
	
	@Test
	public void testOptimizedCRTHomomorphism() {
		Paillier system = new Paillier(keyPair);
		BigInteger[] split = split(data, KEYSIZE, HOMOMORPHISMLEVEL, keyPair.getPublicKey().getN());
		BigInteger[] cipher = new BigInteger[HOMOMORPHISMLEVEL];
		for (int i = 0; i < HOMOMORPHISMLEVEL; i++)
			cipher[i] = system.encode(split[i]);
		BigInteger test = system.decode(combine(cipher, keyPair.getPrivateKey().getN()));
		assertEquals(data, test);
	}
	
}
