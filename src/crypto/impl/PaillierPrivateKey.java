package crypto.impl;

import java.math.BigInteger;

/**
 * Generic Paillier Private Key
 */
public class PaillierPrivateKey{

	private final BigInteger lambda, mu, n;
	private final int bitspace;
	
	public PaillierPrivateKey(int bitspace, BigInteger lambda, BigInteger mu, BigInteger n){
		this.bitspace = bitspace;
		this.lambda = lambda;
		this.mu = mu;
		this.n = n;
	}
	
	public int getBitspace(){
		return bitspace;
	}
	
	public BigInteger getLambda(){
		return lambda;
	}
	
	public BigInteger getMu(){
		return mu;
	}
	
	public BigInteger getN(){
		return n;
	}
	
}
