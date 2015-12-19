package crypto.impl;

import java.math.BigInteger;

/**
 * Generic Paillier Private Key
 */
public class PaillierPrivateKey{

	private final BigInteger lambda, mu, n;
	
	public PaillierPrivateKey(BigInteger lambda, BigInteger mu, BigInteger n){
		this.lambda = lambda;
		this.mu = mu;
		this.n = n;
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
