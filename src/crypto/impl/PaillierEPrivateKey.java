package crypto.impl;

import java.math.BigInteger;

/**
 * Extension of generic Paillier Private Key, used for Chinese Remainder Theorem speedup
 */
public class PaillierEPrivateKey extends PaillierPrivateKey{

	private final BigInteger p, q, g;
	
	public PaillierEPrivateKey(BigInteger lambda, BigInteger mu, BigInteger n, BigInteger p, BigInteger q, BigInteger g){
		super(lambda, mu, n);
		this.p = p;
		this.q = q;
		this.g = g;
	}
	
	public BigInteger getP(){
		return p;
	}
	
	public BigInteger getQ(){
		return q;
	}
	
	public BigInteger getG(){
		return g;
	}
	
}
