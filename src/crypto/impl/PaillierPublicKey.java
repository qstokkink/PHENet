package crypto.impl;

import java.math.BigInteger;

/**
 * Generic Paillier Public Key
 */
public class PaillierPublicKey {

	private final BigInteger n,g;
	
	public PaillierPublicKey(BigInteger n, BigInteger g){
		this.n = n;
		this.g = g;
	}
	
	public BigInteger getN(){
		return n;
	}
	
	public BigInteger getG(){
		return g;
	}

}
