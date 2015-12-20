package crypto.impl;

import java.math.BigInteger;

/**
 * Generic Paillier Public Key
 */
public class PaillierPublicKey {

	private final BigInteger n,g;
	private final int bitspace;
	
	public PaillierPublicKey(int bitspace, BigInteger n, BigInteger g){
		this.bitspace = bitspace;
		this.n = n;
		this.g = g;
	}
	
	public int getBitspace(){
		return bitspace;
	}
	
	public BigInteger getN(){
		return n;
	}
	
	public BigInteger getG(){
		return g;
	}

}
