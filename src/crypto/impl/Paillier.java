package crypto.impl;

import java.math.BigInteger;

import static crypto.impl.PaillierUtil.generateR;
import static crypto.impl.PaillierUtil.L;
import static crypto.impl.PaillierUtil.lcm;

/**
 * Class for encryption and decryption with the Paillier cryptosystem.
 * 
 * Can either be instantiated with precomputed values for faster encryption and/or decryption,
 * or the static encode/decode methods can be used (slower).
 */
public class Paillier {
	
	private PaillierPublicKey pubKey = null;
	private PaillierPrivateKey privKey = null;
	
	private BigInteger n2;
	private BigInteger nr;
	private BigInteger hp;
	private BigInteger hq;
	
	/**
	 * Precompute values for faster encryption
	 */
	public Paillier(PaillierPublicKey key){
		this.pubKey = key;
		
		this.n2 = key.getN().multiply(key.getN());
		BigInteger r = generateR(key.getN());
		this.nr = r.modPow(key.getN(), n2);
	}
	
	/**
	 * Precompute values for faster decryption
	 */
	public Paillier(PaillierPrivateKey key){
		this.privKey = key;
		this.n2 = key.getN().multiply(key.getN());
		if (key instanceof PaillierEPrivateKey)
			precompCRT();
	}
	
	/**
	 * Precompute values for faster encryption and decryption
	 */
	public Paillier(PaillierKeyPair keypair){
		this(keypair.getPublicKey());
		this.privKey = keypair.getExtendedPrivateKey();
		precompCRT();
	}
	
	/**
	 * Precompute values used by Chinese Remainder Theorem
	 */
	private void precompCRT(){
		PaillierEPrivateKey epk = (PaillierEPrivateKey) privKey;
		hp = L(epk.getG().modPow(epk.getP().subtract(BigInteger.ONE), epk.getP().multiply(epk.getP())), epk.getP()).modInverse(epk.getP());
		hq = L(epk.getG().modPow(epk.getQ().subtract(BigInteger.ONE), epk.getQ().multiply(epk.getQ())), epk.getQ()).modInverse(epk.getQ());
	}
	
	/**
	 * Encode some data
	 * @param data The data to encode
	 */
	public BigInteger encode(BigInteger data){
		if (pubKey == null){
			throw new RuntimeException("Unable to encode: Paillier instance not initialized with Public Key");
		}
		return pubKey.getG().modPow(data, n2).multiply(nr);
	}
	
	/**
	 * Decode some data.
	 * Will use CRT if an extended Private Key is available
	 * @param data Encrypted data to be decrypted
	 */
	public BigInteger decode(BigInteger data){
		if (privKey == null){
			throw new RuntimeException("Unable to decode: Paillier instance not initialized with Private Key");
		}
		if (privKey instanceof PaillierEPrivateKey){
			PaillierEPrivateKey epk = (PaillierEPrivateKey) privKey;
			BigInteger mp = L(data.modPow(epk.getP().subtract(BigInteger.ONE), epk.getP().multiply(epk.getP())), epk.getP()).multiply(hp).mod(epk.getP());
			BigInteger mq = L(data.modPow(epk.getQ().subtract(BigInteger.ONE), epk.getQ().multiply(epk.getQ())), epk.getQ()).multiply(hq).mod(epk.getQ());
			return lcm(mp,mq).mod(privKey.getN());
		} else {
			return L(data.modPow(privKey.getLambda(), n2), privKey.getN()).multiply(privKey.getMu()).mod(privKey.getN());
		}
	}
	
	/**
	 * Encrypt data using a Public Key
	 * @param key The Public Key
	 * @param data The data to encrypt
	 */
	public static BigInteger encode(PaillierPublicKey key, BigInteger data){
		BigInteger r = generateR(key.getN());
		BigInteger n2 = key.getN().multiply(key.getN());
		return key.getG().modPow(data, n2).multiply(r.modPow(key.getN(), n2));
	}
	
	/**
	 * Decrypt data using a Private Key
	 * @param key The Private Key
	 * @param data The data to decrypt
	 */
	public static BigInteger decode(PaillierPrivateKey key, BigInteger data){
		return L(data.modPow(key.getLambda(), key.getN().multiply(key.getN())), key.getN()).multiply(key.getMu()).mod(key.getN());
	}

	public static void main(String[] args){
		PaillierKeyPair kp = PaillierKeyPair.forceGenerate(true);
		Paillier pfull = new Paillier(kp);
		
		//BigInteger enc = Paillier.encode(kp.getPublicKey(), BigInteger.valueOf(12345678L));
		BigInteger enc1 = pfull.encode(BigInteger.valueOf(12340000L));
		BigInteger enc2 = pfull.encode(BigInteger.valueOf(5678L));
		BigInteger enc = enc1.multiply(enc2).mod(kp.getPublicKey().getN().multiply(kp.getPublicKey().getN()));
		
		//BigInteger dec = Paillier.decode(kp.getPrivateKey(), enc);
		BigInteger dec = pfull.decode(enc);
		System.out.println(dec);
	}
}
