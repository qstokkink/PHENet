package test.payload;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import net.payload.IllegalPacketException;
import net.payload.Packer;
import net.payload.PacketCombiner;
import net.payload.RawPacket;

import org.junit.Before;
import org.junit.Test;

import crypto.impl.PaillierKeyPair;

public class TestPacker {

	/**
	 * The keysize to use PaillierKeyPair.DEFAULT_BITS = 1024
	 */
	private int KEYSIZE = PaillierKeyPair.DEFAULT_BITS;
	
	/**
	 * A keypair to use for these tests (use a fast choice of g)
	 */
	private PaillierKeyPair keyPair = PaillierKeyPair.forceGenerate(KEYSIZE, true);
	
	/**
	 * The buffer for random data
	 */
	byte[] data = new byte[1024];
	
	/**
	 * The amount of partitions to create
	 */
	private int HOMOMORPHISMLEVEL = 8;
	
	@Before
	public void setUp(){
		new Random().nextBytes(data);
	}
	
	@Test
	public void test() throws IllegalBlockSizeException, IOException, IllegalPacketException, InvalidKeyException, BadPaddingException {
		byte[][] packed = Packer.pack(keyPair.getPublicKey(), HOMOMORPHISMLEVEL, 1, data);
		PacketCombiner combiner = new PacketCombiner(1);
		boolean finished = false;
		
		// Simulate messages arriving on different channels
		for (byte[] message : packed){
			ByteArrayInputStream bis = new ByteArrayInputStream(message);
			RawPacket raw = Packer.read(keyPair.getPrivateKey(), bis);
			finished |= combiner.read(keyPair.getPrivateKey(), raw);
		}
		
		assertTrue(finished);
		
		byte[] decrypted = combiner.finish(keyPair.getPrivateKey());
		
		assertArrayEquals(data, decrypted);
	}

}
