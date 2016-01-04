package test.payload;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import net.payload.IllegalPacketException;
import net.payload.Packer;
import net.payload.PacketCombiner;
import net.payload.RawPacket;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import crypto.impl.PaillierKeyPair;

/**
 * Class for benchmarking encryption and decryption of the payload-based scheme
 */
@RunWith(Parameterized.class)
public class TestPackerBatch {

	/**
	 * The keysize to use PaillierKeyPair.DEFAULT_BITS = 1024
	 */
	private static int KEYSIZE = PaillierKeyPair.DEFAULT_BITS;
	
	/**
	 * A keypair to use for these tests (use a fast choice of g)
	 */
	private static PaillierKeyPair keyPair = PaillierKeyPair.forceGenerate(KEYSIZE, true);
	
	/**
	 * The amount of partitions to create
	 */
	private int HOMOMORPHISMLEVEL = 8;
	
	/**
	 * Packed data to decrypt
	 */
	private byte[][] PACKEDDATA;
	
	/**
	 * Data
	 */
	private byte[] DATA;
	
	public TestPackerBatch(Integer level, byte[] data, byte[][] packed){
		this.HOMOMORPHISMLEVEL = level.intValue();
		this.PACKEDDATA = packed;
		this.DATA = data;
	}

	/**
	 * Generate experiments for 4,8,12 and 16 levels of homomorphic partitioning
	 * Run 20 times for each level with random data
	 */
	@Parameterized.Parameters
	public static ArrayList<Object[]> generateData() {
		ArrayList<Object[]> out = new ArrayList<Object[]>();
		for (int i = 4; i <= 16; i += 4){
			for (int r = 0; r < 20; r++){
				byte[] data = new byte[1024*1024];
				new Random().nextBytes(data);
				try {
					out.add(new Object[] {Integer.valueOf(i), data, Packer.pack(keyPair.getPublicKey(), i, 1, data)});
				} catch (IllegalBlockSizeException e) {
					out.add(new Object[] {Integer.valueOf(i), data, null});
					e.printStackTrace();
				}
			}
		}
		return out;
	}
	
	@Test
	public void testEncrypt() throws IllegalBlockSizeException {
		byte[][] packed = Packer.pack(keyPair.getPublicKey(), HOMOMORPHISMLEVEL, 1, DATA);

		assertEquals(HOMOMORPHISMLEVEL, packed.length);
	}
	
	@Test
	public void testDecrypt() throws IllegalBlockSizeException, IOException, IllegalPacketException, InvalidKeyException, BadPaddingException {
		PacketCombiner combiner = new PacketCombiner(keyPair.getPrivateKey(), 1);
		boolean finished = false;
		
		// Simulate messages arriving on different channels
		for (byte[] message : PACKEDDATA){
			ByteArrayInputStream bis = new ByteArrayInputStream(message);
			RawPacket raw = Packer.read(keyPair.getPrivateKey(), bis);
			finished |= combiner.read(raw);
		}
		
		assertTrue(finished);
		
		byte[] decrypted = combiner.finish();
		
		assertArrayEquals(DATA, decrypted);
	}
}
