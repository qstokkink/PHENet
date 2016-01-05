package test.payload;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import net.payload.IllegalPacketException;
import net.payload.Packer;
import net.payload.PacketCombiner;
import net.payload.RawPacket;

import org.junit.Test;
import org.junit.runner.Description;
import org.junit.runner.JUnitCore;
import org.junit.runner.RunWith;
import org.junit.runner.notification.RunListener;
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
	 * Size in bytes of the random data
	 */
	private static int DATASIZE = 8192*1024;
	
	/**
	 * Amount of times to repeat each experiment
	 */
	private static int REPETITIONS = 20;
	
	/**
	 * The amount of partitions to create
	 */
	private int HOMOMORPHISMLEVEL;
	
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
				byte[] data = new byte[DATASIZE];
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
	
	/**
	 * If the default JUnit core is not used,
	 * Aggregate results, also provide a fancy loadbar
	 */
	public static void main(String[] args){
		JUnitCore core= new JUnitCore();
		final HashMap<String, Long> runtimes = new HashMap<String, Long>();
		RunListener listener = new RunListener(){
			private long stime = 0;
			
			@Override
			public void testStarted(Description description) throws Exception {
				super.testStarted(description);
				String group = getGroup(description.getMethodName());
				if (!runtimes.containsKey(group))
					runtimes.put(group, 0L);
				stime = System.currentTimeMillis();
			}
			
			@Override
			public void testFinished(Description description) throws Exception {
				super.testFinished(description);
				long etime = System.currentTimeMillis() - stime;
				String group = getGroup(description.getMethodName());
				runtimes.put(group, runtimes.get(group) + etime);
				System.out.print("*");
			}
			
			private String getName(String raw){
				return raw.substring(0, raw.indexOf('['));
			}
			
			private int getNumber(String raw){
				return Integer.valueOf(raw.substring(raw.indexOf('[')+1, raw.indexOf(']')));
			}
			
			private String getGroup(String raw){
				return getName(raw) + ((((int) getNumber(raw)/REPETITIONS) + 1)*4);
			}
		};
	    core.addListener(listener);
	    
	    // Generate a fancy loading bar
	    String sloadbar = "====";
	    StringBuilder loadbar = new StringBuilder();
	    for (int i = 0; i < REPETITIONS*2; i++)
	    	loadbar.append(sloadbar);
	    System.out.println("Preparing experiment, please be patient");
	    System.out.println(loadbar.toString());
	    core.run(TestPackerBatch.class);
		System.out.println();
		System.out.println(loadbar.toString());
		
		for (String group : runtimes.keySet()){
			System.out.println(group + ": " + (runtimes.get(group)/1000.0d)/REPETITIONS + "s");
		}
	}
}
