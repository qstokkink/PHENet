package crypto.impl;

import java.util.Random;

/**
 * Class for partitioning AES encrypted data blocks
 */
public class AESSplitter {

	/**
	 * Split the data into a certain amount of partitions, which will
	 * likely have the size of: dataSize/partitions
	 * Returns the partitions (in sequence)
	 */
	public static byte[][] splitUniform(byte[] data, int partitions){
		Random rnd = new Random();
		int position = 0;
		byte[][] out = new byte[partitions][];
		for (int i = 0; i < partitions; i++){
			int maxrange = ((data.length-position)/(partitions-i))/3;
			int wanted = (data.length-position)/(partitions-i);
			int size = rndIndex(rnd, wanted, maxrange);
			if (size + position > data.length || i == partitions - 1)
				size = data.length - position;
			out[i] = new byte[size];
			System.arraycopy(data, position, out[i], 0, size);
			position += size;
		}
		return out;
	}
	
	/**
	 * Get a Gaussian random value which has a 99% chance to naturally
	 * fall in mean + [-maxrange, maxrange] (otherwise it is clamped
	 * to these values, with 1% chance)
	 */
	private static int rndIndex(Random rnd, int mean, int maxrange){
		double out = (rnd.nextGaussian() * maxrange)/3 + mean;
		out = Math.max(out, mean-maxrange);
		out = Math.min(out, mean+maxrange);
		return (int) out;
	}
}
