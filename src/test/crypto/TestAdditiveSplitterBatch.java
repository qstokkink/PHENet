package test.crypto;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.Stack;

import org.junit.Test;
import org.junit.runner.Description;
import org.junit.runner.JUnitCore;
import org.junit.runner.RunWith;
import org.junit.runner.notification.RunListener;
import org.junit.runners.Parameterized;

import crypto.impl.AdditiveSplitter;

/**
 * Class for benchmarking splitting of messages for additive homomorphic encryption
 */
@RunWith(Parameterized.class)
public class TestAdditiveSplitterBatch {

	/**
	 * The amount of partitions to create
	 */
	private int HOMOMORPHISMLEVEL = 8;
	
	/**
	 * The bitspace in which the message resides
	 */
	private int BITSPACE = 32;
	
	/**
	 * Amount of times to repeat each experiment
	 */
	private static int REPETITIONS = 20;
	
	public TestAdditiveSplitterBatch(Integer level, Integer bitspace){
		this.HOMOMORPHISMLEVEL = level.intValue();
		this.BITSPACE = bitspace.intValue();
	}
	
	/**
	 * Generate experiments for 4,8,12 and 16 levels of homomorphic partitioning
	 * For 128, 512, 1024 and 2048 bit messages 
	 * Run 20 times for each level with random data
	 */
	@Parameterized.Parameters
	public static ArrayList<Object[]> generateData() {
		ArrayList<Object[]> out = new ArrayList<Object[]>();
		for (int i : new int[] {4, 8, 12, 16}){
			for (int j : new int[] {128, 512, 1024, 2048}){
				for (int r = 0; r < REPETITIONS; r++){
					out.add(new Object[] {Integer.valueOf(i), Integer.valueOf(j)});
				}
			}
		}
		return out;
	}
	
	@Test
	public void test() {
		BigInteger n = new BigInteger(BITSPACE, new Random());
		BigInteger data = new BigInteger(BITSPACE, new Random()).mod(n);
		BigInteger[] split = AdditiveSplitter.split(data, BITSPACE, HOMOMORPHISMLEVEL, n);
		
		BigInteger sum = BigInteger.ZERO;
		for(BigInteger bi : split)
			sum = sum.add(bi).mod(n);
		
		assertEquals(data, sum);
	}
	
	/**
	 * If the default JUnit core is not used,
	 * Aggregate results, also provide a fancy loadbar
	 */
	public static void main(String[] args){
		JUnitCore core= new JUnitCore();
		final HashMap<String, Stack<Long>> runtimes = new HashMap<String, Stack<Long>>();
		RunListener listener = new RunListener(){
			private long stime = 0;
			
			@Override
			public void testStarted(Description description) throws Exception {
				super.testStarted(description);
				String group = getGroup(description.getMethodName());
				if (!runtimes.containsKey(group))
					runtimes.put(group, new Stack<Long>());
				stime = System.nanoTime();
			}
			
			@Override
			public void testFinished(Description description) throws Exception {
				super.testFinished(description);
				long etime = System.nanoTime() - stime;
				String group = getGroup(description.getMethodName());
				runtimes.get(group).push(etime);
				System.out.print("*");
			}
			
			private int getNumber(String raw){
				return Integer.valueOf(raw.substring(raw.indexOf('[')+1, raw.indexOf(']')));
			}
			
			private String getGroup(String raw){
				int level = (((int) getNumber(raw)/REPETITIONS)/4 + 1)*4;
				int bitspace = ((int) getNumber(raw)/REPETITIONS)%4;
				int[] spaces = new int[] {128, 512, 1024, 2048};
				
				return level + "x" + spaces[bitspace];
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
	    core.run(TestAdditiveSplitterBatch.class);
		System.out.println();
		System.out.println(loadbar.toString());
		
		List<String> sortedGroups = (List<String>) Arrays.asList(runtimes.keySet().toArray(new String[0]));
		Collections.sort(sortedGroups);
		for (String group : sortedGroups){
			Stack<Long> times = runtimes.get(group);
			Collections.sort(times);
			// Get the median
			System.out.println(group + ": " + times.get(REPETITIONS/2)/1000.0d + "ms");
		}
	}

}
