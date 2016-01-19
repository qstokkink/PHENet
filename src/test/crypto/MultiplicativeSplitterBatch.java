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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.Description;
import org.junit.runner.JUnitCore;
import org.junit.runner.RunWith;
import org.junit.runner.notification.RunListener;
import org.junit.runners.Parameterized;

import crypto.impl.MultiplicativeSplitter;

/**
 * Class for benchmarking splitting of messages for additive homomorphic encryption
 */
@RunWith(Parameterized.class)
public class MultiplicativeSplitterBatch {

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
	
	private static HashMap<Integer, BigInteger> cheatsheet = new HashMap<Integer, BigInteger>();
	
	@Before
	public void setUp(){
		cheatsheet.put(new Integer(128), new BigInteger("165229107580883701896684203680876570157"));
		cheatsheet.put(new Integer(512), new BigInteger("10941738641570527421809707322040357612003732945449205990913842131476349984288934784717997257891267332497625752899781833797076537244027146743531593354333897"));
		cheatsheet.put(new Integer(1024), new BigInteger("133294399882575758380143779458803658621711224322668460285458826191727627667054255404674269333491950155273493343140718228407463573528003686665212740575911870128339157499072351179666739658503429931021985160714113146720277365006623692721807916355914275519065334791400296725853788916042959771420436564784273910949"));
		cheatsheet.put(new Integer(2048), new BigInteger("22701801293785014193580405120204586741061235962766583907094021879215171483119139894870133091111044901683400949483846818299518041763507948922590774925466088171879259465921026597046700449819899096862039460017743094473811056991294128542891880855362707407670722593737772666973440977361243336397308051763091506836310795312607239520365290032105848839507981452307299417185715796297454995023505316040919859193718023307414880446217922800831766040938656344571034778553457121080530736394535923932651866030515041060966437313323672831539323500067937107541955437362433248361242525945868802353916766181532375855504886901432221349733"));
		
	}
	
	public MultiplicativeSplitterBatch(Integer level, Integer bitspace){
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
		BigInteger n = cheatsheet.get(BITSPACE);
		BigInteger data = new BigInteger(BITSPACE, new Random()).mod(n);
		BigInteger[] split = MultiplicativeSplitter.split(data, BITSPACE, HOMOMORPHISMLEVEL, n);
		
		BigInteger product = BigInteger.ONE;
		for(BigInteger bi : split)
			product = product.multiply(bi).mod(n);
		
		assertEquals(data, product);
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
	    core.run(MultiplicativeSplitterBatch.class);
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
