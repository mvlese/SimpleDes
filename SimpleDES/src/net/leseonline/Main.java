package net.leseonline;

import java.math.BigInteger;
import java.util.Hashtable;

/**
 * Reference https://www.cs.uri.edu/cryptography/dessimplified.htm
 *
 * @author lesem
 *
 */
public class Main {

	private final boolean DEBUG = false;
	
	// 1000 1011 0101
	private BigInteger input = BigInteger.valueOf(0x8b5);
	
	// 1 1100 0111
	private BigInteger key = BigInteger.valueOf(0x1c7);
	
	private BigInteger[][] s1 = new BigInteger[][] {
		{BigInteger.valueOf(5), BigInteger.valueOf(2),BigInteger.valueOf(1), BigInteger.valueOf(6),BigInteger.valueOf(3), BigInteger.valueOf(4),BigInteger.valueOf(7), BigInteger.valueOf(0)},
		{BigInteger.valueOf(1), BigInteger.valueOf(4),BigInteger.valueOf(6), BigInteger.valueOf(2),BigInteger.valueOf(0), BigInteger.valueOf(7),BigInteger.valueOf(5), BigInteger.valueOf(3)}
	};
	
	private BigInteger[][] s2 = new BigInteger[][] {
		{BigInteger.valueOf(4), BigInteger.valueOf(0),BigInteger.valueOf(6), BigInteger.valueOf(5),BigInteger.valueOf(7), BigInteger.valueOf(1),BigInteger.valueOf(3), BigInteger.valueOf(2)},
		{BigInteger.valueOf(5), BigInteger.valueOf(3),BigInteger.valueOf(0), BigInteger.valueOf(7),BigInteger.valueOf(6), BigInteger.valueOf(2),BigInteger.valueOf(1), BigInteger.valueOf(4)}
	};
	
	/**
	 * This object maps a six-bit value into an eight-bit value.
	 */
	private Hashtable<Integer, Integer[]> expansionMap;
	
	public static void main(String[] args) {
		new Main().doWork();
	}
	
	private void init() {
		// This object maps a six-bit value into an eight-bit value.
		// Bit 5 -> Bit 7
		// Bit 4 -> Bit 6
		// Bit 3 -> Bits 4 and 2
		// Bit 2 -> Bits 5 and 3
		// Bit 1 -> Bit 1
		// Bit 0 -> Bit 0
		expansionMap = new Hashtable<Integer, Integer[]>();
		expansionMap.put(32, new Integer[] {128});
		expansionMap.put(16, new Integer[] {64});
		expansionMap.put(8, new Integer[] {16, 4});
		expansionMap.put(4, new Integer[] {32, 8});
		expansionMap.put(2, new Integer[] {2});
		expansionMap.put(1, new Integer[] {1});
	}
	
	private void doWork() {
		init();
		
		BigInteger encrypted = fprocess(input, 1, 2);
		System.out.println("Encrypted value:   " + toBinaryString(encrypted, 12));
		
		BigInteger plaintext = fprocess(encrypted, 2, 1);
		System.out.println("Decrypted value:   " + toBinaryString(plaintext, 12));

		System.out.println("Original paintext: " + toBinaryString(input, 12));
	}

	private BigInteger fprocess(BigInteger value, int startRound, int finalRound) {
		BigInteger[] parts = value.divideAndRemainder(BigInteger.valueOf(64));

		// L(i-1) and R(i-1)
		BigInteger li_1 = parts[0];
		BigInteger ri_1 = parts[1];
		
		boolean done = false;
		int round = 1;
		int i = startRound;
		while (!done) {
			if (DEBUG) System.out.println("Start of round " + String.valueOf(round++) + ".");
			BigInteger k = getIthKey(i);
			
			// call f(Ri-1,Ki)
			BigInteger fout = ffunc(ri_1, k);
			if (DEBUG) System.out.println(fout.toString(2));

			BigInteger l = BigInteger.valueOf(ri_1.longValue());
			BigInteger r = fout.xor(li_1);

			if (DEBUG) System.out.println("L: " + toBinaryString(l, 6));
			if (DEBUG) System.out.println("R: " + toBinaryString(r, 6));

			li_1 = l;
			ri_1 = r;

			if (startRound > finalRound) {
				// decrypt process
				i--;
				done = (i < finalRound);
			} else {
				// encrypt process
				i++;
				done = (i > finalRound);
			}
		}
		
		BigInteger result = ri_1.shiftLeft(6).add(li_1);
		
		return result;
	}
	
	/**
	 * This is f(Ri-1,Ki).
	 * @param r the right side part.
	 * @param k the key.
	 * @return the output of f(Ri-1, Ki).
	 */
	private BigInteger ffunc(BigInteger r, BigInteger k) {
		BigInteger e0 = efunc(r);
		if (DEBUG) System.out.println("E(Ri): " + toBinaryString(e0, 8));
		
		BigInteger step3 = k.xor(e0);
		if (DEBUG) System.out.println("E(Ri) xor Key(i): " + toBinaryString(step3, 8));
		
		BigInteger left4bits = step3.shiftRight(4);
		BigInteger right4bits = step3.and(BigInteger.valueOf(0xf));
		
		BigInteger s1row = left4bits.shiftRight(3);
		BigInteger s2row = right4bits.shiftRight(3);
		BigInteger s1col = left4bits.and(BigInteger.valueOf(7));
		BigInteger s2col = right4bits.and(BigInteger.valueOf(7));
		
		BigInteger s1prime = s1[s1row.intValue()][s1col.intValue()];
		BigInteger s2prime = s2[s2row.intValue()][s2col.intValue()];
		if (DEBUG) System.out.println("S1 " + toBinaryString(s1prime, 3));
		if (DEBUG) System.out.println("S2 " + toBinaryString(s2prime, 3));
		
		BigInteger fout = s1prime.shiftLeft(3).add(s2prime); 
		
		return fout;
	}
	
	/**
	 * This method takes a six bit input and returns an eight bit output.
	 * @param input
	 * @return
	 */
	private BigInteger efunc (BigInteger inputValue) {
		BigInteger result = BigInteger.ZERO;
		
		for(Integer key: expansionMap.keySet()) {
			BigInteger bd = inputValue.and(BigInteger.valueOf(key));
			if (bd.compareTo(BigInteger.ZERO) > 0) {
				for(Integer value: expansionMap.get(key)) {
					result = result.add(BigInteger.valueOf(value));
				}
			}			
		}

		return result;
	}
	
	/**
	 * This method returns the i-th 8-bit key of the 9-bit key
	 * beginning at the i-th position (left based beginning at 1).
	 * @param i the i-th position (i-th > 0).
	 * @return the 8-bit key.
	 */
	private BigInteger getIthKey(int i) {
		BigInteger result = BigInteger.ZERO;
		
		int t = i - 1;
		int index = t % 9;
		
		BigInteger[] parts = key.divideAndRemainder(BigInteger.valueOf(2).pow(9 - index));
		result = parts[1].shiftLeft(index).add(parts[0]).shiftRight(1);

		return result;
	}
	
	private String toBinaryString(BigInteger value, int nBits) {
		String temp = "000000000000" + value.toString(2);
		return temp.substring(temp.length() - nBits);
	}
	
}
