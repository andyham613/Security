
import java.util.Random;


public class PRGen extends Random implements Proj1Constants {
	// This implements a pseudorandom generator.  It extends java.util.Random, which provides
	//     a useful set of utility methods that all build on next(.).  See the documentation for
	//     java.util.Random for an explanation of what next(.) is supposed to do.
	// If you're calling a PRGen, you probably want to call methods of the Random superclass.
	//
	// There are two requirements on a pseudorandom generator.  First, it must be pseudorandom,
	//     meaning that there is no (known) way to distinguish its output from that of a
	//     truly random generator, unless you know the key.  Second, it must be deterministic,
	//     which means that if two programs create generators with the same seed, and then
	//     the two programs make the same sequence of calls to their generators, they should
	//     receive the same return values from all of those calls.
	// Your generator must have an additional property: backtracking resistance.  This means that if an
	//     adversary is able to observe the full state of the generator at some point in time, that
	//     adversary cannot reconstruct any of the output that was produced by previous calls to the
	//     generator.



	private byte[] current_state = new byte[KeySizeBytes];
  private byte[] list0 = new byte[KeySizeBytes];
	private byte[] list1 = new byte[KeySizeBytes];


	public PRGen(byte[] seed) {
		super();
		assert seed.length == KeySizeBytes;

		// IMPLEMENT THIS
		int i;
		for (i=0; i<KeySizeBytes; i++) {
			list0[i] = (byte) 0;
			list1[i] = (byte) 0xff;
		}
		list1[31] = (byte) 0;
		PRF newprf = new PRF(seed);
		current_state = newprf.eval(seed);
	}

	protected int next(int bits) {
		// For description of what this is supposed to do, see the documentation for
		//      java.util.Random, which we are subclassing.

		//ouputs int that is within the range [0, 2^bits)
		if (bits < 1 || 32 < bits) {
  		throw new IllegalArgumentException("Cannot provide " + bits +  "random bits");
		}
		PRF newprf = new PRF(current_state);
		current_state = newprf.eval(list0);
		PRF newprf2 = new PRF(current_state);
		byte[] evaluated = newprf2.eval(list1);

		int i=0;
		int result = 0;
		for (i=0; i<4; i++) {
			result = (evaluated[i] & 0xff) ^ (result<<8);
		}
		int mask = ((int)Math.pow(2, bits) - 1);
		return result & mask;
 		// IMPLEMENT THIS
	}
	public static void main(String argv[]) {
		System.out.println("************* testerino prg **************");
		byte[] seed1 = new byte[KeySizeBytes];
		byte[] seed2 = new byte[KeySizeBytes];
		byte[] seed3 = new byte[KeySizeBytes];
		int i;
		for(i=0; i<KeySizeBytes;i++) {
			seed1[i] = (byte)(i);
			seed2[i] = (byte)(i^1);
			seed3[i] = (byte)(i^ 0xa);
		}
    PRGen newprg1 = new PRGen(seed1);
		PRGen newprg2 = new PRGen(seed2);
		PRGen newprg3 = new PRGen(seed3);
		for (i=1; i<=32; i+=2) {
        System.out.println(newprg1.next(i));
				//System.out.println(newprg2.next(i));
				//System.out.println(newprg3.next(i));
		}
		System.out.println("compare different prgs");
		for (i=1; i<=32; i+=2) {
        //System.out.println(newprg1.next(i));
				System.out.println(newprg2.next(i));
				//System.out.println(newprg3.next(i));
		}
		System.out.println("+4 yee");
    for (i=1; i<=32; i+=4) {
        //System.out.println(newprg1.next(i));
				//System.out.println(newprg2.next(i));
				System.out.println(newprg3.next(i));
		}
		System.out.println("Asfdasdfasfd");
		System.out.println(newprg1.next(10));
		System.out.println(newprg1.next(10));
		System.out.println(newprg1.next(10));
		System.out.println(newprg1.next(10));
		System.out.println(newprg1.next(10));

	}
}
