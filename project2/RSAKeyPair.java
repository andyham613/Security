import java.math.BigInteger;

import java.util.Arrays;


public class RSAKeyPair {
	private RSAKey publicKey;
	private RSAKey privateKey;
	private BigInteger prime_p;
	private BigInteger prime_q;

	public RSAKeyPair(PRGen rand, int numBits) {
		// Create an RSA key pair.  rand is a PRGen that this code can use to get pseudorandom
		//     bits.  numBits is the size in bits of each of the primes that will be used.
		prime_p = Proj2Util.generatePrime(rand, numBits);
		prime_q = Proj2Util.generatePrime(rand, numBits);
		BigInteger n = prime_p.multiply(prime_q);
		//BigInteger phi = (prime_p - 1) * (prime_q - 1);
		BigInteger phi = (prime_p.subtract(BigInteger.valueOf(1))).multiply(prime_q.subtract(BigInteger.valueOf(1)));
		//System.out.println("BigInteger phi: " + phi.toString());
		//System.out.println("BigInteger phi + 1: " + phi.add(BigInteger.valueOf(1)).toString());
		// for e, public key, make sure it is greater than 2 and not a factor of phi(n)
		BigInteger e = BigInteger.valueOf(3);
		while(((phi.gcd(e)).compareTo(BigInteger.valueOf(1))) != 0) {
			e = e.nextProbablePrime();
		}
		//e = phi.add(BigInteger.valueOf(1));
		publicKey = new RSAKey(e,n);
		//private key is d = (k + phi + 1)/ e; or calc the inverse mod of e using phi
		BigInteger d = e.modInverse(phi);
		if ((e.multiply(d).mod(phi)).compareTo(BigInteger.valueOf(1)) != 0) {
			System.out.println("error, key pairs are not inverses");
		}
		privateKey = new RSAKey(d,n);
		// IMPLEMENT THIS
	}

	public RSAKey getPublicKey() {
		return publicKey;
	}

	public RSAKey getPrivateKey() {
		return privateKey;
	}

	public BigInteger[] getPrimes() {
		// Returns an array containing the two primes that were used in key generation.
		//   In real life we don't always keep the primes around.
		//   But including this helps us grade the assignment.
		BigInteger[] ret = new BigInteger[2];
		ret[0] = prime_p; // IMPLEMENT THIS
		ret[1] = prime_q;
		return ret;
	}
	public static void main(String[] argv) {

      	System.out.println(BigInteger.valueOf(1));
		System.out.println(BigInteger.ONE);
		byte[] key = new byte[32];
		byte[] plaintext = new byte[8];
		int i=0;
		for (i=0; i<8; i++) {
			plaintext[i] = (byte) (i * 2);
		}

		for (i=0;i<32;i++) {
			key[i] = (byte) ((i*7));
		}
		byte[] key2 = new byte[32];
		key2[0] = (byte) 0xA0;
		key2[1] = (byte) 0x14;
		key2[2] = (byte) 0x32;
		key2[3] = (byte) 0x5;
		key2[4] = (byte) 0xD;
		PRGen newprgen = new PRGen(key2);
		RSAKeyPair keypair = new RSAKeyPair(newprgen, 512);
		System.out.println("priv rsakey exponent: " + keypair.privateKey.getExponent());
		System.out.println("priv rsakey modulus: " + keypair.privateKey.getModulus());
		System.out.println("priv rsakey modulus bitlength: " + keypair.privateKey.getModulus().bitLength());
		System.out.println("public rsakey exponent: " + keypair.publicKey.getExponent());
		System.out.println("public rsakey modulus: " + keypair.publicKey.getModulus());
		System.out.println("public rsakey modulus bitlength: " + keypair.publicKey.getModulus().bitLength());

		System.out.println("plaintext: ");
		System.out.println(Arrays.toString(plaintext));
		System.out.println("encrypted: ");
		byte[] encrypted = keypair.publicKey.encrypt(plaintext, newprgen);
		System.out.println("this is encrypted "+ Arrays.toString(encrypted));
		System.out.println("encrypted array size: " + encrypted.length);
		byte[] decrypted = keypair.privateKey.decrypt(encrypted);
		System.out.println("decrypted: ");
		System.out.println(Arrays.toString(decrypted));


		System.out.println("\n\n**************oh boy encrypt decrypt*********");
		System.out.println("Plaintext: "+  Arrays.toString(plaintext));
		System.out.println("encrypted: "+  Arrays.toString(encrypted));
		System.out.println("decrypted: "+  Arrays.toString(decrypted));
  	}
}
