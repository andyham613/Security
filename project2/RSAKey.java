import java.math.BigInteger;
import java.util.Arrays;
import java.nio.ByteBuffer;
public class RSAKey {
    private BigInteger exponent;
    private BigInteger modulus;

    private static final int oaepK0SizeBytes = 32;
	  private static final int oaepK1SizeBytes = 32;


    public RSAKey(BigInteger theExponent, BigInteger theModulus) {
        exponent = theExponent;
        modulus = theModulus;
    }

    public BigInteger getExponent() {
        return exponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public byte[] encrypt(byte[] plaintext, PRGen prgen) {
        if (plaintext == null)    throw new NullPointerException();


        int nSizeBytes = (modulus.bitLength()+7)/8; //total
        int paddedSizeBytes = nSizeBytes - oaepK0SizeBytes; // n-k0
        int mSizeBytes = maxPlaintextLength() + 4; //n-k0-k1, raw size
        int maxPlaintextSizeBytes = maxPlaintextLength();
        if (plaintext.length > maxPlaintextSizeBytes) {
          System.out.println("error, plaintext bigger than maxplaintextlength size");
          return null;
        }

        byte[] m = addPadding(plaintext);
        System.out.println("This is in encrypt(): after padding length of m: " + m.length);
        byte[] encodedOaep = encodeOaep(m,prgen);

        BigInteger encodedOaep_bint = Proj2Util.bytesToBigInteger(encodedOaep);
        //assert encodedOaep_bint.compareTo(modulus) < 0;
        //problem is encodeoaep_bint is larger than modulus, but modulus should be bigger.
        //System.out.println("encodedOaep_bint: " + encodedOaep_bint.toString());
        BigInteger mod_bint = encodedOaep_bint.modPow(exponent, modulus);
        //System.out.println("encrypt mod_bint: " + mod_bint.toString());

        int encryptedSizeBytes = (mod_bint.bitLength()+7)/8;
        //System.out.println("encrytpedSizebytes: " + encryptedSizeBytes + " vs " + "encodeoaep.length: " + encodedOaep.length);
        byte[] encrypted = Proj2Util.bigIntegerToBytes(mod_bint, encryptedSizeBytes);


        return encrypted; // IMPLEMENT THIS
    }

    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext == null)    throw new NullPointerException();
        //System.out.println("ciphertext in decrypt input: " + Arrays.toString(ciphertext));
        BigInteger ciphert_bint = Proj2Util.bytesToBigInteger(ciphertext);
      //  System.out.println("ciphert_bint: " + ciphert_bint.toString());
        BigInteger mod_bint = ciphert_bint.modPow(exponent,modulus);
      //  System.out.println("decrypt mod_bint: " + mod_bint.toString());
        int decryptedSizeBytes = (mod_bint.bitLength()+7)/8;
        byte[] decrypted = Proj2Util.bigIntegerToBytes(mod_bint, decryptedSizeBytes);
      //  System.out.println("decodeOaep input: " + Arrays.toString(decrypted));

        byte[] plaintext = removePadding(decodeOaep(decrypted));
        return plaintext; // IMPLEMENT THIS

    }

    public byte[] sign(byte[] message, PRGen prgen) {
        // Create a digital signature on <message>. The signature need
        //     not contain the contents of <message>--we will assume
        //     that a party who wants to verify the signature will already
        //     know which message this is (supposed to be) a signature on.
    	//
    	//     Note: The signature algorithm that we discussed in class is
    	//     deterministic, and so if you implement it, you do not need
    	//     to use the PRGen parameter. There is, however, a signature
    	//     algorithm that is superior to the one that we discussed that
    	//     does use pseudorandomness. Implement it for extra credit. See
    	//     the assignment description for details.
        if (message == null)    throw new NullPointerException();

        BigInteger message_bint = Proj2Util.bytesToBigInteger(message);
        BigInteger sign_bint = message_bint.modPow(exponent, modulus);
        return Proj2Util.bigIntegerToBytes(sign_bint, modulus.bitLength());

        // IMPLEMENT THIS
    }

    public boolean verifySignature(byte[] message, byte[] signature) {
        // Verify a digital signature. Returns true if  <signature> is
        //     a valid signature on <message>; returns false otherwise.
        //     A "valid" signature is one that was created by calling
        //     <sign> with the same message, using the other RSAKey that
        //     belongs to the same RSAKeyPair as this object.
        if ((message == null) || (signature == null))    throw new NullPointerException();

        BigInteger sign_bint = Proj2Util.bytesToBigInteger(signature);
        BigInteger sign_mod = sign_bint.modPow(exponent, modulus);
        BigInteger message_bint = Proj2Util.bytesToBigInteger(message);
        if (message_bint.equals(sign_mod)) {
          return true;
        } else {
          return false;
        }
    }

    public int maxPlaintextLength() {
        // Return the largest x such that any plaintext of size x bytes
        //      can be encrypted with this key
        int nSizeBytes = (modulus.bitLength()+7)/8;
        return nSizeBytes - oaepK0SizeBytes - oaepK1SizeBytes - 4; // IMPLEMENT THIS
    }

    // The next four methods are public to help us grade the assignment. In real life, these would
    // be private methods as there's no need to expose these methods as part of the public API

    public byte[] encodeOaep(byte[] input, PRGen prgen) {

        int nSizeBytes = (modulus.bitLength()+7)/8; //total
        int paddedSizeBytes = nSizeBytes - oaepK0SizeBytes; // n-k0
        int mSizeBytes = maxPlaintextLength() + 4; //n-k0-k1, raw size
        int maxPlaintextSizeBytes = maxPlaintextLength();

        byte[] padInput = new byte[paddedSizeBytes];
        int i=0;

        for (i=0; i<mSizeBytes/*input.length*/; i++) {
          //input.length should be same size as mSizeBytes
          padInput[i] = input[i];
        }
        for (i=mSizeBytes; i < paddedSizeBytes; i++) {
          padInput[i] = (byte) 0;
        }

        byte[] r = new byte[oaepK0SizeBytes];
        prgen.nextBytes(r); //psuedorandom r generated
        PRGen G = new PRGen(r);
        byte[] G_with_r = new byte[paddedSizeBytes];
        G.nextBytes(G_with_r);



        byte[] X = new byte[paddedSizeBytes];
        for (i =0; i<paddedSizeBytes; i++) {
          X[i] = (byte)(padInput[i] ^ G_with_r[i]);
        }


        byte[] H_with_X = Proj2Util.hash(X);

        byte[] Y = new byte[oaepK0SizeBytes];
        for (i=0; i<oaepK0SizeBytes; i++) {
          Y[i] = (byte) (H_with_X[i] ^ r[i]);
        }

        byte[] result = new byte[nSizeBytes];
        for (i=0; i< paddedSizeBytes; i++) {
          result[i] = X[i];
        }
        for (i = paddedSizeBytes; i< nSizeBytes; i++) {
          result[i] = Y[i - paddedSizeBytes];
        }
        System.out.println("result of encodeOaep: " + Arrays.toString(result));
        return result; // IMPLEMENT THIS
    }

    public byte[] decodeOaep(byte[] input) {

      int nSizeBytes = (modulus.bitLength()+7)/8; //total
      int paddedSizeBytes = nSizeBytes - oaepK0SizeBytes; // n-k0
      int mSizeBytes = maxPlaintextLength() + 4; //n-k0-k1, raw size
      int maxPlaintextSizeBytes = maxPlaintextLength();

      byte[] X = new byte[paddedSizeBytes];
      byte[] Y = new byte[oaepK0SizeBytes];
      byte[] r = new byte[oaepK0SizeBytes];
      byte[] m = new byte[mSizeBytes];
      byte[] plaintext = new byte[maxPlaintextSizeBytes];

      //input.length is nSizeBytes
      int i=0;
      for(i=0; i<paddedSizeBytes; i++) {
        X[i] = input[i];
      }
      for(i = 0; i<oaepK0SizeBytes; i++) {
        Y[i] = input[i+paddedSizeBytes];
      }

      byte[] H_with_X = Proj2Util.hash(X);

      for (i =0; i<oaepK0SizeBytes; i++) {
        r[i] = (byte) (H_with_X[i] ^ Y[i]);
      }

      PRGen G = new PRGen(r);
      System.out.println("input length: " + input.length);
      byte[] G_with_r = new byte[paddedSizeBytes];
      G.nextBytes(G_with_r);
      for(i = 0; i<mSizeBytes; i++) {
        m[i] = (byte) (G_with_r[i] ^ X[i]);
      }
      for(i = 0; i<maxPlaintextSizeBytes; i++) {
        plaintext[i] = (byte) (G_with_r[i] ^ X[i]);
      }

      System.out.println("message m: " + Arrays.toString(m));

      return m; // IMPLEMENT THIS
    }

    public byte[] addPadding(byte[] input) {
        //pad to guarantee that the input to encodeOAEP is n-k0-k1 in length
        int nSizeBytes = (modulus.bitLength()+7)/8; //total
        int paddedSizeBytes = nSizeBytes - oaepK0SizeBytes; // n-k0
        int mSizeBytes = maxPlaintextLength() + 4; //n-k0-k1, raw size
        int maxPlaintextSizeBytes = maxPlaintextLength();

        int padding_length_in_m = maxPlaintextSizeBytes - input.length;

        byte[] pad_to_m = new byte[mSizeBytes];
        int i=0;
      	System.out.println("nsizebyte: "+nSizeBytes);
      	System.out.println("paddedsizebytes: "+paddedSizeBytes);
      	System.out.println("maxplaintext length: "+maxPlaintextLength());
        System.out.println("msizebytes: " + mSizeBytes);
      	System.out.println("input length: " + input.length);
        System.out.println("padding length in m: " + padding_length_in_m);
      	for(i=0; i<input.length; i++) {
          System.out.println(input[i]);
          pad_to_m[i] = input[i];
        }
      	for(i=input.length; i<maxPlaintextSizeBytes; i++) {
      	  pad_to_m[i] = (byte) 0;
      	}
        // for(i=0; i<4; i++) {
        //   pad_to_m[i+maxPlaintextSizeBytes] =
        // }

        //last 4 bytes of m include padding length in m
        //TODO: check ++s make sure right indexing;
        pad_to_m[maxPlaintextSizeBytes++] = (byte) (padding_length_in_m >> 24);
        pad_to_m[maxPlaintextSizeBytes++] = (byte) (padding_length_in_m >> 16);
        pad_to_m[maxPlaintextSizeBytes++] = (byte) (padding_length_in_m >> 8);
        pad_to_m[maxPlaintextSizeBytes++] = (byte) (padding_length_in_m);
        System.out.println(Arrays.toString(pad_to_m));
        //assuming padlength isnt so huge that it exceeds one byte;
        System.out.println("just last byte: " + (pad_to_m[mSizeBytes-1] & 0xFF));
        return pad_to_m; // IMPLEMENT THIS
    }

    public byte[] removePadding(byte[] input) {
      int nSizeBytes = (modulus.bitLength()+7)/8; //total
      int paddedSizeBytes = nSizeBytes - oaepK0SizeBytes; // n-k0
      int mSizeBytes = maxPlaintextLength() + 4; //n-k0-k1, raw size
      int maxPlaintextSizeBytes = maxPlaintextLength();

      int padding_length_in_m = 0;
      int i=0;

      padding_length_in_m = (int) ((input[mSizeBytes-4] << 24) | (input[mSizeBytes-3] << 16) | (input[mSizeBytes-2] << 8) | (input[mSizeBytes-1]));


      byte[] a = new byte[4];
      for (i = 0; i<4; i++) {
        a[i] = input[i+maxPlaintextSizeBytes];
      }
      int n = ByteBuffer.wrap(a).getInt();
      // System.out.println("padding in m using bufferwrap: " + n);
      // System.out.println("byte1: " + (input[input.length-4] << 24));
      // System.out.println("byte2: " + (input[input.length-3] << 16));
      // System.out.println("byte3: " + (input[input.length-2] << 8));
      // System.out.println("byte4: " + (input[input.length-1]));

      int one = (int) (input[mSizeBytes - 1] & 0xff);
      System.out.println("just last byte: " + (int)(input[mSizeBytes-1]));
      // for(i=maxPlaintextSizeBytes; i<mSizeBytes; i++) {
      //   padding_length_in_m += (int)input[i];
      // }

      System.out.println("how much padding in m?: " + padding_length_in_m);
      System.out.println("input length: " + input.length);
      System.out.println("max plaintext length: " + maxPlaintextSizeBytes);
      padding_length_in_m = one;
      byte[] plaintext = new byte[maxPlaintextSizeBytes - padding_length_in_m];

      for(i=0; i<plaintext.length; i++) {
        plaintext[i] = input[i];
      }

      return plaintext; // IMPLEMENT THIS
    }
    public static void main(String[] argv) {
      System.out.println("RSAKey main");


    }
}
