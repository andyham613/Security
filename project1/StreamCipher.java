
public class StreamCipher implements Proj1Constants {
	// This class encrypts or decrypts a stream of bytes, using a stream cipher.


	private PRF newprf;
	private PRGen newprg;
	private boolean is_nonce_set;

	public StreamCipher(byte[] key) {
		// <key> is the key, which must be KeySizeBytes bytes in length.

		assert key.length == KeySizeBytes;
		newprf = new PRF(key);
		// IMPLEMENT THIS
		//System.out.println(is_nonce_set);
		is_nonce_set = false;
	}

	public void setNonce(byte[] arr, int offset){
		// Reset to initial state, and set a new nonce.
		// The nonce is in arr[offset] thru arr[offset+NonceSizeBytes-1].
		// It is an error to call setNonce with the same nonce
		//    more than once on a single StreamCipher object.
		// StreamCipher does not check for nonce uniqueness;
		//    that is the responsibility of the caller.

		assert arr.length >= offset + NonceSizeBytes;
		//System.out.println(is_nonce_set);
		assert is_nonce_set == false;
		assert arr != null;


		byte[] seed = new byte[KeySizeBytes];
		int i;
		for (i=0; i< NonceSizeBytes; i++) {
			seed[i] = arr[i+offset];
		}
		for (i=8; i< KeySizeBytes; i++) {
			seed[i] = (byte) 0xff;
		}

		newprg = new PRGen(newprf.eval(seed,offset,KeySizeBytes));
		//System.out.println(is_nonce_set);
		is_nonce_set = true;

		// IMPLEMENT THIS

	}

	public void setNonce(byte[] nonce) {
		// Reset to initial state, and set a new nonce
		// It is an error to call setNonce with the same nonce
		//    more than once on a single StreamCipher object.
		// StreamCipher does not check for nonce uniqueness;
		//    that is the responsibility of the caller.

		assert nonce.length == NonceSizeBytes;
		setNonce(nonce, 0);
	}

	public byte cryptByte(byte in) {
		// Encrypt/decrypt the next byte in the stream
		assert is_nonce_set == true;
		in = (byte)(in ^ (byte)newprg.next(8)); //next 8 bits aka 1 byte
		return in;   // IMPLEMENT THIS
	}

	public void cryptBytes(byte[] inBuf, int inOffset,
			byte[] outBuf, int outOffset,
			int numBytes) {
		// Encrypt/decrypt the next <numBytes> bytes in the stream
		// Take input bytes from inBuf[inOffset] thru inBuf[inOffset+numBytes-1]
		// Put output bytes at outBuf[outOffset] thru outBuf[outOffset+numBytes-1];
		int i;
    for (i=0; i<numBytes; i++) {
    	outBuf[i + outOffset] = cryptByte(inBuf[i + inOffset]);
    }

		//newprg = new PRGen(newprf.eval(inbuf, inOffset, KeySizeBytes, outBuf, outOffset)).next(numBytes*8);
		// IMPLEMENT THIS
	}



	public static void main(String argv[]) {
		System.out.println("************* testerino stream cipher **************");
		byte[] key = new byte[KeySizeBytes];
		byte[] nonce = new byte[NonceSizeBytes];
		byte[] nonce2 = new byte[NonceSizeBytes];
		byte[] k = new byte[KeySizeBytes];
		byte[] outbuf = new byte[4];
		byte[] outbuf2 = new byte[4];
		int i;
		for(i=0; i<KeySizeBytes; i++) {
			key[i] = (byte)(i ^ 0xaa);
		}
    for (i=0;i<NonceSizeBytes;i++) {
			nonce[i]=(byte)(i^3);
			nonce2[i]=(byte)(i^0xb);
    }
    StreamCipher forwardsc = new StreamCipher(key);
		System.out.println(nonce.length);
    forwardsc.setNonce(nonce, 0);

    StreamCipher backwardsc = new StreamCipher(key);
    backwardsc.setNonce(nonce, 0); //set this to nonce2 to check reset

    byte plain = (byte) 0xaf;
    System.out.println(plain);
    byte encrypted = forwardsc.cryptByte(plain);
    System.out.println(encrypted);

		//backwardsc.setNonce(nonce,0);
		//System.out.println("CHECKING NONCE RESET"+backwardsc.cryptByte(plain));

    System.out.println(backwardsc.cryptByte(encrypted)); //decrypting is same as encrypt

		byte[] plains = new byte[4];
		plains[0] = (byte) 0xaf;
		plains[1] = (byte) 0x07;
		plains[2] = (byte) 0x12;
		plains[3] = (byte) 0x31;
		System.out.println("\nplain:");
		for (i=0; i<4; i++) {
			System.out.println(plains[i]);
		}
		forwardsc.cryptBytes(plains,0,outbuf,0,4);
		System.out.println("\nencrypted:");
		for (i=0; i<4; i++) {
			System.out.println(outbuf[i]);
		}
		backwardsc.cryptBytes(outbuf,0,outbuf2,0,4);
		System.out.println("\ndecrypted:");
		for (i=0; i<4; i++) {
			System.out.println(outbuf2[i]);
		}
		//System.out.println(outbuf);


		//System.out.println(newsc.cryptByte(testByte));
		//System.out.println(newsc.cryptByte(testByte));
		//System.out.println(newsc.cryptByte(testByte));
		//System.out.println(newsc2.cryptByte(testByte));

	}

}
