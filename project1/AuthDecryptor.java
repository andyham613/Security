
public class AuthDecryptor implements Proj1Constants {
	// This class is used to decrypt and authenticate a sequence of values that were encrypted
	//     by an AuthEncryptor.

	private PRF newprf;
	private byte[] MAC_key;
	private byte[] MAC_code;
	private StreamCipher newsc;

	public AuthDecryptor(byte[] key) {
		assert key.length == KeySizeBytes;
		//same as auth encryptor
		newsc = new StreamCipher(key);

		newprf = new PRF(key);
		MAC_key = newprf.eval(key);

		// IMPLEMENT THIS
	}

	public byte[] decrypt(byte[] in, byte[] nonce, boolean nonceIncluded) {
		// Decrypt and authenticate the contents of <in>.  The value passed in will normally
		//    have been created by calling encrypt() with the same nonce in an AuthEncryptor
		//    that was initialized with the same key as this AuthDecryptor.
		// If <nonceIncluded> is true, then the nonce has been included in <in>, and
		//    the value passed in as <nonce> will be disregarded.
		// If <nonceIncluded> is false, then the value of <nonce> will be used.
		// If the integrity of <in> cannot be verified, then this method returns null.   Otherwise it returns
		//    a newly allocated byte-array containing the plaintext value that was originally
		//    passed to encrypt().

		//do the reverse
		int plaint_length = in.length - MAC_key.length;
		System.out.println("mackey len is : " + MAC_key.length);
		if (nonceIncluded == true) {
			System.out.println("nonce lgnth is : " + nonce.length);
			plaint_length -= nonce.length ;
		}
		byte[] encrypted = new byte[plaint_length];
		MAC_code = new byte[MAC_key.length];
		byte[] nonce_isolated = new byte[NonceSizeBytes];
		int i;
		for (i =0; i<plaint_length; i++) {
			encrypted[i] = in[i];
		}
		for (i = 0; i<MAC_key.length; i++) {
			MAC_code[i] = in[i + plaint_length];
		}
		if (nonceIncluded == true) {
			for(i = 0; i<nonce.length; i++) {
				nonce_isolated[i] = in[i +plaint_length + MAC_key.length];
				//System.out.println("nonce: " + nonce_isolated[i]);
			}
		}
		newprf = new PRF(MAC_key);
		System.out.println("testing array equality: \n");
		byte[] test = newprf.eval(encrypted);
		System.out.println(test.length);
		System.out.println(MAC_code.length);

		int equal_to_mac = 1;
		for (i = 0; i<test.length; i++) {
			//System.out.println("newprfeval(encrypt): " + " " + i +" " +test[i] + " this is mac: " + MAC_code[i]);
			if (test[i] != MAC_code[i]) {
				equal_to_mac = 0;
			}
		}
		int nonces_equal = 1;
		if (nonceIncluded == true){
			for (i = 0; i<nonce.length; i++) {
				if (nonce[i] != nonce_isolated[i]) {
					nonces_equal =0;
				}
			}
		}
		System.out.println(test.length);
		System.out.println(test.length + plaint_length);
		System.out.println(equal_to_mac);
		System.out.println(nonces_equal);

		//so if mac code doesnt match OR nonces dont match, return null;
		if (equal_to_mac == 1 && nonces_equal == 1) {
			byte[] outbuf = new byte[plaint_length];
			newsc.setNonce(nonce);
			newsc.cryptBytes(encrypted, 0, outbuf, 0, plaint_length);
			return outbuf;
		} else {
			return null;
		} // IMPLEMENT THIS
	}

	public static void main(String[] argv) {
		System.out.println("************* testerino auth enc/dec **************");
		byte[] key = new byte[KeySizeBytes];
		byte[] key2 = new byte[KeySizeBytes];
		byte[] nonce = new byte[NonceSizeBytes];
		byte[] nonce2 = new byte[NonceSizeBytes];
		for(int i=0; i<KeySizeBytes; i++) {
			key[i] = (byte)(i^7);
			key2[i] = (byte) (i ^0x33);
		}
		for (int i=0;i<NonceSizeBytes;i++) {
			nonce[i]=(byte)(i^0xc);
			nonce2[i] = (byte) ((i * 5) ^ 0xaa);
		}

		byte[] plains = new byte[4];
		plains[0] = (byte) 0xc;
		plains[1] = (byte) 0xf;
		plains[2] = (byte) 0x23;
		plains[3] = (byte) 0x05;

		AuthEncryptor newenc = new AuthEncryptor(key);
		byte[] encrypted = newenc.encrypt(plains, nonce2, true);

		AuthDecryptor newdec = new AuthDecryptor(key);
		byte[] decrypted = newdec.decrypt(encrypted, nonce2, true);

		System.out.print("\nOG    ENC    DEC\n");
		for (int i=0;i<plains.length;i++) {
			System.out.print(plains[i] + "    ");
			System.out.print(encrypted[i] + "     ");
			System.out.print(decrypted[i] + "     \n");
		}

	}
}
