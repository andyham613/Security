
public class AuthEncryptor implements Proj1Constants {
	// This class is used to compute the authenticated encryption of values.
	//     Authenticated encryption protects the confidentiality of a value, so that the only
	//     way to recover the initial value is to do authenticated decryption of the value using the
	//     same key and nonce that were used to encrypt it.   At the same time, authenticated encryption
	//     protects the integrity of a value, so that a party decrypting the value using
	//     the same key and nonce (that were used to decrypt it) can verify that nobody has tampered with the
	//     value since it was encrypted.


	//private byte[] key;
	private PRF newprf;
	//private PRGen newprg;
	//private boolean nonceInMessage;
	private byte[] MAC_key;
	private byte[] MAC_code;
	private StreamCipher newsc;

	public AuthEncryptor(byte[] key) {
		assert key.length == KeySizeBytes;
		//newmac =new MAC(key);
		newsc = new StreamCipher(key);

		newprf = new PRF(key);
		MAC_key = newprf.eval(key);

		// IMPLEMENT THIS
	}


	public byte[] encrypt(byte[] in, byte[] nonce, boolean includeNonce) {
		// Encrypts the contents of <in> so that its confidentiality and
		//    integrity are protected against would-be attackers who do
		//    not know the key that was used to initialize this AuthEncryptor.
		// Callers are forbidden to pass in the same nonce more than once;
		//    but this code will not check for violations of this rule.
		// The nonce will be included as part of the output iff <includeNonce>
		//    is true.  The nonce should be in plaintext if it is included.
		//
		// This returns a newly allocated byte[] containing the authenticated
		//    encryption of the input.

		int out_length = in.length + MAC_key.length;
		if (includeNonce == true) {
			out_length += nonce.length;
		}
		byte[] encrypted = new byte[in.length];
		byte[] outbuf = new byte[out_length];
		newsc.setNonce(nonce);
		newsc.cryptBytes(in, 0, encrypted, 0,in.length);

		newprf = new PRF(MAC_key);
		MAC_code = newprf.eval(encrypted);

		int i;
		//fill in outbuf array
		for (i = 0; i<encrypted.length; i++) {
			//output length is greater than encrypted length
			outbuf[i] = encrypted[i];
		}
		for (i = 0; i<MAC_code.length; i++) {
			outbuf[i + encrypted.length] = MAC_code[i];
		}
		System.out.println("encrypted len:  "+encrypted.length);
		System.out.println("maccode len:   "+MAC_code.length);
		System.out.println("non len:    "+nonce.length);
		System.out.println("outbuf len:    "+out_length);
		if (includeNonce == true) {
			for (i = 0; i<nonce.length; i++) {
				outbuf[i + encrypted.length + MAC_code.length] = nonce[i];
			}
		}
		return outbuf; // IMPLEMENT THIS
	}
}
