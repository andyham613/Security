
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class SecureChannel extends InsecureChannel {
	// This is just like an InsecureChannel, except that it provides
	//    authenticated encryption for the messages that pass
	//    over the channel.   It also guarantees that messages are delivered
	//    on the receiving end in the same order they were sent (returning
	//    null otherwise).  Also, when the channel is first set up,
	//    the client authenticates the server's identity, and the necessary
	//    steps are taken to detect any man-in-the-middle (and to close the
	//    connection if a MITM is detected).
	//
	// The code provided here is not secure --- all it does is pass through
	//    calls to the underlying InsecureChannel.

	private final int NonceSizeBytes = AuthEncryptor.NonceSizeBytes;
	byte[] key;
	PRGen newprgen;
  AuthEncryptor auth_enc;
  AuthDecryptor auth_dec;
	boolean is_sign_verified;
	int received_counter = 0;
	int sent_counter = 0;

	public SecureChannel(InputStream inStr, OutputStream outStr,
			PRGen rand, boolean iAmServer,
			RSAKey serverKey) throws IOException {
		// if iAmServer==false, then serverKey is the server's *public* key
		// if iAmServer==true, then serverKey is the server's *private* key

		super(inStr, outStr);

		newprgen = rand;
		KeyExchange dh = new KeyExchange(newprgen);
		byte[] outmessage = dh.prepareOutMessage(); //g^b mod p or g^a mod p depending

		if (iAmServer) {
			//***PRIVATE KEY***  WE ARE USING SERVERS PRIVATE KEY. ON SERVER SIDE
			byte[] serversign = serverKey.sign(outmessage,rand);
			super.sendMessage(outmessage);
			super.sendMessage(serversign);



			byte[] received = super.receiveMessage();

			//get key
			key = Proj2Util.hash(dh.processInMessage(received));
			//newprgen = new PRGen(key);

			//check for tampering
			byte[] msg_combined = new byte[received.length + serversign.length + outmessage.length];

			int i;
			for (i=0; i<outmessage.length; i++) {
				msg_combined[i] = outmessage[i];
			}
			for (i=0; i<serversign.length; i++) {
				msg_combined[i + outmessage.length] = serversign[i];
			}
			for (i=0; i<received.length; i++) {
				msg_combined[i + outmessage.length + serversign.length] = received[i];
			}

			byte[] hashed_msg = Proj2Util.hash(msg_combined);
			super.sendMessage(hashed_msg);
			byte[] check = super.receiveMessage();

			for (i =0; i<check.length; i++) {
				if (hashed_msg[i] != check[i]) {
					super.close();
				}
			}


			auth_enc = new AuthEncryptor(key);
			auth_dec = new AuthDecryptor(key);


		} else {
			//***PUBLIC KEY***   WE ARE USING SERVERS PUBLIC KEY. ON CLIENT SIDE

			byte[] received = super.receiveMessage(); // first message
			byte[] sign = super.receiveMessage(); //second message aka signature
			if(serverKey.verifySignature(received,sign)) {
				key = Proj2Util.hash(dh.processInMessage(received));
				super.sendMessage(outmessage);

				//check for tampering
				byte[] msg_combined = new byte[received.length + sign.length + outmessage.length];

				int i;
				for (i=0; i<received.length; i++) {
					msg_combined[i] = received[i];
				}
				for (i=0; i<sign.length; i++) {
					msg_combined[i + received.length] = sign[i];
				}
				for (i=0; i<outmessage.length; i++) {
					msg_combined[i + received.length + sign.length] = outmessage[i];
				}

				byte[] hashed_msg = Proj2Util.hash(msg_combined);
				super.sendMessage(hashed_msg);
				byte[] check = super.receiveMessage();

				for (i =0; i<check.length; i++) {
					if (hashed_msg[i] != check[i]) {
						super.close();
					}
				}

				auth_enc = new AuthEncryptor(key);
				auth_dec = new AuthDecryptor(key);

			} else {
				super.close();
			}
		}
		// IMPLEMENT THIS
	}


	public void sendMessage(byte[] message) throws IOException {
		byte[] nonce = new byte[NonceSizeBytes];
		newprgen.nextBytes(nonce);

		sent_counter++;
		// store int counter as bytes
		byte[] sent_counter_bytes = new byte[4];
		int i;
		for (i = 0; i < 4; i++) {
		  sent_counter_bytes[i] = (byte) (sent_counter >> (8*(3 - i)));
		}

		byte[] msg_w_counter = new byte[message.length + 4];
		for (i = 0; i<message.length; i++) {
			msg_w_counter[i] = message[i];
		}
		for (i=0; i<4; i++) {
			msg_w_counter[i+message.length] = sent_counter_bytes[i];
		}

		byte[] ciphertext = new byte[message.length + 4 + NonceSizeBytes];
	 	ciphertext = auth_enc.encrypt(msg_w_counter, nonce, true);
		super.sendMessage(ciphertext);    // IMPLEMENT THIS
	}

	public byte[] receiveMessage() throws IOException {
		byte[] ciphertext = super.receiveMessage();
		byte[] msg_w_counter = auth_dec.decrypt(ciphertext, null, true);

		received_counter++;
		byte[] received_counter_bytes = new byte[4];
		int i;
		int msglen = msg_w_counter.length - 4;
		for(i=0; i<4; i++) {
			received_counter_bytes[i] = msg_w_counter[i + msglen];
		}
		int stored_counter =0;
		for (i = 0; i < 4; i++) {
			stored_counter = (stored_counter << 8) + (received_counter_bytes[i] & 0xff);
		}
		//make sure counter is same
		byte[] plaintext = new byte[msglen];
		if (received_counter == stored_counter) {
			for (i =0; i< msglen; i++) {
				plaintext[i] = msg_w_counter[i];
			}
			if (plaintext == null) {
				super.close();
			}
		} else {
			super.close();
		}
		return plaintext;
	}
}
