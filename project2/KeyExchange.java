import java.math.BigInteger;
public class KeyExchange {

	public static final int OutputSizeBytes = Proj2Util.HashSizeBytes;
	public static final int OutputSizeBits = Proj2Util.HashSizeBits;

	private BigInteger alice_bint;
	private int KeySize = 256;
	private PRGen newprg;

	public KeyExchange(PRGen rand) {
		// Prepares to do a key exchange. rand is a secure pseudorandom generator
		//    that can be used by the implementation.
		//
		// Once the KeyExchange object is created, two operations have to be performed to complete
		// the key exchange:
		// 1.  Call prepareOutMessage on this object, and send the result to the other
		//     participant.
		// 2.  Receive the result of the other participant's prepareOutMessage, and pass it in
		//     as the argument to a call on this object's processInMessage.
		// For a given KeyExchange object, prepareOutMessage and processInMessage
		// could be called in either order, and KeyExchange should produce the same result regardless.
		//
		// The call to processInMessage should behave as follows:
		//     If passed a null value, then throw a NullPointerException.
		//     Otherwise, if passed a value that could not possibly have been generated
		//        by prepareOutMessage, then return null.
		//     Otherwise, return a "digest" value with the property described below.
		//
		// This code must provide the following security guarantee: If the two
		//    participants end up with the same non-null digest value, then this digest value
		//    is not known to anyone else.   This must be true even if third parties
		//    can observe and modify the messages sent between the participants.
		// This code is NOT required to check whether the two participants end up with
		//    the same digest value; the code calling this must verify that property.

		byte[] alice_bob = new byte[256];
		rand.nextBytes(alice_bob);
		alice_bint = Proj2Util.bytesToBigInteger(alice_bob);
		newprg = rand;

		// IMPLEMENT THIS
	}

	public byte[] prepareOutMessage() {
		BigInteger mod = DHParams.g.modPow(alice_bint, DHParams.p);
		byte[] outbytes = Proj2Util.bigIntegerToBytes(mod, OutputSizeBytes);
		return outbytes; // IMPLEMENT THIS
	}

	public byte[] processInMessage(byte[] inMessage) {
		if (inMessage == null)    throw new NullPointerException();
		BigInteger inMessage_bint = Proj2Util.bytesToBigInteger(inMessage);
		if (inMessage_bint.equals(BigInteger.valueOf(1))) {
			return null;
		} else if (inMessage_bint.equals(DHParams.p.subtract(BigInteger.valueOf(1)))) {
			return null;
		} else {
			BigInteger mod = Proj2Util.bytesToBigInteger(inMessage).modPow(alice_bint, DHParams.p);
			byte[] backtobytes = Proj2Util.bigIntegerToBytes(mod, 256);
			return Proj2Util.hash(backtobytes);
		}
		 // IMPLEMENT THIS
	}
}
