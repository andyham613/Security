Andy Ham (aham)
Project 3 Secure Channel

Purpose is to create a secure channel between client and server to ensure forward secrecy.

In the constructor class for Secure Channel, a KeyExchange class is created to prepare an outmessage. The server creates a signature using that and a given prg, and sends both the outmessage and signature. The client receives two messages, the out message and signature, and verifies the signature of the server, preserving authenticity. This prevents a MITM attack by making the client authenticate the server, since the signature is made from the server's private key. Then both client and server are able to create the same key to send messages securely.

 Also make sure to check for tampering and correct order of messages in the constructor and we keep check the counters for messages sent and received to prevent replay attacks. In sendmessage(), generating new nonces for each message and encrypting them provides confidentiality, and integrity is preserved while decrypting in receivemessage().
