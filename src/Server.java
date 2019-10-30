import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.UUID;

public class Server {
    private static Socket socket;
    private PublicCode ss = new PublicCode(); //is there a better way? maybe shareshop can be static?
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
        Server server = new Server();
        server.run();
    }
	private void run() throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
		int port = 25000;
        BigInteger privateKey = new BigInteger("19");
		ServerSocket serverSocket = new ServerSocket(port);
		System.out.println("Server Started and listening to the port 25000"); // change text

        socket = serverSocket.accept();
        InputStream iStream = socket.getInputStream();
        InputStreamReader iStreamReader = new InputStreamReader(iStream);
        BufferedReader bReader = new BufferedReader(iStreamReader);

        OutputStream oStream = socket.getOutputStream();
        OutputStreamWriter oStreamWriter = new OutputStreamWriter(oStream);
        BufferedWriter bWriter = new BufferedWriter(oStreamWriter);

        // RCVD Setup_Request: Hello
        String receivedMessage = bReader.readLine();
        System.out.println("Client to Server: Setup request Hello = " + receivedMessage);

        // SEND Setup: Server's RSA public key
        Random rsa_random = new Random();
        BigInteger p = BigInteger.probablePrime(1024, rsa_random);
        BigInteger q = BigInteger.probablePrime(1024, rsa_random);
        BigInteger n = p.multiply(q); //must be 2048 bits
        BigInteger e = new BigInteger("65537");
        String mToSend = ss.convertPadBitString(n, 2048) + e.toString(2) + "\n";
        bWriter.write(mToSend);
        bWriter.flush();
        System.out.println("Server to Client: Server's RSA public key = " + mToSend);

        //RCVD Client_Hello: ID_C
        receivedMessage = bReader.readLine();
        System.out.println("Client to Server: Client Hello ID_C = " + receivedMessage);

        // SEND Server_Hello: ID_S, SID //TODO: will the ID_C, ID_S, SID ever be used again?
        mToSend = UUID.randomUUID().toString() + "-00-" + UUID.randomUUID().toString() + "\n"; // "-00-" is the delimiter between the ID_S and SID
        bWriter.write(mToSend);
        bWriter.flush();
        System.out.println("Server to Client: Server Hello ID_S||SID = " + mToSend);

        // RCVD Ephemeral DH: Client's Diffie-Hellman public key
        receivedMessage = bReader.readLine();
        BigInteger clientPublicKey = new BigInteger(receivedMessage);
        System.out.println("Client to Server: Client's DH Public Key || rsa signature = " + receivedMessage);

        // SEND Ephemeral DH: Server's Diffie-Hellman public key
        BigInteger serverPublicKey = ss.fastModExp(ss.getDh_g(), privateKey, ss.getDh_p()); // generate Server's DH public key
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE)));
        BigInteger d = e.modInverse(m);
        BigInteger s = ss.fastModExp(ss.getSHA256(serverPublicKey.toString()), d, n); // generate RSA signature s
        mToSend = ss.convertPadBitString(serverPublicKey, 1024) + s.toString(2) + "\n";
        bWriter.write(mToSend);
        bWriter.flush();
        System.out.println("Server to Client: Server's DH Public Key || rsa signature = " + mToSend);

        // RCVD Finished, check the shared key: Client's hashed session key/nonce pair, and nonce
        receivedMessage = bReader.readLine();
        System.out.println("Client to Server: Client's hashed session key/nonce pair, with nonce_C: " + receivedMessage);
        BigInteger hashedSessionKey_C = new BigInteger(receivedMessage.substring(0, 256), 2);
        BigInteger nonce_c = new BigInteger(receivedMessage.substring(256), 2);
        // check validity:
        BigInteger serverSharedKey = ss.fastModExp(clientPublicKey, privateKey, ss.getDh_p());
        String testHash = serverSharedKey.toString(2) + nonce_c.toString(2);
        BigInteger check = new BigInteger(ss.convertPadBitString(ss.getSHA256(testHash), 256), 2);
        if (check.compareTo(hashedSessionKey_C) == 0) {
            System.out.println("Server: Client's session key verified.");
        } else {
            System.out.println("Signature verification failed");
            socket.close();
            return;
        }

        // SEND Finished, check the shared key: Server's hashed session key/nonce pair, and nonce
        Random rand = new Random();//TODO: is it necessary to do this again here?
        BigInteger nonce_S = new BigInteger(1024, rand);
        String toHash = serverSharedKey.toString(2) + nonce_S.toString(2);
        String hashedSessionKey = ss.convertPadBitString(ss.getSHA256(toHash), 256);
        mToSend = hashedSessionKey + nonce_S.toString(2) + "\n";
        bWriter.write(mToSend);
        bWriter.flush();
        System.out.println("Server to Client: Server's hashed session key/nonce pair, with nonce_S = " + mToSend);

        // RCVD Data exchange: Client sends M1 via E[Message_1||CBC-MAC(Message_1)]
        receivedMessage = bReader.readLine();
        System.out.println("Client to Server: E[Message_1||CBC-MAC(Message_1)] = " + receivedMessage);
        String decrypted_message = ss.encryptCTR(new BigInteger(receivedMessage,2),serverSharedKey);
        String c_string = decrypted_message.substring(0,512);
        System.out.println("Server: decrypted message 1 = " + c_string);
        String test_mac = ss.encryptCBC(new BigInteger(c_string, 2), serverSharedKey);
        if (test_mac.compareTo(decrypted_message.substring(512)) == 0) { // compare received MAC to calculated MAC
            System.out.println("Message successfully authenticated via CBC-MAC");
        } else {
            System.out.println("Signature verification failed");
            socket.close();
            return;
        }

        // SEND Data exchange: Server sends M2 via E[Message_2||CBC-MAC(Message_2)]
        BigInteger m2 = new BigInteger(512, rand);//generate message plaintext //TODO: can Random rand be reused?
        String mac = ss.encryptCBC(m2, serverSharedKey);// generate CBC-MAC
        String mToEncrypt = ss.convertPadBitString(m2, 512) + mac;//64 bytes + 64 bytes = 128 bytes total (1024 bits)
        String message2 = ss.encryptCTR(new BigInteger(mToEncrypt,2), serverSharedKey) + "\n";
        bWriter.write(message2);
        bWriter.flush();
        System.out.println("Server: Message 2 plaintext = " + ss.convertPadBitString(m2, 512));//TODO: should this be printed to show that it encrypts/decrypts correctly?
        System.out.println("Server to Client: E[Message_2||CBC-MAC(Message_2)] = " + message2);

		socket.close();
	}
}