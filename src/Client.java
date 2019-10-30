import javax.crypto.*;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

// Client.java - Assignment 3
// Author: Leala Darby
// Student Number: 3279478
// Date: 1/11/2019

/**
 * This Client class contains the main flow of the Client behaviour in the SSL handshake process.
 */

public class Client {
	private static Socket socket; //why up here? why static?
    private PublicCode ss = new PublicCode(); //is there a better way? maybe PublicCode can be static?
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        Client client = new Client();
        client.run();
    }
    private void run() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        int port = 25000;
        BigInteger privateKey = new BigInteger("13");
        InetAddress host = InetAddress.getLocalHost(); // get the localhost IP address
		socket = new Socket(host, port);

		OutputStream oStream = socket.getOutputStream();
		OutputStreamWriter oStreamWriter = new OutputStreamWriter(oStream);
		BufferedWriter bWriter = new BufferedWriter(oStreamWriter);

        InputStream iStream = socket.getInputStream(); //is this 'getting' right now?
        InputStreamReader iStreamReader = new InputStreamReader(iStream);
        BufferedReader bReader = new BufferedReader(iStreamReader);

        // SEND Setup_Request: Hello
		String client_init = "Hello";
		String mToSend = client_init + "\n";
		bWriter.write(mToSend);
        bWriter.flush();
        System.out.println("Client to Server: Setup request Hello = " + mToSend);

        // RCVD Setup: Server's RSA public key
        String receivedMessage = bReader.readLine();
        String rsa_e = receivedMessage.substring(2048);
        String rsa_n = receivedMessage.substring(0, 2048);
        System.out.println("Server to Client: Server's RSA public key = " + receivedMessage); // should I print the values for n and e also?

        // SEND Client_Hello: ID_C
        mToSend = UUID.randomUUID().toString() + "\n";
        bWriter.write(mToSend);
        bWriter.flush();
        System.out.println("Client to Server: Client Hello ID_C = " + mToSend);

        // RCVD Server_Hello: ID_S, SID
        receivedMessage = bReader.readLine();
        System.out.println("Server to Client: Server Hello ID_S || SID = " + receivedMessage);

        // SEND Ephemeral DH: Client's Diffie-Hellman public key
        BigInteger clientPublicKey = ss.fastModExp(ss.getDh_g(), privateKey, ss.getDh_p());
        System.out.println("clientPublicKey length: " + clientPublicKey.bitLength());
        mToSend = clientPublicKey.toString() + "\n";
        bWriter.write(mToSend);
        bWriter.flush();
        System.out.println("Client to Server: Client's DH Public Key || rsa signature = " + mToSend);

        // RCVD Ephemeral DH: Server's Diffie-Hellman public key
        receivedMessage = bReader.readLine();
        BigInteger serverPublicKey = new BigInteger(receivedMessage.substring(0, 1024), 2);
        BigInteger signature = new BigInteger(receivedMessage.substring(1024), 2);
        System.out.println("Server to Client: Server's DH Public Key || rsa signature = " + receivedMessage);
        // Signature Verification:
        BigInteger hashedK = ss.getSHA256(serverPublicKey.toString());
        BigInteger check = ss.fastModExp(signature, new BigInteger(rsa_e, 2), new BigInteger(rsa_n, 2));
        if (hashedK.compareTo(check) == 0) {
            System.out.println("Server: Server's session key verified.");
        } else {
            System.out.println("Signature verification failed");
            socket.close();
            return;
        }

        // SEND Finished, check the shared key: Client's hashed session key/nonce pair, and nonce
        BigInteger clientSharedKey = ss.fastModExp(serverPublicKey, privateKey, ss.getDh_p());
        Random rand = new Random();
        BigInteger nonce_C = new BigInteger(1024, rand);
        String toHash = clientSharedKey.toString(2) + nonce_C.toString(2);
        String hashedSessionKey = ss.convertPadBitString(ss.getSHA256(toHash), 256);
        mToSend = hashedSessionKey + nonce_C.toString(2) + "\n";
        bWriter.write(mToSend);
        bWriter.flush();
        System.out.println("Client to Server: Client's hashed Session Key with nonce_C = " + mToSend);

        // RCVD Finished, check the shared key: Server's hashed session key/nonce pair, and nonce
        receivedMessage = bReader.readLine();
        System.out.println("Server to Client: Server's hashed session key/nonce pair, with nonce_S = " + receivedMessage);
        BigInteger hashedSessionKey_S = new BigInteger(receivedMessage.substring(0, 256), 2);
        BigInteger nonce_s = new BigInteger(receivedMessage.substring(256), 2);
        // check validity:
        String testHash = clientSharedKey.toString(2) + nonce_s.toString(2);
        check = new BigInteger(ss.convertPadBitString(ss.getSHA256(testHash), 256), 2);
        if (check.compareTo(hashedSessionKey_S) == 0) {
            System.out.println("Client: Server's session key verified.");
        } else {
            System.out.println("Signature verification failed");
            socket.close();
            return;
        }

        // SEND Data exchange: Client sends M1 via E[Message_1||CBC-MAC(Message_1)]
        BigInteger m1 = new BigInteger(512, rand);//generate message plaintext //TODO: can Random rand be reused?
        String mac = ss.encryptCBC(m1, clientSharedKey);// generate CBC-MAC
        String mToEncrypt = ss.convertPadBitString(m1, 512) + mac;//64 bytes + 64 bytes = 128 bytes (1024 bits)
        String message1 = ss.encryptCTR(new BigInteger(mToEncrypt,2), clientSharedKey) + "\n";
        bWriter.write(message1);
        bWriter.flush();
        System.out.println("Client: Message 1 plaintext = " + ss.convertPadBitString(m1, 512));
        System.out.println("Client to Server: E[Message_1||CBC-MAC(Message_1)] = " + message1);

        // RCVD Data exchange: Client sends M2 via E[Message_2||CBC-MAC(Message_2)]
        receivedMessage = bReader.readLine();
        System.out.println("Server to Client: E[Message_2||CBC-MAC(Message_2)] = " + receivedMessage);
        String decrypted_message = ss.encryptCTR(new BigInteger(receivedMessage,2), clientSharedKey);
        String c_string = decrypted_message.substring(0,512);
        System.out.println("Client: decrypted message 2: " + c_string);
        String test_mac = ss.encryptCBC(new BigInteger(c_string, 2), clientSharedKey);
        if (test_mac.compareTo(decrypted_message.substring(512)) == 0) { // compare received MAC to calculated MAC
            System.out.println("Message successfully authenticated via CBC-MAC");
        } else {
            System.out.println("Signature verification failed");
            socket.close();
            return;
        }

		socket.close();
	}
}
