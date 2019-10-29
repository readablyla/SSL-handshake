import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.io.IOException;//shouldn't need?
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Client {
	private static Socket socket; //why up here? why static?
    private ShareShop ss = new ShareShop(); //is there a better way? maybe shareshop can be static?
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        Client client = new Client();
        client.run();
    }
    private void run() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        int port = 25000;
        BigInteger privateKey = new BigInteger("13");
        //get the localhost IP address
        InetAddress host = InetAddress.getLocalHost();
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
        System.out.println("Client to Server: " + mToSend);

        // RCVD Setup: Server's RSA public key
        String receivedMessage = bReader.readLine();
        String rsa_e = receivedMessage.substring(2048);
        String rsa_n = receivedMessage.substring(0, 2048);
        System.out.println("Server to Client: " + receivedMessage); // should I print the values for n and e also?

        // SEND Client_Hello: ID_C
        //String uniqueID = UUID.randomUUID().toString().replaceAll("\\D","") + "\n";
        //mToSend = uniqueID;
        mToSend = UUID.randomUUID().toString() + "\n";
        bWriter.write(mToSend);
        bWriter.flush();
        System.out.println("Client to Server: ID_C = " + mToSend);

        // RCVD Server_Hello: ID_S, SID
        receivedMessage = bReader.readLine();
        System.out.println("Server to Client: ID_S || SID = " + receivedMessage);

        // SEND Ephemeral DH: Client's Diffie-Hellman public key
        BigInteger clientPublicKey = ss.fastModExp(ss.getDh_g(), privateKey, ss.getDh_p());
        System.out.println("clientPublicKey length: " + clientPublicKey.bitLength());
        mToSend = clientPublicKey.toString() + "\n";
        bWriter.write(mToSend);
        bWriter.flush();
        System.out.println("Client to Server: Client's DH Public Key = " + mToSend);

        // RCVD Ephemeral DH: Server's Diffie-Hellman public key
        receivedMessage = bReader.readLine();
        System.out.println("received message length: " + new BigInteger(receivedMessage,2).bitLength());
        BigInteger serverPublicKey = new BigInteger(receivedMessage.substring(0, 1024), 2);
        BigInteger signature = new BigInteger(receivedMessage.substring(1024), 2);
        System.out.println("Server to Client: Server's DH Public Key || rsa signature = " + receivedMessage);
        System.out.println("Server public key = " + serverPublicKey);
        System.out.println("Server sig = " + signature);

        // Signature Verification:
        BigInteger hashedK = ss.getSHA256(serverPublicKey.toString());
        BigInteger check = ss.fastModExp(signature, new BigInteger(rsa_e, 2), new BigInteger(rsa_n, 2));
        System.out.println("LHS: " + hashedK);
        System.out.println("RHS: " + check);
        //implement a check that ends the session now if they don't match
        if (hashedK.compareTo(check) != 0){
            System.out.println("Signature verification failed");
            bWriter.write("exit");
            bWriter.flush();
            socket.close();
        }

        // Finished, check the shared key: Client's shared key
        BigInteger clientSharedKey = ss.fastModExp(serverPublicKey, privateKey, ss.getDh_p());
        Random rand = new Random();
        BigInteger nonce_C = new BigInteger(1024, rand);
        String toHash = clientSharedKey.toString(2) + nonce_C.toString(2);
        System.out.println("clientSharedKey:  " + clientSharedKey);
        System.out.println("clientSharedKey length: " + clientSharedKey.bitLength());
        System.out.println("nonce_C:  " + nonce_C);
        System.out.println("nonce_C length: " + nonce_C.bitLength());
        System.out.println("toHash: " + toHash);
        String hashedSessionKey = ss.convertPadBitString(ss.getSHA256(toHash), 256);
        System.out.println("hashedSessionKey: " + hashedSessionKey);
        mToSend = hashedSessionKey + nonce_C.toString(2) + "\n";
        bWriter.write(mToSend);
        bWriter.flush();
        System.out.println("Client to Server: Client's hashed Session Key with nonce_c = " + mToSend);

        // RCVD
        receivedMessage = bReader.readLine();
        System.out.println("Client to Server: Client's hashed session key/nonce pair, and nonce: " + receivedMessage);
        System.out.println("received message length: " + new BigInteger(receivedMessage,2).bitLength());
        BigInteger hashedSessionKey_S = new BigInteger(receivedMessage.substring(0, 256), 2);
        BigInteger nonce_s = new BigInteger(receivedMessage.substring(256), 2);
        System.out.println("hashedSessionKey_S: " + hashedSessionKey_S);
        System.out.println("nonce_S: " + nonce_s);
        // check validity:
        System.out.println("clientSharedKey " + clientSharedKey);
        String testHash = clientSharedKey.toString(2) + nonce_s.toString(2);
        check = new BigInteger(ss.convertPadBitString(ss.getSHA256(testHash), 256), 2);
        System.out.println("check: " + check);
        System.out.println("compare: " + check.compareTo(hashedSessionKey_S));
        if (check.compareTo(hashedSessionKey_S) != 0){
            System.out.println("Signature verification failed");
            bWriter.write("exit");
            bWriter.flush();
            socket.close();
            //this does not end it!
        }

        // SEND M1 - add CBC MAC then encrypt
        BigInteger m1 = new BigInteger(512, rand);//generate message plaintext //TODO: can Random rand be reused?
        System.out.println("m1: " + ss.convertPadBitString(m1, 512));
        String mac = ss.encryptCBC(m1, clientSharedKey);// generate CBC-MAC //TODO: invalid AES key length: 33 bytes
        System.out.println("mac: " + mac);
        BigInteger macNum = new BigInteger(mac, 2);
        System.out.println("mac num: " +macNum);
        System.out.println("mac bits: "+macNum.bitLength());
        String mToEncrypt = ss.convertPadBitString(m1, 512) + mac;//64 bytes + 64 bytes = 128 bytes (1024 bits)
        System.out.println("mToEncrypt: " + mToEncrypt);
        String message1 = ss.encryptCTR(new BigInteger(mToEncrypt,2), clientSharedKey);//
        System.out.println("message1: " + message1);


        String decryptedmessage1 = ss.encryptCTR(new BigInteger(message1,2),clientSharedKey);
        System.out.println("decrypted message: " + decryptedmessage1);
        System.out.println("mToEncrypt       : " + mToEncrypt);
        String c_string = decryptedmessage1.substring(0,512);
        String mac_string = decryptedmessage1.substring(512);
        String test_mac = ss.encryptCBC(new BigInteger(c_string, 2), clientSharedKey);
        System.out.println("test_mac    : "+test_mac);
        System.out.println("received mac: "+mac_string);


        /*byte[] input = m1.getBytes(StandardCharsets.UTF_8);
        String s = Base64.getEncoder().encodeToString(input);
        System.out.println(s);
        //mToSend = m1 + t;*/

		socket.close();
	}
}
