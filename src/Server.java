//https://www.careerbless.com/samplecodes/java/beginners/socket/SocketBasic1.php
//https://www.journaldev.com/741/java-socket-programming-server-client
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.io.IOException;//shouldn't need?
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.UUID;

public class Server {
    private static Socket socket;
    private ShareShop ss = new ShareShop(); //is there a better way? maybe shareshop can be static?
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        Server server = new Server();
        server.run();
    }
	private void run() throws IOException, NoSuchAlgorithmException {
		int port = 25000;
        BigInteger privateKey = new BigInteger("19");
		ServerSocket serverSocket = new ServerSocket(port);
		System.out.println("Server Started and listening to the port 25000");//change text

		//Keep server running using while(true) loop. Needed?
		while(true){
            socket = serverSocket.accept();
            InputStream iStream = socket.getInputStream();
            InputStreamReader iStreamReader = new InputStreamReader(iStream);
            BufferedReader bReader = new BufferedReader(iStreamReader);

		    OutputStream oStream = socket.getOutputStream();
            OutputStreamWriter oStreamWriter = new OutputStreamWriter(oStream);
            BufferedWriter bWriter = new BufferedWriter(oStreamWriter);

            // RCVD Setup_Request: Hello
            String receivedMessage = bReader.readLine();
            System.out.println("Client to Server: " + receivedMessage);

            // SEND Setup: Server's RSA public key
            Random rsa_random = new Random();
            BigInteger p = BigInteger.probablePrime(1024, rsa_random);
            BigInteger q = BigInteger.probablePrime(1024, rsa_random);
            BigInteger n = p.multiply(q); //must be 2048 bits
            BigInteger e = new BigInteger("65537");
            String mToSend = ss.convertPadBitString(n, 2048) + e.toString(2) + "\n";
            bWriter.write(mToSend);
            bWriter.flush();
            System.out.println("Server to Client: " + mToSend);

            //RCVD Client_Hello: ID_C
            receivedMessage = bReader.readLine();
            System.out.println("Client to Server: ID_C = " + receivedMessage);

            // SEND Server_Hello: ID_S, SID //TODO: will the ID_C, ID_S, SID ever be used again?
            mToSend = UUID.randomUUID().toString() + "-00-" + UUID.randomUUID().toString() + "\n";
            bWriter.write(mToSend);
            bWriter.flush();
            System.out.println("Server to Client: " + mToSend);

            // RCVD Ephemeral DH: Client's Diffie-Hellman public key
            receivedMessage = bReader.readLine();
            BigInteger clientPublicKey = new BigInteger(receivedMessage);
            System.out.println("Client to Server: Client's DH Public Key = " + receivedMessage);

            // SEND Ephemeral DH: Server's Diffie-Hellman public key
            BigInteger serverPublicKey = ss.fastModExp(ss.getDh_g(), privateKey, ss.getDh_p());
            BigInteger m = (p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE)));
            BigInteger d = e.modInverse(m);
            BigInteger s = ss.fastModExp(ss.getSHA256(serverPublicKey.toString()), d, n);

            System.out.println("Server public key = " + serverPublicKey);
            System.out.println("Server sig = " + s);

                // Convert to padded binary string
            mToSend = ss.convertPadBitString(serverPublicKey, 1024) + s.toString(2) + "\n";//not padding sig anymore
            bWriter.write(mToSend);
            bWriter.flush();
            System.out.println("Server to Client: Server's DH Public Key || rsa signature = " + mToSend);

            // RCVD
            receivedMessage = bReader.readLine();
            System.out.println("Client to Server: Client's hashed session key/nonce pair, and nonce: " + receivedMessage);
            System.out.println("received message length: " + new BigInteger(receivedMessage,2).bitLength());
            BigInteger hashedSessionKey_C = new BigInteger(receivedMessage.substring(0, 256), 2);
            BigInteger nonce_c = new BigInteger(receivedMessage.substring(256), 2);
            System.out.println("hashedSessionKey_C: " + hashedSessionKey_C);
            System.out.println("nonce_c: " + nonce_c);
            // check validity:
            BigInteger serverSharedKey = ss.fastModExp(clientPublicKey, privateKey, ss.getDh_p());
            System.out.println("serverSharedKey " + serverSharedKey);
            String testHash = serverSharedKey.toString(2) + nonce_c.toString(2);
            BigInteger check = new BigInteger(ss.convertPadBitString(ss.getSHA256(testHash), 256), 2);
            System.out.println("check: " + check);
            System.out.println("compare: " + check.compareTo(hashedSessionKey_C));
            if (check.compareTo(hashedSessionKey_C) != 0){
                System.out.println("Signature verification failed");
                receivedMessage = "exit";
            }

            // SEND
            Random rand = new Random();
            BigInteger nonce_S = new BigInteger(1024, rand);
            String toHash = serverSharedKey.toString(2) + nonce_S.toString(2);
            String hashedSessionKey = ss.convertPadBitString(ss.getSHA256(toHash), 256);
            mToSend = hashedSessionKey + nonce_S.toString(2) + "\n";
            bWriter.write(mToSend);
            bWriter.flush();
            System.out.println("Server to Client: Server's hashed Session Key with nonce_c = " + mToSend);




			if(receivedMessage.equalsIgnoreCase("exit")) break;
		}
		socket.close();
	}
}
