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
import java.util.Random;
import java.util.UUID;

public class Server {
    private static Socket socket;
	public static void main(String[] args) throws UnknownHostException, IOException, ClassNotFoundException, InterruptedException{
		int port = 25000;
        int privateKey = 19;
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
            BigInteger rsa_e = new BigInteger("65537");
            String nString;
            if (n.bitLength() != 2048){
                nString = "0" + n.toString(2);
            } else{
                nString = n.toString(2);
            }
            String mToSend = nString + rsa_e.toString(2) + "\n";
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

            // SEND Ephemeral DH:
            //add run method, create instance of ShareShop
            BigInteger clientPublicKey = (ss.getDh_g().pow(privateKey)).mod(ss.getDh_p());
            BigInteger hashedPublicKey = ss.getSHA256(clientPublicKey.toString());
            //get e and n into their proper form (decimal, BigInteger)
            //how can the client compute s and sign their public key without having d?
            BigInteger m = (p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE)));
            BigInteger d = rsa_e.modInverse(m);
            BigInteger s = ss.fastModExp(hashedPublicKey, d, rsa_n);


			if(receivedMessage.equalsIgnoreCase("exit")) break;


		}
		socket.close();
	}
}
