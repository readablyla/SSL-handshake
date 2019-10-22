import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.math.BigInteger;
import java.net.*; // for Socket programming
import java.security.MessageDigest; // for SHA256
import java.security.NoSuchAlgorithmException; // SHA256


public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        //int p = 178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239;
        //int g = 174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730

        //Fast modular exponentiation
        BigInteger b = new BigInteger("378555");
        BigInteger e = new BigInteger("8395559");
        BigInteger n = new BigInteger("655375");
        BigInteger result = fastModExp(b,e,n);
        //System.out.println("Result is " + result);

        //RSA
        Random rsa_random = new Random();
        BigInteger p = new BigInteger(1024, 100, rsa_random); //must be a prime?
        BigInteger q = new BigInteger(1024, 100, rsa_random); //must be a prime?
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE)));
        BigInteger rsa_e = new BigInteger("65537");
        BigInteger rsa_n = p.multiply(q);
        BigInteger d = rsa_e.modInverse(m);

        // I thought that a public key was the (n, e) pair, but it says that the public key is
        //the fixed e=65537. This is the message to be sent?

        // find SHA256
        MessageDigest mdigest = MessageDigest.getInstance("SHA-256");
        mdigest.update(rsa_e.toString().getBytes(StandardCharsets.UTF_8)); // getBytes works if rsa_e is a string. convert e to byte array and update the mdigest with this value. next call will operate on the update, and return correct value
        String output = String.format("%064x", new BigInteger(1, mdigest.digest()));//digest the original mdigest, format result as a string
        BigInteger sha_bigInt = new BigInteger(output, 16);
        System.out.println("HashedString: " + output+"\nHashedString as dec: "+sha_bigInt);//correctly converts hex to dec

        // RSA signature generation
        BigInteger s = fastModExp(sha_bigInt, d, rsa_n);
        System.out.println("b: " + sha_bigInt + "\ne: " + d + "\nn: " + rsa_n);
        System.out.println("Result of fastModExp = s: " + s);
        // RSA signature verification
        BigInteger check_h_m = fastModExp(s, rsa_e, rsa_n);
        System.out.println("Compare sha_bigInt: " + sha_bigInt + "\nvs check_h_m: " + check_h_m);

        //Diffie-Hellman
        BigInteger p_ = new BigInteger("23");
		BigInteger g = new BigInteger("2");
		//BigInteger x_a = new BigInteger("3");
		//BigInteger x_b = new BigInteger("5");
		int x_a = 3;
		int x_b = 5;


		BigInteger y_b = g.pow(x_b);
		//find SHA256 of y_b, then s. Server sends y_b||s, and the client computes whether correct.
    }

    public static BigInteger fastModExp(BigInteger b, BigInteger e, BigInteger n){
        if (n.compareTo(BigInteger.ONE) == 0){ //if n == 0
            return BigInteger.ZERO;
        }
        BigInteger result = BigInteger.ONE;
        while (e.compareTo(BigInteger.ZERO) == 1){ //while e > 0
            if (e.testBit(0)){ //if e is odd
                result = (result.multiply(b)).mod(n);
            }
            e = e.shiftRight(1); //binary stuff to divide by 2
            b = (b.multiply(b)).mod(n);
        }
        return result; // does this need to be mod again?
    }
    /*public int keyGen(int p, int g){
        int y; //=(g^x) % p
        return y;
    }

    public int dHex(){

    }*/
}
