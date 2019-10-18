import java.util.*;
import java.math.BigInteger;
import java.net.*; // for Socket programming
import java.security.MessageDigest; // for SHA256


public class Main {
    public static void main(String[] args) {
        //int p = 178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239;
        //int g = 174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730

        //Fast modular exponentiation
        BigInteger b = new BigInteger("378555");
        BigInteger e = new BigInteger("8395559");
        BigInteger n = new BigInteger("655375");
        BigInteger result = fastModExp(b,e,n);
        System.out.println("Result is " + result);

        //RSA
        Random rsa_random = new Random();
        //double check 2048 and 100 are the right numbers to use here
        BigInteger p = new BigInteger(2048, 100, rsa_random);
        BigInteger q = new BigInteger(2048, 100, rsa_random);
        BigInteger rsa_e = new BigInteger("65537");
        BigInteger rsa_n = p.multiply(q);
        BigInteger[] rsa_servers_public_key = new BigInteger[2];
        rsa_servers_public_key[0] = rsa_n;
        rsa_servers_public_key[1] = rsa_e;

        /*//Diffie-Hellman
        int p = 23;
        int g = 2;*/
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
