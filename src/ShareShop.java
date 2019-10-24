import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.math.BigInteger;
import java.net.*; // for Socket programming
import java.security.MessageDigest; // for SHA256

public class ShareShop {
    BigInteger dh_g = new BigInteger("174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730");
    BigInteger dh_p = new BigInteger("178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239");
    Random rsa_random = new Random();
    //double check 2048 and 100 are the right numbers to use here
    BigInteger p = new BigInteger(1024, 100, rsa_random); //must be a prime?
    BigInteger q = new BigInteger(1024, 100, rsa_random); //must be a prime?
    BigInteger m = (p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE)));
    BigInteger rsa_e = new BigInteger("65537");
    BigInteger rsa_n = p.multiply(q);
    BigInteger d = rsa_e.modInverse(m);

    public BigInteger getDh_g() {
        return dh_g;
    }
    public BigInteger getDh_p() {
        return dh_p;
    }

    // fastmodexp
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

    // getSHA256 -- can make this static?
    public BigInteger getSHA256(String message) throws NoSuchAlgorithmException {
        MessageDigest mdigest = MessageDigest.getInstance("SHA-256");
        mdigest.update(message.getBytes(StandardCharsets.UTF_8)); // getBytes works if rsa_e is a string. convert e to byte array and update the mdigest with this value. next call will operate on the update, and return correct value
        String output = String.format("%064x", new BigInteger(1, mdigest.digest()));//digest the original mdigest, format result as a string
        return new BigInteger(output, 16);
    }

    // Convert a BigInteger into a bit string
    public String convertPadBitString(BigInteger bInt, int expectedLength){
        if (bInt.bitLength() != expectedLength){
            return "0" + bInt.toString(2);
        } else{
            return bInt.toString(2);
        }
    }

}
