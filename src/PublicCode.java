import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.math.BigInteger;
import java.net.*; // for Socket programming
import java.security.MessageDigest; // for SHA256

public class PublicCode {
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
    public static BigInteger getSHA256(String message) throws NoSuchAlgorithmException {
        MessageDigest mdigest = MessageDigest.getInstance("SHA-256");
        mdigest.update(message.getBytes(StandardCharsets.UTF_8)); // getBytes works if rsa_e is a string. convert e to byte array and update the mdigest with this value. next call will operate on the update, and return correct value
        String output = String.format("%064x", new BigInteger(1, mdigest.digest()));//digest the original mdigest, format result as a string
        return new BigInteger(output, 16);
    }

    // Convert a BigInteger into a bit string
    public static String convertPadBitString(BigInteger bInt, int expectedLength){
        int numZeros = expectedLength - bInt.bitLength();
        if (bInt.bitLength() < expectedLength){
            if (bInt.equals(BigInteger.ZERO)){
                numZeros--;
            }
            StringBuilder padding = new StringBuilder();
            padding.append("0".repeat(Math.max(0, numZeros)));
            return padding + bInt.toString(2);
        } else if (bInt.bitLength() > expectedLength){
            return bInt.toString(2).substring(1);
        } else{
            return bInt.toString(2);
        }
    }

    // Assumes a message length of 64 bytes
    public static String encryptCBC(BigInteger p, BigInteger key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        String p_string = convertPadBitString(p, 512); //split plaintext into blocks
        List<BigInteger> plaintext_blocks = new ArrayList<>();
        plaintext_blocks.add(new BigInteger(p_string.substring(0,128),2));
        plaintext_blocks.add(new BigInteger(p_string.substring(128,256),2));
        plaintext_blocks.add(new BigInteger(p_string.substring(256,384),2));
        plaintext_blocks.add(new BigInteger(p_string.substring(384),2));

        BigInteger iv = new BigInteger("0");

        //CBC
        BigInteger encrypted = new BigInteger("0");
        BigInteger xor_vec;
        String result = "";
        for (int i = 0; i < 4; i++){//since the message length is fixed at 64 bytes
            if (i == 0){
                xor_vec = iv.xor(plaintext_blocks.get(i));
            } else{
                xor_vec = encrypted.xor(plaintext_blocks.get(i));
            }

            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            BigInteger aes_key = getSHA256(convertPadBitString(key, 256));
            byte[] kbytes = aes_key.toByteArray();
            SecretKeySpec sharedKey = new SecretKeySpec(kbytes, "AES");

            cipher.init(Cipher.ENCRYPT_MODE, sharedKey);//TODO: what key to use for CBC-MAC vs the message itself?

            List<Integer> byteList = new ArrayList<>();
            for(String str : convertPadBitString(xor_vec, 128).split("(?<=\\G.{8})")) {
                byteList.add(Integer.parseInt(str, 2));
            }
            byte[] bytearray = new byte[16];
            for (int j = 0; j < byteList.size(); j++){
                bytearray[j] = byteList.get(j).byteValue();
            }
            String encryp = Base64.getEncoder().encodeToString(cipher.doFinal(bytearray));
            byte[ ] decode = Base64.getDecoder().decode(encryp);
            encrypted = new BigInteger(1, decode);

            result += convertPadBitString(encrypted, 128);
        }
        return result;
    }

    // Assumes a message length of 128 bytes
    public static String encryptCTR(BigInteger p, BigInteger key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String p_string = convertPadBitString(p, 1024); //split plaintext into blocks.
        List<BigInteger> plaintext_blocks = new ArrayList<>();
        plaintext_blocks.add(new BigInteger(p_string.substring(0,128),2));
        plaintext_blocks.add(new BigInteger(p_string.substring(128,256),2));
        plaintext_blocks.add(new BigInteger(p_string.substring(256,384),2));
        plaintext_blocks.add(new BigInteger(p_string.substring(384,512),2));
        plaintext_blocks.add(new BigInteger(p_string.substring(512,640),2));
        plaintext_blocks.add(new BigInteger(p_string.substring(640,768),2));
        plaintext_blocks.add(new BigInteger(p_string.substring(768,896),2));
        plaintext_blocks.add(new BigInteger(p_string.substring(896),2));

        //Random rand = new Random();
        //BigInteger iv = new BigInteger(128, rand);
        BigInteger iv = new BigInteger("0");

        //CTR
        BigInteger encrypted;
        String result = "";
        for (int i = 0; i < 8; i++){//since the message length is fixed at 128 bytes
            if (i != 0){
                iv = iv.add(BigInteger.ONE);
            }
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

            // convert form of key
            BigInteger aes_key = getSHA256(convertPadBitString(key, 256));
            byte[] kbytes =  aes_key.toByteArray();
            SecretKeySpec sharedKey = new SecretKeySpec(kbytes, "AES");

            cipher.init(Cipher.ENCRYPT_MODE, sharedKey);//TODO: what key to use for CBC-MAC vs the message itself?

            List<Integer> byteList = new ArrayList<>();
            for(String str : convertPadBitString(iv, 128).split("(?<=\\G.{8})")) {
                byteList.add(Integer.parseInt(str, 2));
            }
            byte[] bytearray = new byte[16];
            for (int j = 0; j < byteList.size(); j++){
                bytearray[j] = byteList.get(j).byteValue();
            }
            String encryp = Base64.getEncoder().encodeToString(cipher.doFinal(bytearray));
            byte[ ] decode = Base64.getDecoder().decode(encryp);
            encrypted = new BigInteger(1, decode);
            encryp = encrypted.toString(2);
            BigInteger t = new BigInteger(convertPadBitString(plaintext_blocks.get(i), 1024), 2);

            encrypted = encrypted.xor(plaintext_blocks.get(i));
            result += convertPadBitString(encrypted, 128);
        }
        return result;
    }
}


