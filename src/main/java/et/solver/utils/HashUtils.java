package et.solver.utils;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class HashUtils {
    public static byte[] sha256(byte[] input) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        return sha256.digest(input);
    }

    public static byte[] hmacSha512(byte[] data, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA512");  // Use "HmacSHA512" directly here
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA512");
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    public static byte[] hash160(byte[] publicKey) throws Exception {
    // Add BouncyCastle as a security provider
    Security.addProvider(new BouncyCastleProvider());

    // SHA-256
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    byte[] sha256Result = sha256.digest(publicKey);

    // RIPEMD-160
    MessageDigest ripemd160 = MessageDigest.getInstance("RIPEMD160", "BC");
    return ripemd160.digest(sha256Result);
}
    
}
