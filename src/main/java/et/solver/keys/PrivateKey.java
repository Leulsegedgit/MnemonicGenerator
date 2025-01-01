package et.solver.keys;

import java.math.BigInteger;
import java.util.Arrays;

import et.solver.utils.HexUtils;
import et.solver.utils.KeyUtils;

public class PrivateKey {
    private final byte[] keyBytes;

    private static final BigInteger MIN_PRIVATE_KEY = BigInteger.ONE;
    private static final BigInteger MAX_PRIVATE_KEY = new BigInteger(
            "115792089237316195423570985008687907852837564279074904382605163141518161494336"
    ); // n-1 for secp256k1

    public PrivateKey(byte[] keyBytes) {
        
        if (keyBytes == null || keyBytes.length != 32) {
            throw new IllegalArgumentException("Private key must be a 32-byte array.");
        }

        // Convert the key to BigInteger for range checking
        BigInteger keyInt = new BigInteger(1, keyBytes); // 1 for positive values
        if (keyInt.compareTo(MIN_PRIVATE_KEY) < 0 || keyInt.compareTo(MAX_PRIVATE_KEY) > 0) {
            throw new IllegalArgumentException("Private key is out of range. Must be between 1 and n-1.");
        }

        this.keyBytes = Arrays.copyOf(keyBytes, keyBytes.length);
    }

    public byte[] getBytes() {
        return Arrays.copyOf(keyBytes, keyBytes.length);
    }

    public String getHex() {
        return HexUtils.bytesToHex(keyBytes);
    }

    public PublicKey getPublicKey() {
       byte[] publicKey = KeyUtils.getPublicKeyFromPrivateKey(keyBytes);
       return new PublicKey(publicKey);
    }
}

