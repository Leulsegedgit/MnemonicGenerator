package et.solver.utils;



import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;


import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import et.solver.encoding.Base58;
import et.solver.encoding.Bech32;
import et.solver.keys.PublicKey;

public class KeyUtils {

    private static final ECDomainParameters ecSpec;

    static {
        // Initialize secp256k1 curve parameters using Bouncy Castle
        var params = SECNamedCurves.getByName("secp256k1");
        ecSpec = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    }

    public static byte[] getPublicKeyFromPrivateKey(byte[] privateKey) {
        BigInteger privateKeyInt = new BigInteger(HexUtils.bytesToHex(privateKey), 16);

        // Generate the public key point from the private key using the curve's generator point
        ECPoint point = ecSpec.getG().multiply(privateKeyInt);

        boolean compressed = true;

        if (compressed) {
            // Compressed public key format
            byte[] compressedPubKey = point.normalize().getEncoded(true); // true for compressed
            return compressedPubKey;
        } else {
            // Uncompressed public key format
            byte[] uncompressedPubKey = point.normalize().getEncoded(false); // false for uncompressed
            return uncompressedPubKey;
        }
    }

  

    public static String getBitcoinAddress(PublicKey publicKey) throws Exception {
        // 2. Perform Hash160
        byte[] hash160Result = HashUtils.hash160(publicKey.getBytes());
        return Bech32.segwitToBech32("bc", 0, hash160Result);
    }

    public static ECPoint decodePublicKey(byte[] publicKey) {
        ECCurve curve = ecSpec.getCurve();
        try {
            return curve.decodePoint(publicKey);
        } catch (IllegalArgumentException e) {
            // Debug: Provide detailed error information
            System.err.println("Failed to decode public key: " + HexUtils.bytesToHex(publicKey));
            throw e; // Re-throw exception after logging
        }
    }
    

        public static String exportAddress(byte[] key, byte[] chainCode, int depth, int childNumber, byte[] parentFingerprint, boolean isPrivate) {
            try {
                ByteBuffer buffer = ByteBuffer.allocate(78);
    
                // 1. Version: Choose the appropriate prefix based on whether the key is private or public
                byte[] version = isPrivate ? HexUtils.hexToBytes("04b2430c") : HexUtils.hexToBytes("04b24746");
                buffer.put(version);
    
                // 2. Depth: A single byte indicating the depth
                buffer.put((byte) depth);
    
                // 3. Parent Fingerprint: 4 bytes
                if (depth == 0) {
                    // Master key has no parent, so set fingerprint to 0x00000000
                    buffer.put(new byte[]{0x00, 0x00, 0x00, 0x00});
                } else {
                    buffer.put(parentFingerprint);
                }
    
                // 4. Child Number: 4 bytes
                buffer.putInt(depth == 0 ? 0 : childNumber);
    
                // 5. Chain Code: 32 bytes
                buffer.put(chainCode);
    
                // 6. Key: 33 bytes (prepend with 0x00 for private keys)
                if (isPrivate) {
                    buffer.put((byte) 0x00); // Private keys are prepended with 0x00
                }
                buffer.put(key);
    
                byte[] serializedData = buffer.array();
    
                // 7. Add checksum: First 4 bytes of double SHA-256 of serialized data
                byte[] checksum = Arrays.copyOfRange(HashUtils.sha256(HashUtils.sha256(serializedData)), 0, 4);
    
                // 8. Combine serialized data and checksum
                byte[] extendedKeyWithChecksum = ByteBuffer.allocate(serializedData.length + checksum.length)
                                                           .put(serializedData)
                                                           .put(checksum)
                                                           .array();
    
                // 9. Convert to Base58 and return the final address
                return Base58.encode(extendedKeyWithChecksum);
    
            } catch (Exception e) {
                throw new RuntimeException("Error exporting address from extended key", e);
            }
        }
    

}
