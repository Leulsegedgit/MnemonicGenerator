package et.solver.extendedkeys;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import et.solver.keys.PrivateKey;
import et.solver.keys.PublicKey;
import et.solver.utils.HashUtils;
import et.solver.utils.HexUtils;
import et.solver.utils.KeyUtils;

public class ExtendedKeys {

    private static final ECDomainParameters ecSpec;

    static {
        // Initialize secp256k1 curve parameters using Bouncy Castle
        var params = SECNamedCurves.getByName("secp256k1");
        ecSpec = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    }
    
    public static ExtendedPrivateKey seedToExtendedPrivateKey(byte[] seed) {
        try {
            // Define HMAC key as "Bitcoin seed"
            byte[] hmacKey = "Bitcoin seed".getBytes();

            // Generate HMAC-SHA512 hash of the seed
            byte[] i = HashUtils.hmacSha512(seed, hmacKey);

            // Split the HMAC output into master private key (left 32 bytes) and chain code (right 32 bytes)
            byte[] masterPrivateKeyByte = new byte[32];
            byte[] chainCodeByte = new byte[32];
            System.arraycopy(i, 0, masterPrivateKeyByte, 0, 32);
            System.arraycopy(i, 32, chainCodeByte, 0, 32);

            PrivateKey masterPrivateKey = new PrivateKey(masterPrivateKeyByte);
            ChainCode chainCode = new ChainCode(chainCodeByte);

            // Create and return an ExtendedPrivateKey object
            return new ExtendedPrivateKey(masterPrivateKey, chainCode);

        } catch (Exception e) {
            throw new RuntimeException("Error generating extended private key from seed", e);
        }
    }

    public static ExtendedPrivateKey deriveNormalChildKey(ExtendedPrivateKey parentKey, long index) throws InvalidKeyException, NoSuchAlgorithmException {
        if (index < 0 || index > 0x7FFFFFFF) {
            throw new IllegalArgumentException("Index out of range for normal child keys.");
        }

        // 1. Calculate the public key for the parent private key
        byte[] parentPublicKey = parentKey.getExtendedPublicKey().getPublicKey().getBytes();

        // 2. Prepare data for HMAC: public key (32 bytes) + index (4 bytes)
        byte[] data = new byte[parentPublicKey.length + 4];
        System.arraycopy(parentPublicKey, 0, data, 0, parentPublicKey.length);
        System.arraycopy(HexUtils.longToByteArray(index), 0, data, parentPublicKey.length, 4);

        // 3. HMAC-SHA512 with parent chain code as the key
        byte[] hmacResult = HashUtils.hmacSha512(data,parentKey.getChainCode().getBytes());

        // 4. Split the HMAC result: IL (first 32 bytes) and IR (last 32 bytes)
        byte[] IL = new byte[32];
        byte[] IR = new byte[32];
        System.arraycopy(hmacResult, 0, IL, 0, 32);
        System.arraycopy(hmacResult, 32, IR, 0, 32);

        // 5. Derive the child private key: (IL + parent private key) % n
        BigInteger ILInt = new BigInteger(1, IL);
        BigInteger parentPrivateKeyInt = new BigInteger(1, parentKey.getPrivateKey().getBytes());
        BigInteger childPrivateKeyInt = ILInt.add(parentPrivateKeyInt).mod(ecSpec.getN());
        byte[] childPrivateKey = childPrivateKeyInt.toByteArray();

        // Ensure the private key is 32 bytes
        if (childPrivateKey.length > 32) {
            childPrivateKey = Arrays.copyOfRange(childPrivateKey, 1, 33);
        } else if (childPrivateKey.length < 32) {
            byte[] paddedPrivateKey = new byte[32];
            System.arraycopy(childPrivateKey, 0, paddedPrivateKey, 32 - childPrivateKey.length, childPrivateKey.length);
            childPrivateKey = paddedPrivateKey;
        }
        // 6. The new chain code is IR
        return new ExtendedPrivateKey(new PrivateKey(childPrivateKey), new ChainCode(IR));
    }

    public static ExtendedPrivateKey deriveHardenedChildKey(ExtendedPrivateKey parentKey, int indexInt) throws InvalidKeyException, NoSuchAlgorithmException {
        // 1. Ensure the index is in the hardened range
        if (indexInt < 0 || indexInt > 0x7FFFFFFF) {
            throw new IllegalArgumentException("Index out of range for hardened child keys.");
        }
        long index = indexInt + 2147483648L;
    
        // 2. Prepare data for HMAC: 0x00 prefix + private key (32 bytes) + index (4 bytes)
        byte[] data = new byte[1 + parentKey.getPrivateKey().getBytes().length + 4];
        data[0] = 0x00;  // Prefix with 0x00 to indicate the key is private
        System.arraycopy(parentKey.getPrivateKey().getBytes(), 0, data, 1, parentKey.getPrivateKey().getBytes().length);
        System.arraycopy(HexUtils.longToByteArray(index), 0, data, 33, 4);
    
        // 3. HMAC-SHA512 with parent chain code as the key
        byte[] hmacResult = HashUtils.hmacSha512(data,parentKey.getChainCode().getBytes());
    
        // 4. Split the HMAC result: IL (first 32 bytes) and IR (last 32 bytes)
        byte[] IL = new byte[32];
        byte[] IR = new byte[32];
        System.arraycopy(hmacResult, 0, IL, 0, 32);
        System.arraycopy(hmacResult, 32, IR, 0, 32);
    
        // 5. Derive the child private key: (IL + parent private key) % n
        BigInteger ILInt = new BigInteger(1, IL);
        BigInteger parentPrivateKeyInt = new BigInteger(1, parentKey.getPrivateKey().getBytes());
        BigInteger childPrivateKeyInt = ILInt.add(parentPrivateKeyInt).mod(ecSpec.getN());
        byte[] childPrivateKey = childPrivateKeyInt.toByteArray();
    
        // Ensure the private key is 32 bytes
        if (childPrivateKey.length > 32) {
            childPrivateKey = Arrays.copyOfRange(childPrivateKey, 1, 33);
        } else if (childPrivateKey.length < 32) {
            byte[] paddedPrivateKey = new byte[32];
            System.arraycopy(childPrivateKey, 0, paddedPrivateKey, 32 - childPrivateKey.length, childPrivateKey.length);
            childPrivateKey = paddedPrivateKey;
        }
    
        // 6. The new chain code is IR
        return new ExtendedPrivateKey(new PrivateKey(childPrivateKey), new ChainCode(IR));
    }
    
    public static ExtendedPublicKey deriveNormalChildPublicKey(ExtendedPublicKey parentKey, int index) throws InvalidKeyException, NoSuchAlgorithmException {
        if (index < 0 || index > 0x7FFFFFFF) {
            throw new IllegalArgumentException("Index out of range for normal child keys.");
        }

        
        // 1. Prepare data for HMAC: public key (33 bytes) + index (4 bytes)
        byte[] parentPublicKey = parentKey.getPublicKey().getBytes();
        if (parentPublicKey.length != 33) {
            throw new IllegalArgumentException("Invalid compressed public key length: " + parentPublicKey.length);
        }

    
        // Decode the parent public key point
        ECPoint parentPublicKeyPoint = KeyUtils.decodePublicKey(parentPublicKey);

        byte[] data = new byte[parentPublicKey.length + 4];
        System.arraycopy(parentPublicKey, 0, data, 0, parentPublicKey.length);
        System.arraycopy(HexUtils.intToByteArray(index), 0, data, parentPublicKey.length, 4);

        // 2. HMAC-SHA512 with parent chain code as the key
        byte[] hmacResult = HashUtils.hmacSha512(data,parentKey.getChainCode().getBytes());

        // 3. Split the HMAC result: IL (first 32 bytes) and IR (last 32 bytes)
        byte[] IL = new byte[32];
        byte[] IR = new byte[32];
        System.arraycopy(hmacResult, 0, IL, 0, 32);
        System.arraycopy(hmacResult, 32, IR, 0, 32);

        // 4. Calculate the child public key
        BigInteger ILInt = new BigInteger(1, IL);
        ECPoint pointILG = ecSpec.getG().multiply(ILInt);  // Point on the curve from IL * G

        ECPoint childPublicKeyPoint = pointILG.add(parentPublicKeyPoint).normalize();

        // Get the compressed public key
        byte[] childPublicKey = childPublicKeyPoint.getEncoded(true); // true for compressed

        // 5. The new chain code is IR
        return new ExtendedPublicKey(new PublicKey(childPublicKey), new ChainCode(IR));
    }

}
