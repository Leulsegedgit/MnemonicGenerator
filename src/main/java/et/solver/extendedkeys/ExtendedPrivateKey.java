package et.solver.extendedkeys;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import et.solver.encoding.Base58;
import et.solver.keys.PrivateKey;
import et.solver.utils.HashUtils;
import et.solver.utils.KeyUtils;

public class ExtendedPrivateKey {
    private final PrivateKey privateKey;
    private final ChainCode chainCode;

    public ExtendedPrivateKey(PrivateKey privateKey, ChainCode chainCode) {
        this.privateKey = privateKey;
        this.chainCode = chainCode;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public ChainCode getChainCode() {
        return chainCode;
    }

    
    public ExtendedPrivateKey deriveNormalChildKey(int index) throws InvalidKeyException, NoSuchAlgorithmException {
        return ExtendedKeys.deriveNormalChildKey(this, index);
    } 
    public ExtendedPrivateKey deriveHardenedChildKey(int index) throws InvalidKeyException, NoSuchAlgorithmException {
        return ExtendedKeys.deriveHardenedChildKey(this, index);
    }

    public ExtendedPublicKey getExtendedPublicKey(){
        return new ExtendedPublicKey(this.privateKey.getPublicKey(), this.chainCode);
    }
    public String exportAddress(int depth, int childNumber, ExtendedPublicKey parentPublicKey) throws Exception{
        byte[] parentFingerprint = null;
        if(parentPublicKey != null){
            byte[] parentFingerprintFull = HashUtils.hash160(parentPublicKey.getPublicKey().getBytes());
                   parentFingerprint = Arrays.copyOfRange(parentFingerprintFull, 0, 4);    
        }
        return KeyUtils.exportAddress(this.privateKey.getBytes(), this.chainCode.getBytes(), depth, childNumber, parentFingerprint, true);
    }
public String toWIF(){
    return toWIF(this.privateKey.getBytes(), true, true);
}
    /**
     * Converts a private key to Wallet Import Format (WIF).
     *
     * @param privateKey       32-byte private key.
     * @param isMainnet        True if for mainnet, false for testnet.
     * @param isCompressed     True if using compressed public key, false otherwise.
     * @return                 WIF-formatted private key.
     */
    public static String toWIF(byte[] privateKey, boolean isMainnet, boolean isCompressed) {
        if (privateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be exactly 32 bytes.");
        }

        try {
            // 1. Add version byte
            byte version = (byte) (isMainnet ? 0x80 : 0xef);
            byte[] data = new byte[isCompressed ? 34 : 33];
            data[0] = version;

            // 2. Append the private key
            System.arraycopy(privateKey, 0, data, 1, privateKey.length);

            // 3. Add compression byte (if compressed)
            if (isCompressed) {
                data[data.length - 1] = 0x01;
            }

            // 4. Calculate checksum (Hash256 and take first 4 bytes)
            byte[] checksum = Arrays.copyOfRange(HashUtils.sha256(HashUtils.sha256(data)), 0, 4);

            // 5. Combine data and checksum
            byte[] finalData = ByteBuffer.allocate(data.length + checksum.length)
                                         .put(data)
                                         .put(checksum)
                                         .array();

            // 6. Encode in Base58
            return Base58.encode(finalData);

        } catch (Exception e) {
            throw new RuntimeException("Error converting to WIF format", e);
        }
    }
}

