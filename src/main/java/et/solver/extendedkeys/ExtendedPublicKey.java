package et.solver.extendedkeys;

import java.util.Arrays;

import et.solver.keys.PublicKey;
import et.solver.utils.HashUtils;
import et.solver.utils.KeyUtils;

public class ExtendedPublicKey {
    private final PublicKey publicKey;
    private final ChainCode chainCode;

    public ExtendedPublicKey(PublicKey publicKey, ChainCode chainCode) {
        this.publicKey = publicKey;
        this.chainCode = chainCode;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public ChainCode getChainCode() {
        return chainCode;
    }

    // Method to derive child public keys (BIP 32 implementation required)
    public ExtendedPublicKey deriveChildKey(int index) {
        // Implement child key derivation logic
        return null;  // Replace with actual derived values
    }

    public String exportAddress(int depth, int childNumber, ExtendedPublicKey parent) throws Exception{
        byte[] parentFingerprint = null;
        if(parent!=null){
            byte[] parentFingerprintFull = HashUtils.hash160(parent.getPublicKey().getBytes());
                   parentFingerprint = Arrays.copyOfRange(parentFingerprintFull, 0, 4);
        }
        
        return KeyUtils.exportAddress(this.publicKey.getBytes(), this.chainCode.getBytes(), depth, childNumber, parentFingerprint, false);
    }

}

