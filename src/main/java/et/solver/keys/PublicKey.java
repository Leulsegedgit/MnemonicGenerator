package et.solver.keys;

import java.util.Arrays;

import et.solver.utils.HexUtils;

public class PublicKey {
    private final byte[] keyBytes;

    public PublicKey(byte[] keyBytes) {
        this.keyBytes = Arrays.copyOf(keyBytes, keyBytes.length);
    }

    public byte[] getBytes() {
        return Arrays.copyOf(keyBytes, keyBytes.length);
    }

    public String getHex() {
        return HexUtils.bytesToHex(keyBytes);
    }
}
