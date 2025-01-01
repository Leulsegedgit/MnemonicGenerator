package et.solver.extendedkeys;

import java.util.Arrays;

import et.solver.utils.HexUtils;

public class ChainCode {
        private final byte[] keyBytes;

    public ChainCode(byte[] keyBytes) {
        this.keyBytes = Arrays.copyOf(keyBytes, keyBytes.length);
    }

    public byte[] getBytes() {
        return Arrays.copyOf(keyBytes, keyBytes.length);
    }

    public String getHex() {
        return HexUtils.bytesToHex(keyBytes);
    }
}
