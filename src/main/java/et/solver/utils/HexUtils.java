package et.solver.utils;

public class HexUtils {

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    // Convert byte array to hex string
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    // Convert hex string to byte array
    public static byte[] hexToBytes(String hex) {
        int length = hex.length();
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static byte[] hexStringToByteArray(String hex) {
        int length = hex.length();
        byte[] byteArray = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            byteArray[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                     + Character.digit(hex.charAt(i+1), 16));
        }
        return byteArray;
    }
    public static byte[] binaryStringToByteArray(String binaryString) {
        // Pad the binary string to make its length a multiple of 8
        int length = binaryString.length();
        int remainder = length % 8;
        if (remainder != 0) {
            binaryString = "0".repeat(8 - remainder) + binaryString;
        }

        // Calculate the number of bytes
        int byteCount = binaryString.length() / 8;
        byte[] byteArray = new byte[byteCount];

        // Convert each 8-bit chunk to a byte
        for (int i = 0; i < byteCount; i++) {
            String byteString = binaryString.substring(i * 8, (i + 1) * 8);
            byteArray[i] = (byte) Integer.parseInt(byteString, 2);
        }

        return byteArray;
    }
    // Helper function to convert long to byte array
    public static byte[] longToByteArray(long value) {
        return new byte[]{
            (byte) (value >> 24),
            (byte) (value >> 16),
            (byte) (value >> 8),
            (byte) value
        };
}
public static byte[] intToByteArray(int value) {
    return new byte[]{
            (byte) (value >> 24),
            (byte) (value >> 16),
            (byte) (value >> 8),
            (byte) value
    };
}
}

