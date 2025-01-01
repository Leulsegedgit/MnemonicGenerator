package et.solver.utils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class MnemonicAndSeed {

    public static byte[] generateSecureRandom(int bitLength) {
        // Check if bit length is valid
        if (bitLength < 128 || bitLength > 256 || bitLength % 32 != 0) {
            throw new IllegalArgumentException("Bit length must be between 128 and 256, and a multiple of 32.");
        }

        // Convert bit length to byte length
        int byteLength = bitLength / 8;
        byte[] randomBytes = new byte[byteLength];

        // Generate cryptographically secure random bytes
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(randomBytes);

        return randomBytes;
    }

    // Assuming `wordList` is a list of words following the BIP39 specification.
    private static final List<String> wordList = loadWordList(); // Placeholder for the actual word list loading method

    // Function to convert entropy to mnemonic
    public static String generateMnemonic(byte[] entropy) throws Exception {
        int entropyBitLength = entropy.length * 8;
    
        // Validate entropy length
        if (entropyBitLength < 128 || entropyBitLength > 256 || entropyBitLength % 32 != 0) {
            throw new IllegalArgumentException("Entropy bit length must be between 128 and 256, and a multiple of 32.");
        }
    
        // Step 1: Generate the checksum
        byte[] hash = HashUtils.sha256(entropy);
        int checksumLength = entropyBitLength / 32;
        int checksum = (hash[0] >> (8 - checksumLength)) & ((1 << checksumLength) - 1);
    
        // Step 2: Combine entropy and checksum into a single bit array
        int combinedBitLength = entropyBitLength + checksumLength;
        byte[] combinedBits = new byte[(combinedBitLength + 7) / 8]; // Ensure enough space by rounding up
    
        System.arraycopy(entropy, 0, combinedBits, 0, entropy.length);
    
        // Add checksum bits to the end of the combined array
        int bitOffset = entropyBitLength % 8;
        if (bitOffset == 0) {
            combinedBits[entropy.length] = (byte) (checksum << (8 - checksumLength));
        } else {
            combinedBits[entropy.length - 1] |= (checksum >> bitOffset);
            if (entropy.length < combinedBits.length) {
                combinedBits[entropy.length] = (byte) (checksum << (8 - bitOffset));
            }
        }
        
        // Step 3: Split the combined bit array into 11-bit words and map to mnemonic
        int[] indices = get11BitChunks(combinedBits, combinedBitLength);
        List<String> mnemonicWords = new ArrayList<>();
        for (int index : indices) {
            mnemonicWords.add(wordList.get(index));
        }
    
        // Join mnemonic words with spaces
        return String.join(" ", mnemonicWords);
    }
    

    public static boolean validateMnemonic(String mnemonic) throws Exception {
        String[] words = mnemonic.split(" ");
        int totalBits = words.length * 11;
        
        // Validate that the mnemonic word count is correct
        if (totalBits < 132 || totalBits > 264 || totalBits % 33 != 0) {
            return false;
        }
        
        // Step 1: Convert mnemonic words to a bit string
        StringBuilder bitString = new StringBuilder();
        for (String word : words) {
            int index = wordList.indexOf(word);
            if (index == -1) {
                return false; // Word not found in word list
            }
            String binaryString = String.format("%11s", Integer.toBinaryString(index)).replace(" ", "0");
            bitString.append(binaryString);
        }
        
        // Step 2: Separate entropy and checksum bits
        int entropyBits = totalBits * 32 / 33;
        int checksumBits = totalBits - entropyBits;
        
        String entropyBitsString = bitString.substring(0, entropyBits);
        String checksumBitsString = bitString.substring(entropyBits);
        
        // Convert entropy bits back to bytes
        byte[] entropy = new byte[entropyBits / 8];
        for (int i = 0; i < entropy.length; i++) {
            entropy[i] = (byte) Integer.parseInt(entropyBitsString.substring(i * 8, (i + 1) * 8), 2);
        }
        
        // Step 3: Calculate checksum for the entropy and compare
        byte[] hash = HashUtils.sha256(entropy);
        int recalculatedChecksum = (hash[0] >> (8 - checksumBits)) & ((1 << checksumBits) - 1);
        int originalChecksum = Integer.parseInt(checksumBitsString, 2);
        
        return originalChecksum == recalculatedChecksum;
    }


    // Helper method to extract 11-bit chunks from a byte array
    private static int[] get11BitChunks(byte[] data, int bitLength) {
        int totalChunks = bitLength / 11;
        int[] chunks = new int[totalChunks];
        
        int bitIndex = 0;
        for (int i = 0; i < totalChunks; i++) {
            int chunk = 0;
            
            // Collect 11 bits
            for (int j = 0; j < 11; j++) {
                int byteIndex = (bitIndex + j) / 8;
                int bitInByte = 7 - ((bitIndex + j) % 8);
                
                if ((data[byteIndex] & (1 << bitInByte)) != 0) {
                    chunk |= (1 << (10 - j)); // Set corresponding bit in the chunk
                }
            }
            chunks[i] = chunk;
            bitIndex += 11;
        }
        
        return chunks;
    }

    public static byte[] mnemonicToSeed(String mnemonic, String passphrase) {
        try {
            // Combine mnemonic and passphrase as per BIP39
            String salt = "mnemonic" + (passphrase != null ? passphrase : "");

             int PBKDF2_ITERATIONS = 2048;
             int SEED_LENGTH_BITS = 512;
            // Use PBKDF2 with HMAC-SHA512
            KeySpec spec = new PBEKeySpec(mnemonic.toCharArray(), salt.getBytes(), PBKDF2_ITERATIONS, SEED_LENGTH_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            byte[] seed = factory.generateSecret(spec).getEncoded();

            return seed;

        } catch (Exception e) {
            throw new RuntimeException("Error generating seed from mnemonic", e);
        }
    }


// Placeholder method for loading the word list
    public static List<String> loadWordList() {
        List<String> words = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                MnemonicAndSeed.class.getClassLoader().getResourceAsStream("bip39-2048.txt")))) {

            String line;
            while ((line = reader.readLine()) != null) {
                words.add(line.trim());
            }

            // Verify the file contains exactly 2048 words
            if (words.size() != 2048) {
                throw new IllegalStateException("Word list must contain exactly 2048 words.");
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to load word list", e);
        }
        return words;
    }
}
