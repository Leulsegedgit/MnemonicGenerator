package et.solver;

import java.util.Scanner;

import et.solver.extendedkeys.ExtendedKeys;
import et.solver.extendedkeys.ExtendedPrivateKey;
import et.solver.utils.HexUtils;
import et.solver.utils.KeyUtils;
import et.solver.utils.MnemonicAndSeed;

/**
 * Hello world!
 */
public class App {
    public static void main(String[] args) throws Exception {
        String check = check() ? "Check passed!" : "WARNING SOME CHECKS HAVE FAILD, NEED TO REVIEW THE CODE!";
        System.out.println(check);
        if(!check()) throw new Exception(check);

        
        System.out.println("Choose function\n1.Generate random\n2.From mnemonic");
        Scanner scanner = new Scanner(System.in);
        int command = scanner.nextInt();
        scanner.nextLine(); // Consume the newline left by nextInt()
        switch (command) {
            case 1:
                generateRandom(scanner);
                break;
            case 2:
                fromMnemonic(scanner);
                break;
            default:
                break;
        }
        scanner.close();
    }

public static void generateRandom(Scanner scanner) throws Exception{
    System.out.println("Enter your optional passphrase (press Enter to skip):");
        String passphrase = scanner.nextLine().trim();
    
    byte[] entropy = MnemonicAndSeed.generateSecureRandom(128);
    String mnemonic = MnemonicAndSeed.generateMnemonic(entropy);
    if(!MnemonicAndSeed.validateMnemonic(mnemonic))throw new Exception("Invalid mnemonic");
    byte[] seed = MnemonicAndSeed.mnemonicToSeed(mnemonic, passphrase);

    ExtendedPrivateKey extendedMasterPrivateKey = ExtendedKeys.seedToExtendedPrivateKey(seed);
    ExtendedPrivateKey m84h0h0h = extendedMasterPrivateKey.deriveHardenedChildKey(84)
                                                          .deriveHardenedChildKey(0)
                                                          .deriveHardenedChildKey(0);
    String zpub = m84h0h0h.getExtendedPublicKey().exportAddress(0, 0, null);
    ExtendedPrivateKey m84h0h0h0n0n = m84h0h0h.deriveNormalChildKey(0)
                                              .deriveNormalChildKey(0);
    String wif = m84h0h0h0n0n.toWIF();                                          
    String address = KeyUtils.getBitcoinAddress(m84h0h0h0n0n.getExtendedPublicKey().getPublicKey());                                          
                                                       
    System.out.println("Mnemonic: "+mnemonic);
    if(passphrase.length()>0)
    System.out.println("Passphrase: "+passphrase);
    System.out.println("zpub(m'/84'/0'/0'): "+zpub);
    System.out.println("WIF(m'/84'/0'/0'/0/0): "+wif);
    System.out.println("Address(m'/84'/0'/0'/0/0): "+address);

        
}

public static void fromMnemonic(Scanner scanner) throws Exception{
    String mnemonic = null;
        while (true) {
            System.out.println("Enter your 12-word mnemonic, separated by single spaces:");
            mnemonic = scanner.nextLine().trim();
            if (MnemonicAndSeed.validateMnemonic(mnemonic)) {
                break;
            } else {
                System.out.println("Invalid mnemonic. Please ensure it's exactly 12 words.");
            }
        }

        System.out.println("Enter your optional passphrase (press Enter to skip):");
        String passphrase = scanner.nextLine().trim();
    
    
    
    byte[] seed = MnemonicAndSeed.mnemonicToSeed(mnemonic, passphrase);

    ExtendedPrivateKey extendedMasterPrivateKey = ExtendedKeys.seedToExtendedPrivateKey(seed);
    ExtendedPrivateKey m84h0h0h = extendedMasterPrivateKey.deriveHardenedChildKey(84)
                                                          .deriveHardenedChildKey(0)
                                                          .deriveHardenedChildKey(0);
    String zpub = m84h0h0h.getExtendedPublicKey().exportAddress(0, 0, null);
    ExtendedPrivateKey m84h0h0h0n0n = m84h0h0h.deriveNormalChildKey(0)
                                              .deriveNormalChildKey(0);
    String wif = m84h0h0h0n0n.toWIF();                                          
    String address = KeyUtils.getBitcoinAddress(m84h0h0h0n0n.getExtendedPublicKey().getPublicKey());                                          
                                                       
    System.out.println("Mnemonic: "+mnemonic);
    if(passphrase.length()>0)
    System.out.println("Passphrase: "+passphrase);
    System.out.println("zpub(m'/84'/0'/0'): "+zpub);
    System.out.println("WIF(m'/84'/0'/0'/0/0): "+wif);
    System.out.println("Address(m'/84'/0'/0'/0/0): "+address);
}














































    public static boolean check() throws Exception {
       
        String entropyBinary = "11001010101111011101100111111010001111000101010001"+
                               "001010001110101010011111000000111011001000010010111001101010011011010111100111";
        byte[] entropy = HexUtils.binaryStringToByteArray(entropyBinary);

        String mnemonic =  "skirt uphold leader judge dwarf bubble pair budget lucky snap hope soldier";


        String seedHex = "3471D2AD6D0474A40E1DC40ACF32B135C60750ADBB0772596FF1837B7586A1FD57C510B55DB9334266A77C99B3615A1D79188FD3182ED3B3F601180F26921EEC";
        byte[] seed = HexUtils.hexStringToByteArray(seedHex);
        
        String MasterPrivateKey = "E0950A3619AFBC8F68A805BA99C7EAE461ECDFA89DB8824EA92AB2053FACBD38";
        String MasterChainCode = "A1519D56598D6E26BEEDBE9AD436014F163D5DA1E65ADCD4F30B44060EC182DF";
        String MasterPublicKey = "022D549C5BC08460FD300A715A954DA61CC0EBDA3B318F5818F4F784CD99981CD9";
        String normalChild0PrivateKey = "3219903EE0EFE9A8919456AD2DF6ECE78725AD9891D74D089A25E9D4DCFE75A7";
        String normalChild0PublicKey = "0251DA21E87F34D76EDA43DFD304B20E82DB0BDD8B17A2586ADADA6CA2D09379E5";
        String hardnedChild0PrivateKey = "76E26D6DB9B70B0FA21BF6224CFA062A1BD34F8BA24480CA21B02539E222E2D6";
        String m84h0h0hPubExportAddress = "zpub6jftahH18ngZwH7e4oxgzxBijBzn5Mq8uvz3kiizNjpcZv6oP8JJgiRY7EMGhha1LjvTXpoqpEd9FhLn5hjTutccZnygBH26WQj1vt4hMJy";
        String m84h0h0h0n0nWIF = "L47xtCV9jbJxT5TKzewzmf8c7vnvjrpGUrrn7taWavzwfkhvPeyQ";
        String m84h0h0h0n0nBitcoinAddress = "bc1qs9yuuhzpx04xnlxrymg9pezl472y7uzgt8j75s";

        boolean check_1 = mnemonic.equals(MnemonicAndSeed.generateMnemonic(entropy));
        boolean check_2 = seedHex.equals(HexUtils.bytesToHex(MnemonicAndSeed.mnemonicToSeed(mnemonic, "")));
        boolean check_3 = MnemonicAndSeed.validateMnemonic(mnemonic);

        ExtendedPrivateKey masExtendedPrivateKey = ExtendedKeys.seedToExtendedPrivateKey(seed);
        boolean check_4 = MasterPrivateKey.equals(masExtendedPrivateKey.getPrivateKey().getHex());
        boolean check_5 = MasterChainCode.equals(HexUtils.bytesToHex(masExtendedPrivateKey.getChainCode().getBytes()));
        boolean check_6 = MasterPublicKey.equals(HexUtils.bytesToHex(masExtendedPrivateKey.getExtendedPublicKey().getPublicKey().getBytes()));

        ExtendedPrivateKey normalChild0ExtendedPrivateKey = masExtendedPrivateKey.deriveNormalChildKey(0);
        boolean check_7 = normalChild0PrivateKey.equals(normalChild0ExtendedPrivateKey.getPrivateKey().getHex());
        boolean check_8 = normalChild0PublicKey.equals(normalChild0ExtendedPrivateKey.getExtendedPublicKey().getPublicKey().getHex());
        
        ExtendedPrivateKey hardenedChild0ExtendedPrivateKey = masExtendedPrivateKey.deriveHardenedChildKey(0);
        boolean check_9 = hardnedChild0PrivateKey.equals(hardenedChild0ExtendedPrivateKey.getPrivateKey().getHex());

        ExtendedPrivateKey m84h0h0h = masExtendedPrivateKey.deriveHardenedChildKey(84).deriveHardenedChildKey(0).deriveHardenedChildKey(0);
        boolean check_10 = m84h0h0hPubExportAddress.equals(m84h0h0h.getExtendedPublicKey().exportAddress(0, 0, null));
        ExtendedPrivateKey m84h0h0h0n0n = masExtendedPrivateKey.deriveHardenedChildKey(84).deriveHardenedChildKey(0).deriveHardenedChildKey(0).deriveNormalChildKey(0).deriveNormalChildKey(0);
        boolean check_11 = m84h0h0h0n0nWIF.equals(m84h0h0h0n0n.toWIF());
        boolean check_12 = m84h0h0h0n0nBitcoinAddress.equals(KeyUtils.getBitcoinAddress(m84h0h0h0n0n.getExtendedPublicKey().getPublicKey()));
    
    return check_1 && check_2 && check_3 && check_4 && check_5 && check_6 && check_7 && 
           check_8 && check_9 && check_10 && check_11 && check_12;
    }


}
