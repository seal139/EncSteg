package pgp;

import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {

    private static final int SALT_LENGTH    = 32 /* byte */;
    private static final int IV_LENGTH      = 16 /* byte */;
    private static final int SALT_IV_LENGTH = SALT_LENGTH + IV_LENGTH;
    private static final int AES_KEY_LENGTH = 256 /* bit */;
    private static final int PKCS2_ITER     = 65536;

    private static final SecretKeyFactory factoryBC;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

    static {
        Security.addProvider(new BouncyCastleProvider());

        SecretKeyFactory sec = null;
        try {
            sec = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", "BC");
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            System.exit(-1);
        }

        factoryBC = sec;
    }

    public static void main(String[] args) {
        System.out.println("AES-Based Steganography Tools");
        System.out.println("Author: ");
        System.out.println("\t41521110038 - Daniel Jayasutra");
        System.out.println("\t41521110012 - Septian Pramana R");
        System.out.println();
        System.out.println("Major Assignment 2 of Cryptography and Steganography");
        System.out.println("Informatics Engineering, Mercubuana University");

        System.out.println("--------------------------------------------------------\n");

        help();

        while (true) {
            try {
                System.out.print("> ");
                if (!mainLoop(reader.readLine())) {
                    break;
                }
            }
            catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
    }

    private static void help() {
        System.out.println("For encode:");
        System.out.println("\tencode ${message_to_be_concealed} ${cover_image} ${disguised_image} ${password}");
        System.out.println("\texample: encode \"Cryptography and Steganography\" \"D:\\cover.jpg\" \"D:\\disguised.jpg\" 12345");
        System.out.println();
        System.out.println("For decode:");
        System.out.println("\tdecode ${disguised_image} ${password}");
        System.out.println("\texample: decode \"D:\\disguised.jpg\" 12345");
        System.out.println();
        System.out.println("Type 'exit' for exit");
    }

    private static boolean mainLoop(String input) throws Exception {
        List<String> tokens  = new ArrayList<>();
        Matcher      matcher = Pattern.compile("\"([^\"]*)\"|'([^']*)'|([^\\s]+)").matcher(input);

        while (matcher.find()) {
            if (matcher.group(1) != null) {
                tokens.add(matcher.group(1)); // double quotes
            }
            else if (matcher.group(2) != null) {
                tokens.add(matcher.group(2)); // single quotes
            }
            else {
                tokens.add(matcher.group(3)); // plain word
            }
        }

        if ("exit".equals(tokens.get(0).toLowerCase())) {
            return false;
        }

        if ("encode".equals(tokens.get(0).toLowerCase())) {
            System.out.println("Fusing message into an image...");
            encode(tokens.get(1), new File(tokens.get(2)), tokens.get(4).toCharArray(), new File(tokens.get(3)));
            System.out.println("Fused...");
        }
        else if ("decode".equals(tokens.get(0).toLowerCase())) {
            System.out.println("Reading message...");
            String output = decode(new File(tokens.get(1)), tokens.get(2).toCharArray());
            System.out.println("Message: " + output);
        }
        else {
            System.out.println("Unknown command");
            help();
        }

        return true;
    }

    private static final void encode(String text, File cover, char[] password, File disguised) throws Exception {
        final byte[] plain  = text.getBytes(StandardCharsets.UTF_8);
        final byte[] cipher = encrypt(plain, password);
        final int[]  bits   = bytesToBits(cipher);

        disguise(bits, cover, disguised);
    }

    private static final String decode(File disguised, char[] password) throws Exception {
        final int[]  encryptedBits = undisguise(disguised);
        final byte[] bytes         = bitsToBytes(encryptedBits);
        final byte[] plain         = decrypt(bytes, password);

        return new String(plain, StandardCharsets.UTF_8);
    }

    // =============================================

    /**
     * Derive encryption key from user-defined password using PBKDF2 with salt and
     * 65536 iteration
     *
     * @param password User-defined password
     * @param salt     random data to enhance password security
     * @return 256-bit AES key
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static byte[] deriveKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {

        KeySpec   keyspecBC = new PBEKeySpec(password, salt, PKCS2_ITER, AES_KEY_LENGTH);
        SecretKey keyBC     = factoryBC.generateSecret(keyspecBC);

        return keyBC.getEncoded();
    }

    // =============================================
    // TODO encode phase

    /**
     * Encrypt data
     *
     * @param plainData Data to be encrypted
     * @param password  User-defined password. The key used will be derived using
     *                  {@link #deriveKey(char[], byte[])}
     * @return Encrypted data
     *
     * @throws Exception
     */
    private static byte[] encrypt(byte[] plainData, char[] password) throws Exception {
        final byte[] salt = new byte[SALT_LENGTH];
        final byte[] iv   = new byte[IV_LENGTH];

        {
            RANDOM.nextBytes(iv);
            RANDOM.nextBytes(salt);
        }

        final byte[] key = deriveKey(password, salt);

        final SecretKeySpec   keySpec = new SecretKeySpec(key, "AES");
        final IvParameterSpec ivSpec  = new IvParameterSpec(iv);
        final Cipher          cipher  = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        final byte[] encrypted = cipher.doFinal(plainData);

        // prepend salt + iv + ciphertext
        final byte[] out = new byte[SALT_IV_LENGTH + encrypted.length];
        {
            System.arraycopy(salt, 0, out, 0, SALT_LENGTH);
            System.arraycopy(iv, 0, out, SALT_LENGTH, IV_LENGTH);
            System.arraycopy(encrypted, 0, out, SALT_IV_LENGTH, encrypted.length);
        }

        return out;
    }

    /**
     * Convert byte array into an array of it's 8 bit representation
     *
     * @param bytes Bytes to be converted
     * @return 8-bits representation of that bytes
     */
    private static int[] bytesToBits(byte[] bytes) {
        final int[] bits = new int[bytes.length * 8];

        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                bits[(i * 8) + j] = (bytes[i] >> (7 - j)) & 1;
            }
        }

        return bits;
    }

    /**
     * Fuse data into an image
     *
     * @param messageBit Message to be concealed
     * @param cover      Original cover image file
     * @param disguised  Disguised image output. This is a cover image file that
     *                   contains the concealed message
     * @throws IOException
     */
    private static void disguise(int[] messageBit, File cover, File disguised) throws IOException {

        final int[] finalMsg = new int[messageBit.length + 32];

        { // Encode message length in 32 bit
            final int  bit_l = messageBit.length / 8;
            final char c[]   = String                                          //
                    .format("%1$" + 32 + "s", Integer.toBinaryString(bit_l))   //
                    .replace(' ', '0')                                         //
                    .toCharArray();

            // Append msg length in the beginning of array
            int index = -1;
            for (char cc : c) {
                finalMsg[++index] = Integer.parseInt(String.valueOf(cc));
            }

            // and append the actual data
            System.arraycopy(messageBit, 0, finalMsg, 32, messageBit.length);
        }

        int index = -1;

        final BufferedImage coverImage = ImageIO.read(cover);
        breakpoint: for (int x = 0; x < coverImage.getWidth(); x++) {
            for (int y = 0; y < coverImage.getHeight(); y++) {

                if (++index >= finalMsg.length) {
                    break breakpoint;
                }

                final int currentPixel = coverImage.getRGB(x, y);

                final int red   = (currentPixel >> 16) & 255;
                final int green = (currentPixel >> 8) & 255;
                final int blue  = currentPixel & 255;

                final String x_s = Integer.toBinaryString(blue);

                final String originalBit = x_s.substring(0, x_s.length() - 1);
                final String stegBit     = Integer.toString(finalMsg[index]);

                final int s_pixel = Integer.parseInt(originalBit + stegBit, 2);

                final int rgb = (255 << 24) | (red << 16) | (green << 8) | s_pixel;
                coverImage.setRGB(x, y, rgb);
            }
        }

        ImageIO.write(coverImage, "png", disguised);
    }

    // =============================================
    // TODO decode phase

    /**
     * Return back bits data from disguised image file
     *
     * @param disguised Image file that contains concealed message to be extracted
     * @return The concealed message
     * @throws IOException
     */
    private static int[] undisguise(File disguised) throws IOException {

        final StringBuilder lenBit = new StringBuilder();

        int len    = 0;
        int bits[] = null;

        int index = -1;

        final BufferedImage disguisedImage = ImageIO.read(disguised);
        breakpoint: for (int x = 0; x < disguisedImage.getWidth(); x++) {
            for (int y = 0; y < disguisedImage.getHeight(); y++) {

                final int blue = disguisedImage.getRGB(x, y) & 255;

                final String x_s = Integer.toBinaryString(blue);
                final int    bit = ('1' == x_s.charAt(x_s.length() - 1)) ? 1 : 0;

                // Retrieve message length
                if ((x == 0) && (y <= 31)) {
                    lenBit.append(bit);

                    // Init bits[] and length
                    if (y == 31) {
                        len  = 8 * Integer.parseInt(lenBit.toString(), 2);
                        bits = new int[len--];
                    }
                }

                else if (index < len) {
                    bits[++index] = bit;
                }

                else {
                    break breakpoint;
                }
            }
        }

        return bits;
    }

    /**
     * Convert array of 8-bits into a byte array
     *
     * @param bits bits to be converted. Must be a modulo of 8
     * @return Byte[] representation of that 8-bits
     */
    private static byte[] bitsToBytes(int[] bits) {
        final int    byteLength = bits.length / 8;
        final byte[] result     = new byte[byteLength];

        for (int i = 0; i < byteLength; i++) {
            byte b = 0;
            for (int j = 0; j < 8; j++) {
                b <<= 1;
                b  |= (bits[(i * 8) + j] & 1); // only take last bit
            }
            result[i] = b;
        }

        return result;
    }

    /**
     * Decrypt data
     *
     * @param encryptedData Encrypted data to be decrypted
     * @param password      User-defined password. The key used will be derived
     *                      using {@link #deriveKey(char[], byte[])}
     * @return Decrypted data
     *
     * @throws Exception
     */
    private static byte[] decrypt(byte[] encryptedData, char[] password) throws Exception {
        final byte[] salt      = new byte[SALT_LENGTH];
        final byte[] iv        = new byte[IV_LENGTH];
        final byte[] encrypted = new byte[encryptedData.length - SALT_IV_LENGTH];

        {
            System.arraycopy(encryptedData, 0, salt, 0, SALT_LENGTH);
            System.arraycopy(encryptedData, SALT_LENGTH, iv, 0, IV_LENGTH);
            System.arraycopy(encryptedData, SALT_IV_LENGTH, encrypted, 0, encrypted.length);
        }

        final byte[] key = deriveKey(password, salt);

        final SecretKeySpec   keySpec = new SecretKeySpec(key, "AES");
        final IvParameterSpec ivSpec  = new IvParameterSpec(iv);
        final Cipher          cipher  = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        return cipher.doFinal(encrypted);
    }

}
