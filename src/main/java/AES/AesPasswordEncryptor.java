package AES;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Scanner;

public class AesPasswordEncryptor {

    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = TagLength.TAG_128.getLength();
    private static final int IV_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 16;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    public static String encrypt(byte[] pText, String password) throws Exception {

        byte[] salt = UtilityCrypto.getRandomNonce(SALT_LENGTH_BYTE);

        byte[] iv = UtilityCrypto.getRandomNonce(IV_LENGTH_BYTE);

        // secret key from password
        SecretKey aesKeyFromPassword = UtilityCrypto.getAESKeyFromPassword(password.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        cipher.init(Cipher.ENCRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        byte[] cipherText = cipher.doFinal(pText);

        byte[] cipherTextWithIvSalt = ByteBuffer.allocate(iv.length + salt.length + cipherText.length)
                .put(iv)
                .put(salt)
                .put(cipherText)
                .array();

        return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);
    }

    private static String decrypt(String cText, String password) throws Exception {

        byte[] decode = Base64.getDecoder().decode(cText.getBytes(UTF_8));

        ByteBuffer bb = ByteBuffer.wrap(decode);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);

        byte[] salt = new byte[SALT_LENGTH_BYTE];
        bb.get(salt);

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        SecretKey aesKeyFromPassword = UtilityCrypto.getAESKeyFromPassword(password.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        byte[] plainText = cipher.doFinal(cipherText);

        return new String(plainText, UTF_8);

    }

    public static void main(String[] args) throws Exception {
        System.out.println("*********************************************************");
        System.out.println("\n*************** AES Password Encryption ***************");
        Scanner scanner = new Scanner(System.in);
        String OUTPUT_FORMAT = "%-30s:%s";

        System.out.println("Enter password:");
        String PASSWORD = scanner.nextLine();
        System.out.println("Password you have entered: " + PASSWORD);

        System.out.println("Enter message to encrypt:");
        String MESSAGE = scanner.nextLine();

        String encryptedTextBase64 = AesPasswordEncryptor.encrypt(MESSAGE.getBytes(UTF_8), PASSWORD);

        System.out.println(String.format(OUTPUT_FORMAT, "Input message: ", MESSAGE));
        System.out.println(String.format(OUTPUT_FORMAT, "Encrypted message: ", encryptedTextBase64));

        System.out.println("\n*************** AES Password Decryption ***************");
        System.out.println(String.format(OUTPUT_FORMAT, "Input message: ", encryptedTextBase64));

        String decryptedText = AesPasswordEncryptor.decrypt(encryptedTextBase64, PASSWORD);
        System.out.println(String.format(OUTPUT_FORMAT, "Decrypted message: ", decryptedText));
        System.out.println("*********************************************************");

    }

}