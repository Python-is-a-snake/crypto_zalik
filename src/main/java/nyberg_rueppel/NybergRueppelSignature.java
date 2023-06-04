package nyberg_rueppel;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class NybergRueppelSignature {
    private static final int KEY_SIZE = 2048;
    private static final BigInteger FIELD_SIZE = BigInteger.valueOf(2).pow(KEY_SIZE);
    private static final BigInteger GENERATOR = BigInteger.valueOf(2);

    public static void main(String[] args) {
        // Генерація ключів
        BigInteger privateKey = generatePrivateKey();
        BigInteger publicKey = calculatePublicKey(privateKey);

        // Повідомлення для підпису
        String message = "Hello, world!";

        // Підписування
        BigInteger signature = signMessage(message, privateKey);

        // Перевірка підпису
        boolean isVerified = verifySignature(message, signature, publicKey);

        System.out.println("Message: " + message);
        System.out.println("Signature: " + signature.toString());
        System.out.println("Verification: " + isVerified);
    }

    private static BigInteger generatePrivateKey() {
        SecureRandom random = new SecureRandom();
        BigInteger privateKey;
        do {
            privateKey = new BigInteger(KEY_SIZE, random);
        } while (privateKey.compareTo(FIELD_SIZE) >= 0);
        return privateKey;
    }

    private static BigInteger calculatePublicKey(BigInteger privateKey) {
        return GENERATOR.modPow(privateKey, FIELD_SIZE);
    }

    private static BigInteger signMessage(String message, BigInteger privateKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedMessage = digest.digest(message.getBytes());
            BigInteger hash = new BigInteger(1, hashedMessage);
            return hash.modPow(privateKey, FIELD_SIZE);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static boolean verifySignature(String message, BigInteger signature, BigInteger publicKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedMessage = digest.digest(message.getBytes());
            BigInteger hash = new BigInteger(1, hashedMessage);
            BigInteger leftSide = GENERATOR.modPow(signature, FIELD_SIZE);
            BigInteger rightSide = publicKey.modPow(hash, FIELD_SIZE);
            return leftSide.equals(rightSide);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false;
    }
}
