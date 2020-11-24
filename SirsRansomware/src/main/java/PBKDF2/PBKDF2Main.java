package PBKDF2;

import java.security.SecureRandom;
import java.util.Random;

public class PBKDF2Main {
    private static final Random RANDOM = new SecureRandom();

    public static byte[] getNextSalt() {
        byte[] salt = new byte[64];
        RANDOM.nextBytes(salt);
        return salt;
    }
}