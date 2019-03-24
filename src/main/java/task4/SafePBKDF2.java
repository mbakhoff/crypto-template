package task4;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;

public class SafePBKDF2 {

  public static void main(String[] args) throws Exception {
    // Pick a random password and hash it with `PBKDF2WithHmacSHA256`.
    // Find the iteration count that takes ~500ms on your machine.

    // Hint: no need to automate the search.
    // Just try different iteration counts until close enough

    // TODO: implement
    SecureRandom rng = new SecureRandom();
    byte[] salt = new byte[32];
    rng.nextBytes(salt);

    char[] password = "pass".toCharArray();
    int outputLengthBits = 256;

    // tweak this until the time is right
    int iterationCount = 450_000;

    long start = System.currentTimeMillis();
    PBEKeySpec spec = new PBEKeySpec(password, salt, iterationCount, outputLengthBits);
    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    long end = System.currentTimeMillis();
    System.out.println("current try " + (end - start) + "ms");
  }
}
