package task2;

import common.Combinations;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class BruteForcePlain {

  public static void main(String[] args) throws Exception {
    // Encrypt a file using a 4-letter password as the key (without PBKDF2).
    // Use brute force to try all 4-letter passwords until you find the password
    // that decrypts the file. How long does the brute force attack take?

    // Hints:

    // Use a simple password consisting only of lower case letters a-z
    // Use the method below to covert the string into an encryption key

    // Use a regular small text file for testing
    // Compare the file content to the original to detect if the brute force password was correct

    // When the password is wrong, then the built-in hash check should throw AEADBadTagException

    // use System.currentTimeMillis() for measuring time

    // TODO: implement
    byte[] data = "testtest".getBytes(StandardCharsets.UTF_8);

    byte[] key = passwordToAESKey("zzzz");

    SecureRandom rng = new SecureRandom();
    byte[] iv = new byte[12];
    rng.nextBytes(iv);

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, iv));
    byte[] encrypted = cipher.doFinal(data); // aka cipher text

    // try to break it
    long start = System.currentTimeMillis();
    for (String combination : Combinations.ofLowerCaseLetters(4)) {
      try {
        byte[] tryKey = passwordToAESKey(combination);
        cipher.init(Cipher.DECRYPT_MODE,
            new SecretKeySpec(tryKey, "AES"),
            new GCMParameterSpec(128, iv));
        byte[] recovered = cipher.doFinal(encrypted);
        if (Arrays.equals(data, recovered)) {
          System.out.println("key was " + combination);
          break;
        }
      } catch (AEADBadTagException e) {
        // wrong key, try the next one
      }
    }
    long end = System.currentTimeMillis();
    System.out.println("took only " + (end - start) + "ms");
  }

  static byte[] passwordToAESKey(String password) {
    // aes key must be exactly 256-bit
    return Arrays.copyOf(password.getBytes(StandardCharsets.UTF_8), 32);
  }
}
