package task3;

import common.Combinations;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class BruteForcePBKDF2 {

  public static void main(String[] args) throws Exception {
    // Copy-paste the previous task and modify it to generate the
    // encryption key using PBKDF2 with iteration count 1.
    // How long does the brute force attack take?
    // Change the iteration count to 1 000 000 and time it again.

    // TODO: implement
    byte[] data = "testtest".getBytes(StandardCharsets.UTF_8);

    SecureRandom rng = new SecureRandom();
    byte[] salt = new byte[32];
    rng.nextBytes(salt);

    byte[] key = passwordToPBKDF2("zzzz", salt);

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
        byte[] tryKey = passwordToPBKDF2(combination, salt);
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

  private static byte[] passwordToPBKDF2(String password, byte[] salt) throws Exception {
    int iterationCount = 1;
    int outputLengthBits = 256;
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, outputLengthBits);
    return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
  }
}
