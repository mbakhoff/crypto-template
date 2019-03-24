package task2;

import common.Combinations;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class BruteForcePlain {

  public static void main(String[] args) throws Exception {
    // Encrypt a file using a 4-letter password as the key (without PBKDF2).
    // Use brute force to try all 4-letter passwords until you find the password
    // that decrypts the file. How long does the brute force attack take?

    // Hints:

    // Use a simple password consisting only of lower case letters a-z
    // Use the method below to covert the string into an encryption key

    // Use this to generate all password combination
    for (String combination : Combinations.ofLowerCaseLetters(4)) {
      System.out.println(combination);
    }

    // Use a regular small text file for testing
    // Compare the file content to the original to detect if the brute force password was correct

    // When the password is wrong, then the built-in hash check should throw AEADBadTagException

    // use System.currentTimeMillis() for measuring time

    // TODO: implement
  }

  static byte[] passwordToAESKey(String password) {
    // aes key must be exactly 256-bit
    return Arrays.copyOf(password.getBytes(StandardCharsets.UTF_8), 32);
  }
}
