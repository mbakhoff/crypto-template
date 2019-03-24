package common;

import java.math.BigInteger;
import java.util.Iterator;

public class Combinations implements Iterable<String> {

  private final int length;
  private final char[] dictionary;
  private final int count;
  private final int[] powerCache;

  public Combinations(int length, char[] dictionary) {
    this.length = length;
    this.dictionary = dictionary;
    this.count = BigInteger.valueOf(dictionary.length).pow(length).intValueExact();
    this.powerCache = buildPowerCache(length, dictionary);
  }

  public static Combinations ofLowerCaseLetters(int length) {
    char[] dict = new char['z' - 'a' + 1]; // letters a-z
    for (int i = 0; i < dict.length; i++) {
      dict[i] = (char) ('a' + i);
    }
    return new Combinations(length, dict);
  }

  @Override
  public Iterator<String> iterator() {
    return new Iterator<>() {

      int counter = 0;

      @Override
      public String next() {
        char[] value = new char[length];
        int c = counter++;
        for (int i = 0; i < length; i++) {
          int i1 = c / powerCache[i];
          c -= i1 * powerCache[i];
          value[i] = dictionary[i1];
        }
        return new String(value);
      }

      @Override
      public boolean hasNext() {
        return counter < count;
      }
    };
  }

  private int[] buildPowerCache(int length, char[] dictionary) {
    int[] cache = new int[length];
    for (int i = 0; i < length; i++) {
      cache[i] = BigInteger.valueOf(dictionary.length).pow(length - i - 1).intValueExact();
    }
    return cache;
  }
}
