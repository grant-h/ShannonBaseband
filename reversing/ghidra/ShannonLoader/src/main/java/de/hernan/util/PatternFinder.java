package de.hernan.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.regex.*;

import de.hernan.util.ByteCharSequence;

public class PatternFinder {
  private byte [] content;

  public PatternFinder(InputStream input, int amount) throws IOException {
    this.content = new byte[amount];
    input.read(this.content, 0, amount);
  }

  public int find(String pattern, int offset) {
    Pattern reg = Pattern.compile(pattern);
    Matcher m = reg.matcher(new ByteCharSequence(this.content));

    if (!m.find())
      return -1;

    return m.start() + offset;
  }

  public int find(String pattern) {
    return find(pattern, 0);
  }
}

