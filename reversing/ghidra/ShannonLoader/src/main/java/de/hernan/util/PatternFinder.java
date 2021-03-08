package de.hernan.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.regex.*;
import java.util.List;
import java.util.Map;

import de.hernan.util.ByteCharSequence;

public class PatternFinder {
  private byte [] content;
  private Map<String, List<PatternEntry>> patternDB;

  public PatternFinder(InputStream input, int amount, Map<String, List<PatternEntry>> patternDB) throws IOException {
    this.content = new byte[amount];
    input.read(this.content, 0, amount);

    this.patternDB = patternDB;
  }

  public int find(String patternName) {
    for (PatternEntry pat : patternDB.get(patternName)) {
      Matcher m = matchInternal(pat.pattern);

      if (m.find())
        return m.start() + pat.offset;
    }

    return -1;
  }

  public Matcher match(String patternName) {
    Matcher m = null;

    for (PatternEntry pat : patternDB.get(patternName)) {
      m = matchInternal(pat.pattern);

      if (m.find())
        return m;
    }

    // returns match object which can be used to call .find()
    return null;
  }

  private Matcher matchInternal(String pattern) {
    Pattern reg = Pattern.compile(pattern, Pattern.COMMENTS | Pattern.DOTALL | Pattern.MULTILINE);
    return reg.matcher(new ByteCharSequence(this.content));
  }
}

