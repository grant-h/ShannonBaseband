// Copyright (c) 2023, Grant Hernandez
// SPDX-License-Identifier: MIT
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

  public class FindInfo {
    public final PatternEntry pattern;
    public final int offset;

    public FindInfo(PatternEntry pattern, int offset)
    {
      this.pattern = pattern;
      this.offset = offset;
    }

    public boolean found()
    {
      return offset != -1;
    }
  }

  public PatternFinder(InputStream input, int amount, Map<String, List<PatternEntry>> patternDB) throws IOException {
    this.content = new byte[amount];
    input.read(this.content, 0, amount);

    this.patternDB = patternDB;
  }

  public PatternFinder(byte [] content, Map<String, List<PatternEntry>> patternDB) {
    this.content = content;
    this.patternDB = patternDB;
  }

  public int find_pat(String patternName) {
    for (PatternEntry pat : patternDB.get(patternName)) {
      Matcher m = matchInternal(pat.pattern);

      if (m.find())
        return m.start() + pat.offset;
    }

    return -1;
  }

  public FindInfo find_pat_earliest(String patternName) {
    long earliestOffset = 0xffffffffL;
    Matcher earliest = null;
    PatternEntry earliestPat = null;

    for (PatternEntry pat : patternDB.get(patternName)) {
      Matcher m = matchInternal(pat.pattern);

      if (m.find()) {
        int foundAddr = m.start() + pat.offset;
        /*System.out.println(String.format("%s: %s\nADDR: %08x",
              patternName, pat.pattern, foundAddr));*/

        if (foundAddr < earliestOffset) {
          earliest = m;
          earliestPat = pat;
          earliestOffset = foundAddr;
        }
      }
    }

    if (earliest != null)
      return new FindInfo(earliestPat, (int)earliestOffset);

    return new FindInfo(null, -1);
  }

  public int find(String pattern, int offset) {
    Matcher m = matchInternal(pattern);

    if (m.find())
        return m.start() + offset;

    return -1;
  }

  public int find(String pattern) {
    return find(pattern, 0);
  }

  public Matcher match(String pattern) {
    Matcher m = matchInternal(pattern);

    if (!m.find())
      return null;

    return m;
  }

  public Matcher match_pat(String patternName) {
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

