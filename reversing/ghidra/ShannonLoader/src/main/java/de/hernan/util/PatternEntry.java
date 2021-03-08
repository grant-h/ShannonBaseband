package de.hernan.util;

public class PatternEntry {
  public String pattern;
  public int offset;

  public PatternEntry(String pattern)
  {
    this.pattern = pattern;
    this.offset = 0;
  }

  public PatternEntry(String pattern, int offset)
  {
    this.pattern = pattern;
    this.offset = offset;
  }
}
