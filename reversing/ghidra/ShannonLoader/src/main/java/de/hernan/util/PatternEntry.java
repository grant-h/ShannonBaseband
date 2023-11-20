// Copyright (c) 2023, Grant Hernandez
// SPDX-License-Identifier: MIT
package de.hernan.util;

public class PatternEntry {
  // what the pattern is trying to find at a high-level
  public static enum PatternType {
    GENERIC, STRUCT, DATA16, DATA32, DATA64,
    CODE16, CODE32, CODE64, STRING
  };

  public final String pattern;
  public final PatternType type;
  public final int offset;

  public PatternEntry(String pattern)
  {
    this(pattern, PatternType.GENERIC);
  }

  public PatternEntry(String pattern, PatternType type)
  {
    this(pattern, type, 0);
  }

  public PatternEntry(String pattern, int offset)
  {
    this(pattern, PatternType.GENERIC, offset);
  }

  public PatternEntry(String pattern, PatternType type, int offset)
  {
    this.pattern = pattern;
    this.offset = offset;
    this.type = type;
  }
}
