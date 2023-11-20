// Copyright (c) 2023, Grant Hernandez
// SPDX-License-Identifier: MIT
package de.hernan.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hasher {
  public static String md5(byte [] data) {
    StringBuilder builder = new StringBuilder();
    try {
      MessageDigest md = MessageDigest.getInstance("MD5");

      md.update(data);

      byte [] digest = md.digest();

      for (int i = 0; i < digest.length; i++) {
        builder.append(String.format("%02x", digest[i]));
      }

      return builder.toString();
    } catch (NoSuchAlgorithmException e) {
      // only used for debugging so...
      return "";
    }
  }
}
