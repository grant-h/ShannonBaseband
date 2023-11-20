// Copyright (c) 2023, Grant Hernandez
// SPDX-License-Identifier: MIT
package de.hernan.util;

import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;

// Adapter taken from http://blog.sarah-happy.ca/2013/01/java-regular-expression-on-byte-array.html
public class ByteCharSequence implements CharSequence {

    private final byte[] data;
    private final int length;
    private final int offset;

    public ByteCharSequence(byte[] data) {
        this(data, 0, data.length);
    }

    public ByteCharSequence(byte[] data, int offset, int length) {
        this.data = data;
        this.offset = offset;
        this.length = length;
    }

    @Override
    public String toString() {
        return StandardCharsets.ISO_8859_1.decode(ByteBuffer.wrap(data, offset, length)).toString();
    }

    @Override
    public int length() {
        return this.length;
    }

    @Override
    public char charAt(int index) {
        return (char) (data[offset + index] & 0xff);
    }

    @Override
    public CharSequence subSequence(int start, int end) {
        return new ByteCharSequence(data, offset + start, end - start);
    }

}
