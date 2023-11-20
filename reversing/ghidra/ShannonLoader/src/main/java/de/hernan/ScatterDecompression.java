// Copyright (c) 2023, Grant Hernandez
// SPDX-License-Identifier: MIT
package de.hernan;

import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;

public class ScatterDecompression {

  static public class DecompressionResult {
    public final byte [] data;
    public final Address inputEnd;

    public DecompressionResult(byte [] data, Address inputEnd)
    {
      this.data = data;
      this.inputEnd = inputEnd;
    }
  }

  static public DecompressionResult Decompress1(FlatProgramAPI fapi, Address start, int decompressedSize) throws MemoryAccessException
  {
      byte [] emit = new byte[decompressedSize];
      int emitOff = 0;
      int off = 0;

      while (emitOff < decompressedSize) {
        int token = Byte.toUnsignedInt(fapi.getByte(start.add(off++)));
        int matchLen = token & 7;

        if ((token & 7) == 0) {
          matchLen = Byte.toUnsignedInt(fapi.getByte(start.add(off++)));
        }

        int litLen = (token >> 4) & 0xf;

        if (litLen == 0) {
          litLen = Byte.toUnsignedInt(fapi.getByte(start.add(off++)));
        }

        for (int i = 0; i < matchLen-1; i++) {
          if (emitOff >= decompressedSize)
            throw new MemoryAccessException("Decompression overflow");
          emit[emitOff++] = fapi.getByte(start.add(off++));
        }

        // RLE for zeros
        if ((token & 8) == 0) {
          for (int i = 0; i < litLen; i++) {
            if (emitOff >= decompressedSize)
              throw new MemoryAccessException("Decompression overflow");
            emit[emitOff++] = 0;
          }
        } else {
          int backref = Byte.toUnsignedInt(fapi.getByte(start.add(off++)));
          int backrefOffset = emitOff - backref;

          /*System.out.println(String.format("emitoff=%d backref=%d backrefOff=%d max=%d",
                emitOff, backref, backrefOffset, decompressedSize));*/

          for (int i = 0; i < litLen+2; i++) {
            if (emitOff >= decompressedSize)
              throw new MemoryAccessException("Decompression overflow");

            if (backrefOffset < 0 || backrefOffset >= emitOff || backrefOffset >= decompressedSize)
              throw new MemoryAccessException("Decompression backreference out-of-range");

            backrefOffset = emitOff - backref;
            emit[emitOff] = emit[backrefOffset];
            emitOff++;
          }
        }
      }

      return new DecompressionResult(emit, start.add(off));
  }

  static public DecompressionResult Decompress2(FlatProgramAPI fapi, Address start, int decompressedSize) throws MemoryAccessException
  {
      byte [] emit = new byte[decompressedSize];
      int emitOff = 0;
      int off = 0;

      while (emitOff < decompressedSize) {
        int token = Byte.toUnsignedInt(fapi.getByte(start.add(off++)));
        int matchLen = token & 3;

        if (matchLen == 0) {
          matchLen = Byte.toUnsignedInt(fapi.getByte(start.add(off++)));
        }

        int litLen = (token >> 4) & 0xf;

        if (litLen == 0) {
          litLen = Byte.toUnsignedInt(fapi.getByte(start.add(off++)));
        }

        for (int i = 0; i < matchLen-1; i++) {
          if (emitOff >= decompressedSize)
            throw new MemoryAccessException("Decompression overflow");
          emit[emitOff++] = fapi.getByte(start.add(off++));
        }

        if (litLen == 0)
          continue;

        int backref = Byte.toUnsignedInt(fapi.getByte(start.add(off++)));
        int backrefMult = token & 0xC;

        // The backreference can stride much further with decompress2
        if (backrefMult == 0xC) {
          backrefMult = Byte.toUnsignedInt(fapi.getByte(start.add(off++)));
          backref += 0x100*backrefMult;
        } else {
          backref += 0x40*backrefMult;
        }

        int backrefOffset = emitOff - backref;

        /*System.out.println(String.format("emitoff=%d backref=%d backrefOff=%d max=%d",
              emitOff, backref, backrefOffset, decompressedSize));*/

        for (int i = 0; i < litLen+2; i++) {
          if (emitOff >= decompressedSize)
            throw new MemoryAccessException("Decompression overflow");
          if (backrefOffset < 0 || backrefOffset >= emitOff || backrefOffset >= decompressedSize)
            throw new MemoryAccessException("Decompression backreference out-of-range");

          backrefOffset = emitOff - backref;
          emit[emitOff] = emit[backrefOffset];
          emitOff++;
        }
      }

      return new DecompressionResult(emit, start.add(off));
  }
}
