package de.hernan;

import java.util.ArrayList;
import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class ShannonMemEntry {
  private long src;
  private long dst;
  private long size;
  private long function;
  private TOCSectionHeader baseSection;

  public ShannonMemEntry(BinaryReader reader, TOCSectionHeader baseSection) throws IOException {
    this.baseSection = baseSection;
    readEntry(reader);
  }

  private void readEntry(BinaryReader reader) throws IOException
  {
      this.src = reader.readNextUnsignedInt();
      this.dst = reader.readNextUnsignedInt();
      this.size = reader.readNextUnsignedInt();
      this.function = reader.readNextUnsignedInt();
  }

  public long getSourceAddress() {
    return src;
  }

  public long getSourceFileOffset() {
    return getSourceAddress() - baseSection.getLoadAddress() + baseSection.getOffset();
  }

  public long getDestinationAddress() {
    return dst;
  }

  public long getSize() {
    return size;
  }

  public long getFunction() {
    return function;
  }

  @Override
  public String toString() {
    return String.format("ShannonMemEntry<dst=%08x, src=%08x, size=%08x, fn=%08x, secbase=%s>",
        this.dst, this.src, this.size, this.function, this.baseSection.getName());
  }
}
