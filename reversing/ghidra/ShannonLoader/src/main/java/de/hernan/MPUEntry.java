package de.hernan;

import java.util.ArrayList;
import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class MPUEntry {
  private int slotId;
  private long baseAddress;
  private int size;
  private int flags;
  private boolean enabled;

  private static String [] apName = new String[] {"NA","P_RW", "P_RW/U_RO", "RW", "RESV", "P_RO/U_NA", "RO", "RESV"};

  public MPUEntry(BinaryReader reader) throws IOException {
    readEntry(reader);
  }

  private void readEntry(BinaryReader reader) throws IOException
  {
      this.slotId = reader.readNextInt();
      this.baseAddress = reader.readNextUnsignedInt();
      this.size = reader.readNextInt();
      this.flags = 0;

      for (int i = 0; i < 6; i++)
        this.flags |= reader.readNextInt();

      this.enabled = reader.readNextInt() != 0;
  }

  public long getStartAddress() {
    return baseAddress;
  }

  public long getSize() {
      int sizeBytes = (size >> 1) & 0b11111;
      assert sizeBytes >= 7 : "Invalid MPU size flag";
      return (long)Math.pow(2, 8+sizeBytes-7);
  }
  public long getEndAddress() {
      int sizeBytes = (size >> 1) & 0b11111;
      assert sizeBytes >= 7 : "Invalid MPU size flag";
      return getStartAddress() + (getSize() - 1L);
  }

  public int getSlotId() {
    return this.slotId;
  }

  public boolean isExecutable() {
    // eXecute Never = 0 -> executable
    return ((flags >> 12) & 1) == 0;
  }

  public int getAPBits() {
    return (flags >> 8) & 0b111;
  }

  // we assume from perspective of supervisor
  public boolean isReadable() {
    int bits = getAPBits();
    return bits != 0 && bits != 4 && bits != 7;
  }

  public boolean isWritable() {
    int bits = getAPBits();
    return bits == 1 || bits == 2 || bits == 3;
  }

  @Override
  public String toString() {
    return String.format("MPUEntry<slot=%d, start=%08x, end=%08x, exec=%s, ap=%s>",
        this.slotId, this.baseAddress, getEndAddress(), isExecutable(), apName[getAPBits()]);
  }
}
