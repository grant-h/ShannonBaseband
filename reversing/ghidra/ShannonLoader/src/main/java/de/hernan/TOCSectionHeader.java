// Copyright (c) 2023, Grant Hernandez
// SPDX-License-Identifier: MIT
package de.hernan;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class TOCSectionHeader
{
    private String name;
    private int offset;
    private int loadAddress;
    private int size;
    private int unk1;
    private int sectionID;

    public TOCSectionHeader(BinaryReader reader) throws IOException
    {
        this.readHeader(reader);
    }

    private void readHeader(BinaryReader reader) throws IOException
    {
        this.name = reader.readNextAsciiString(12);
        this.offset = reader.readNextInt();
        this.loadAddress = reader.readNextInt();
        this.size = reader.readNextInt();
        this.unk1 = reader.readNextInt();
        this.sectionID = reader.readNextInt();
    }

    public String getName()
    {
        return this.name;
    }

    public int getLoadAddress()
    {
        return this.loadAddress;
    }

    public int getSectionID()
    {
        return this.sectionID;
    }

    public int getOffset()
    {
        return this.offset;
    }

    public int getSize()
    {
        return this.size;
    }

    @Override
    public String toString()
    {
      return String.format("TOCSectionHeader<name=%s, offset=%08x, size=%08x, loadAddress=%08x>",
          this.name, this.offset, this.size, this.loadAddress);
    }
}
