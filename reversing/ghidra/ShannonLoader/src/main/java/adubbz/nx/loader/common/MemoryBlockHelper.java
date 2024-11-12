/**
 * Copyright 2019 Adubbz
 * Modified by Grant Hernandez 2020
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.common;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfStringTable;
import ghidra.app.util.bin.format.elf.ElfSymbolTable;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public class MemoryBlockHelper 
{
    private Program program;
    private MessageLog log;
    private long baseAddress;
    
    public MemoryBlockHelper(Program program, MessageLog log, long baseAddress)
    {
        this.program = program;
        this.log = log;
        this.baseAddress = baseAddress;
    }

    public boolean addUninitializedBlock(String name, long addressOffset, long dataSize, boolean read, boolean write, boolean execute)
    {
        try {
          AddressSpace addressSpace = this.program.getAddressFactory().getDefaultAddressSpace();
          MemoryBlockUtils.createUninitializedBlock(program, false, name, addressSpace.getAddress(this.baseAddress + addressOffset), dataSize, "", null, read, write, execute, this.log);
          return true;
        } catch (AddressOutOfBoundsException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean addInitializedBlock(String name, long addressOffset, InputStream dataInput, long dataSize, boolean read, boolean write, boolean execute)
    {
        try {
          AddressSpace addressSpace = this.program.getAddressFactory().getDefaultAddressSpace();
          MemoryBlockUtils.createInitializedBlock(program, false, name, addressSpace.getAddress(this.baseAddress + addressOffset), dataInput, dataSize, "", null, read, write, execute, this.log, null);
          return true;
        } catch (AddressOutOfBoundsException | AddressOverflowException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean renameBlock(String name, long addressOffset)
    {
        AddressSpace addressSpace = this.program.getAddressFactory().getDefaultAddressSpace();
        Address blockStart = addressSpace.getAddress(this.baseAddress + addressOffset);
        Memory memory = this.program.getMemory();

        try {
          MemoryBlock block = memory.getBlock(blockStart);

          if (block == null) {
            Msg.error(this, String.format("No existing block found for address at %s", blockStart));
            return false;
          }

          block.setName(name);
        } catch (LockException e) {
          Msg.error(this, String.format("Exception when trying to rename block at %s to %s", blockStart, name));
          return false;
        }

        return true;
    }

    public boolean blockExists(long addressOffset)
    {
        AddressSpace addressSpace = this.program.getAddressFactory().getDefaultAddressSpace();
        Address blockStart = addressSpace.getAddress(this.baseAddress + addressOffset);

        return blockExists(blockStart);
    }

    public boolean blockExists(Address blockStart)
    {
        return this.program.getMemory().getBlock(blockStart) != null;
    }

    public boolean initializeRange(long addressOffset, long size)
    {
        AddressSpace addressSpace = this.program.getAddressFactory().getDefaultAddressSpace();
        Address address = addressSpace.getAddress(addressOffset);
        return initializeRange(address, size);
    }

    public boolean initializeRange(Address addressOffset, long size)
    {
        Memory memory = this.program.getMemory();

        int offset = 0;
        MemoryBlock block = memory.getBlock(addressOffset);

        if (block == null)
          return false;

        while (block != null && offset < size) {
          try {
            // XXX: maybe we don't want to initialize the entire block...should we split it?
            if (!block.isInitialized()) {
              memory.convertToInitialized(block, (byte)0);
              Msg.info(this, String.format("Zero Initializing [%s - %s]", block.getStart(), block.getEnd()));
            }
          } catch (LockException | MemoryBlockException | NotFoundException e) {
            Msg.error(this, String.format("Failed to initialize block @ %s", block.getStart()));
            return false;
          }

          offset += block.getSize();
          block = memory.getBlock(addressOffset.add(offset));
        }

        return true;
    }

    public boolean addMergeSection(String name, long addressOffset, InputStream dataInput, long dataSize) throws AddressOverflowException, AddressOutOfBoundsException
    {
        AddressSpace addressSpace = this.program.getAddressFactory().getDefaultAddressSpace();
        Address writeStart = addressSpace.getAddress(this.baseAddress + addressOffset);
        Address writeEnd = writeStart.add(dataSize);
        Address writePtr = writeStart;

        Memory memory = this.program.getMemory();

        // Adding a merge section may include adding bytes to more than one existing
        // block as different MPU permissions will exist

        Msg.info(this, String.format("%s: Creating merge block -> [%08x - %08x]",
              name, addressOffset, addressOffset+dataSize));

        int chunkNum = 0;
        long dataPtr = 0;

        byte [] data = new byte[(int)dataSize];

        try {
          dataInput.read(data, 0, (int)dataSize);
        } catch (IOException e) {
          e.printStackTrace();
          return false;
        }

        while (dataPtr < dataSize) {
          MemoryBlock currentBlock = memory.getBlock(writePtr);

          if (currentBlock == null) {
            Msg.error(this, String.format("%s: No existing MPU block found for address write at %s",
                  name, writePtr));
            return false;
          }

          if (currentBlock.getStart().compareTo(writePtr) != 0) {
            Msg.info(this, String.format("%s: Split block at %s", name, writePtr));

            try {
              memory.split(currentBlock, writePtr);
            } catch (NotFoundException | LockException | MemoryBlockException e) {
              Msg.error(this, String.format("%s: Creating merge block split failed", name));
              e.printStackTrace();
              return false;
            }

            // get new split block
            currentBlock = memory.getBlock(writePtr);
          }

          long amtToWrite = Math.min(currentBlock.getEnd().subtract(writePtr) + 1, dataSize-dataPtr);

          try {
            if (!currentBlock.isInitialized()) {
              memory.convertToInitialized(currentBlock, (byte)0);
              Msg.info(this, String.format("Zero Initializing [%s - %s]",
                    currentBlock.getStart(), currentBlock.getEnd()));
            }

            String blockName = String.format("%s_%d_%s",
                name, chunkNum, memoryPermissions(currentBlock));
            Msg.info(this, String.format("%s: Create sub-block %s [%s - %s] 0x%08x bytes @ %s",
                  name, blockName, currentBlock.getStart(), currentBlock.getEnd(), amtToWrite, writePtr));

            memory.setBytes(writePtr, data, (int)dataPtr, (int)amtToWrite);
            currentBlock.setName(blockName);

            writePtr = writePtr.add(amtToWrite);
            dataPtr += amtToWrite;
            chunkNum++;
          } catch (NotFoundException | LockException | MemoryAccessException e) {
            Msg.error(this, String.format("%s: Creating merge block failed", name));
            e.printStackTrace();
            return false;
          }
        }

        return true;
    }

    private String memoryPermissions(MemoryBlock block)
    {
      String perms = "";
      int flags = block.getFlags();

      if ((flags & MemoryBlock.READ) != 0)
        perms += "R";
      if ((flags & MemoryBlock.WRITE) != 0)
        perms += "W";
      if ((flags & MemoryBlock.EXECUTE) != 0)
        perms += "X";

      return perms;
    }
}
