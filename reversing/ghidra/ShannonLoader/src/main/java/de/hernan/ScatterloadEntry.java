// Copyright (c) 2023, Grant Hernandez
// SPDX-License-Identifier: MIT
package de.hernan;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;

public class ScatterloadEntry {
  public final Address src;
  public final Address dst;
  public final Address function;
  public final long size;

  public ScatterloadEntry(Address src, Address dst, Address function, long size) {
    this.src = src;
    this.dst = dst;
    this.size = size;
    this.function = function;
  }

  @Override
  public String toString() {
    return String.format("ScatterloadEntry<dst=%s, src=%s, size=%s, fn=%s>",
        this.dst, this.src, this.size, this.function);
  }

  public byte [] emulateEntry(FlatProgramAPI fapi) {
    Msg.info(this, String.format("Scatter: emulating %s...", this.toString()));

    Program program = fapi.getCurrentProgram();
    EmulatorHelper emu = new EmulatorHelper(program);
    Address stopAddress = fapi.toAddr(0xdead0000L);

    // NOTE: when emulating a function, especially for ARM, it should be
    // disassembled beforehand to ensure that the instruction context (ARM vs
    // Thumb = TMode from SLEIGH) is set properly. Bad disassembly will lead to
    // bad Pcode which will lead to emulator FAULTs or worse (non-returning
    // emulation).
    //
    // Start emulation from the scatterload function pointer
    emu.writeRegister(emu.getPCRegister(), this.function.getOffset());
    // Create a "fake stack" in a memory range. These functions aren't expected
    // to use the stack, but at least have it initialized
    emu.writeRegister(emu.getStackPointerRegister(), 0x10000L); // fake stack
    // Calling convention for scatterload functions follows the normal ARM EABI
    // func(src, dst, size)
    emu.writeRegister("r0", this.src.getOffset());
    emu.writeRegister("r1", this.dst.getOffset());
    emu.writeRegister("r2", this.size);

    // The emulator will hit our breakpoint when it returns from the scatter function
    // and hits the magic stop address
    emu.writeRegister("lr", stopAddress.getOffset());
    emu.setBreakpoint(stopAddress);

    // We don't know the extent of the memory write range for decompress functions before emulation
    emu.enableMemoryWriteTracking(true);

    // Silence warnings
    emu.setMemoryFaultHandler(new MemoryFaultHandler() {
      @Override
      public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset) {
        return false;
      }

      @Override
      public boolean unknownAddress(Address address, boolean write) {
        return false;
      }
    });

    long timeElapsed = 0;

    try {
      // TODO actual monitor
      long startTime = System.currentTimeMillis();
      emu.run(TaskMonitor.DUMMY);
      timeElapsed = System.currentTimeMillis() - startTime;
    } catch (CancelledException e) {
      Msg.warn(this, "Scatter: emulation cancelled");
      return null;
    }

    EmulateExecutionState endState = emu.getEmulateExecutionState();
    AddressSetView writtenAddresses = emu.getTrackedMemoryWriteSet();

    if (endState != EmulateExecutionState.BREAKPOINT) {
      Msg.warn(this, String.format("Scatter: error emulating the scatterload function. End state %s, end address %s", endState.toString(), emu.getExecutionAddress().toString()));
      return null;
    }

    // Uncomment to debug the written ranges
    /*for (AddressRange range : writtenAddresses.getAddressRanges()) {
      System.out.println(String.format("WRITE: %s", range.toString()));
    }*/

    AddressRange writtenRange = writtenAddresses.getRangeContaining(this.dst);

    if (writtenRange != null) {
      byte [] data = emu.readMemory(this.dst, (int)writtenRange.getLength());

      Msg.info(this, String.format("Scatter: emulation succeeded. Wrote 0x%x bytes at %s in %.2fs", data.length, writtenRange.toString(), timeElapsed/1000.0));
      return data;
    } else {
      Msg.warn(this, String.format("Scatter: emulation succeeded, but unable to find written address range starting at %s!", this.dst.toString()));
      return null;
    }
  }
}
