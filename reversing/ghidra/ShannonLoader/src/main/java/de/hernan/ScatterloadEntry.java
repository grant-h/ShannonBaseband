package de.hernan;

import ghidra.program.model.address.Address;

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
}
