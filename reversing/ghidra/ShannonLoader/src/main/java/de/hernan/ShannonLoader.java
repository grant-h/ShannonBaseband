// Copyright (c) 2023, Grant Hernandez
// SPDX-License-Identifier: MIT
package de.hernan;

import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import static java.util.Map.entry;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;

import adubbz.nx.loader.common.MemoryBlockHelper;
import de.hernan.util.PatternFinder;
import de.hernan.util.PatternEntry;

import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.Project;
import ghidra.program.model.data.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.listing.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.module.TreeManager;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class ShannonLoader extends BinaryLoader 
{
    public static final String LOADER_NAME = "Samsung Shannon Modem Binary";
    public static final LanguageID LANG_ID = new LanguageID("ARM:LE:32:v8");

    private MemoryBlockHelper memoryHelper = null;
    private HashMap<String, TOCSectionHeader> headerMap = new HashMap<>();
    private ArrayList<AddressItem> addrEntries = new ArrayList<>();
    private ArrayList<MPUEntry> mpuEntries = new ArrayList<>();
    private FlatProgramAPI fapi = null;


    private int mpuTableOffset = -1;

    Map<String, List<PatternEntry>> patternDB = Map.ofEntries(
        entry("soc_version",
          List.of(
            new PatternEntry(String.join("\n",
                    "(?<SOC>[S][0-9]{3,4}(AP)?) # SOC-ID",
                    ".{0,10}                    # garbage or unknown (usually underscores)",
                    "(?<date>[0-9]{8})          # Date as YYYYMMDD (for rough SoC revision)",
                    "[^\\x00]*                  # null terminator"))
          )
        ),
        entry("shannon_version",
          List.of(
            new PatternEntry(String.join("\n",
                     "(ShannonOS.*?)[\\x00] # Match until end of string"
              )
            )
          )
        ),

        /* This pattern needs explaining. An MPU entry is a table that Shannon
         * will process to populate the MPU table of the Cortex-R series CPU.
         * Each entry is 40 bytes (10 words little-endian) with this layout (each field is 4 bytes):
         *
         * [slot][base][size][access_control]{6}[enable]
         *
         * Slot - the architectural MPU slot number
         * Base - the base address the MPU entry should apply to
         * Size - a size code that indicates the memory range an entry should cover
         * Access Control - a series of 6 words that are OR'd together to form the MPU permissions
         * Enable - whether this MPU entry is enabled (usually 1)
         *
         * SO...now about this pattern. Well this pattern is matching the first MPU entry.
         * See the comments inline.
         */

        entry("mpu_table",
          List.of(
            new PatternEntry(String.join("\n",
              "[\\x00]{8} # matches a slot ID of 0 and base address of 0x00000000",
              "\\x1c\\x00\\x00\\x00 # matches a size code 0x8000 bytes",
              "(....){6} # matches 6 arbitrary 4-byte values",
              "\\x01\\x00\\x00\\x00 # matches an enable of 1",
              "\\x01\\x00\\x00\\x00 # matches the next entry slot ID of 1",
              "\\x00\\x00\\x00\\x04 # matches address 0x04000000 which is the Cortex-R Tightly Coupled Memory (TCM) region",
              "\\x20 # matches the size code of 0x20000"
              )
            )
          )
        ),

        /* This pattern matches the __scatterload function which is called at boot to process
         * run-time image unpacking and relocation.
         *
         * These relocation entries are 16 bytes (4 words) of (src, dst, size, function).
         * Function is a pointer to memcpy, memset, or lz4_decode and they are called
         * with the first three fields as r0, r1, and r2 (first three args).
         * These relocations are used to load parts of the MAIN image to special memory regions
         * at boot and to decompress other resources into memory.
         *
         * This function is decompiled to find the table bounds and then the entries are processed.
         *
         * Hippity-hoppity your patterns are now my property~
         * https://github.com/SysSec-KAIST/BaseSpec/blob/e027413148ce79f53bfdabb3bd5e6c2ffb291dcc/basespec/scatterload.py#L172
         * Reference: https://developer.arm.com/documentation/dui0474/f/using-scatter-files?lang=en
         */

        entry("__scatterload",
          List.of(
            // Thumb-2 for scatterload function
            new PatternEntry(String.join("\n",
              "\\x0A\\xA0\\x90\\xE8\\x00\\x0C\\x82\\x44"
              ), PatternEntry.PatternType.CODE16
            ),
            // ARM for scatterload function
            new PatternEntry(String.join("\n",
              "\\x2C\\x00\\x8F\\xE2\\x00\\x0C\\x90\\xE8\\x00\\xA0\\x8A\\xE0\\x00\\xB0\\x8B\\xE0"
              ), PatternEntry.PatternType.CODE32
            )
          )
        ),

        entry("__scatterload_copy",
          List.of(
            // ARM version of scatterload. Found on old versions of modem and newer
            // Seems to be up to the linker and the context during which they are called
            new PatternEntry(String.join("\n",
              "\\x10\\x20\\x52\\xe2 # subs      r2,r2,#0x10",
              "\\x78\\x00\\xb0\\x28 # ldmiacs   r0!,{r3 r4 r5 r6}=>DAT_01245cc4"
              )
            ),
            // Thumb-2 version of scatterload. Found on 2015-2019 versions of modem
            new PatternEntry(String.join("\n",
              "\\x10\\x3a # sub       sz,#0x10",
              "\\x24\\xbf # itt       cs",
              "\\x78\\xc8 # ldmia.cs  src!,{ r3, r4, r5, r6 }",
              "\\x78\\xc1 # stmia.cs  dst!,{ r3, r4, r5, r6 }",
              "\\xfa\\xd8 # bhi       BOOT_MEMCPY",
              "\\x52\\x07 # lsl       sz,sz,#0x1d"
              )
            )
          )
        ),

        entry("__scatterload_zeroinit",
          List.of(
            // ARM version of scatterload. Found on old versions of modem and newer
            // Seems to be up to the linker and the context during which they are called
            new PatternEntry(String.join("\n",
              "\\x00\\x30\\xb0\\xe3 # movs      r3,#0x0",
              "\\x00\\x40\\xb0\\xe3 # movs      r4,#0x0",
              "\\x00\\x50\\xb0\\xe3 # movs      r5,#0x0",
              "\\x00\\x60\\xb0\\xe3 # movs      r6,#0x0"
              )
            ),
            // Thumb-2 version of scatterload. Found on 2015-2019 versions of modem
            new PatternEntry(String.join("\n",
              "\\x00\\x23 # mov       r3,#0x0",
              "\\x00\\x24 # mov       r4,#0x0",
              "\\x00\\x25 # mov       r5,#0x0",
              "\\x00\\x26 # mov       r6,#0x0",
              "\\x10\\x3a # sub       sz,#0x10",
              "\\x28\\xbf # it        cs",
              "\\x78\\xc1 # stmia.cs  dst!,{ r3, r4, r5, r6 }",
              "\\xfb\\xd8 # bhi       LAB_415da584"
              )
            )
          )
        ),

        // How the ARM RVCT linker (armlink) chooses which scatter compressor to use
        // https://developer.arm.com/documentation/dui0474/f/using-linker-optimizations/overriding-the-compression-algorithm-used-by-the-linker?lang=en
        // These are using LZ77 compression or mixing it with Run Length Encoding (RLE)
        entry("__scatterload_decompress",
          List.of(
            // ARM version of scatterload. Found on old versions of modem and newer
            // Seems to be up to the linker and the context during which they are called
            new PatternEntry(String.join("\n",
              "\\x02\\x20\\x81\\xe0 # add       r2,r1,r2",
              "\\x00\\xc0\\xa0\\xe3 # mov       r12,#0x0",
              "\\x01\\x30\\xd0\\xe4 # ldrb      r3,[r0],#0x1"
              )
            ),
            // Still looking for a version of this
            new PatternEntry(String.join("\n",
              "\\x0a\\x44\\x10\\xf8\\x01\\x4b\\x14\\xf0\\x0f\\x05\\x08\\xbf\\x10\\xf8\\x01\\x5b"
              )
            ),
            new PatternEntry(String.join("\n",
              "\\x0a\\x44           # add       endptr,dst",
              "\\x4f\\xf0\\x00\\x0c # mov.w     r12,#0x0",
              "\\x10\\xf8\\x01\\x3b # ldrb.w    r3,src],#0x1",
              "\\x13\\xf0\\x07\\x04 # ands      match_len,r3,#0x7",
              "\\x08\\xbf           # it        eq"
              )
            ),
            new PatternEntry(String.join("\n",
              "..\\x8f\\xe2         # adr r12, REF (starts in ARM)",
              "\\x1c\\xff\\x2f\\xe1 # bx r12 (switch to thumb)",
              "\\x8a\\x18 # add  r2,r1,r2 (REF)", 
              "\\x03\\x78 # ldrb r3,[r0,#0x0]",
              "\\x01\\x30 # add  r0,#0x1",
              "\\x5c\\x07 # lsl  r4,r3,#0x1d",
              "\\x64\\x0f # lsr  r4,r4,#0x1d"
              )
            )
          )
        ),

        entry("__scatterload_decompress2",
          List.of(
            // Still looking for a version of this
            new PatternEntry(String.join("\n",
              "\\x10\\xf8\\x01\\x3b\\x0a\\x44\\x13\\xf0\\x03\\x04\\x08\\xbf\\x10\\xf8\\x01\\x4b"
              )
            )
          )
        )
    );

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException 
    {
        List<LoadSpec> loadSpecs = new ArrayList<>();
        BinaryReader reader = new BinaryReader(provider, true);
        String magic_0x0 = reader.readAsciiString(0, 4);

        reader.setPointerIndex(0);

        if (magic_0x0.equals("TOC")) {
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(LANG_ID, new CompilerSpecID("default")), true));
        }

        return loadSpecs;
    }

    @Override
    protected List<Loaded<Program>> loadProgram(ByteProvider provider, String programName,
	    Project project, String programFolderPath, LoadSpec loadSpec, List<Option> options,
	    MessageLog log, Object consumer, TaskMonitor monitor)
		    throws IOException, CancelledException 
    {
        LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
        Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
        CompilerSpec importerCompilerSpec = importerLanguage.getCompilerSpecByID(pair.compilerSpecID);

        Address baseAddr = importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(0);
        Program prog = createProgram(provider, programName, baseAddr, getName(), importerLanguage, importerCompilerSpec, consumer);

        List<Loaded<Program>> results = new ArrayList<>(1);
        try 
        {
          this.loadInto(provider, loadSpec, options, log, prog, monitor);
          results.add(new Loaded<Program>(prog, programName, programFolderPath));
        }
        catch (Exception e) 
        {
          Msg.error(this, "Error while loading " + programFolderPath + ": " + e);
          prog.release(consumer);
        }

        return results;
    }

    class AddressItem {
      public boolean end;
      public MPUEntry entry;

      public AddressItem(MPUEntry entry, boolean end) {
        this.entry = entry;
        this.end = end;
      }

      public long getAddr() {
        if (end)
          return entry.getEndAddress();
        else
          return entry.getStartAddress();
      }

      @Override
      public String toString() {
        return String.format("AddressItem<[%08x], end=%s, %s>",
            getAddr(), end, entry.toString());

      }
    }

    @Override
    protected void loadProgramInto(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            MessageLog messageLog, Program program, TaskMonitor monitor) 
                    throws IOException, LoadException
    {
        BinaryReader reader = new BinaryReader(provider, true);
        memoryHelper = new MemoryBlockHelper(program, messageLog, 0L);
        fapi = new FlatProgramAPI(program);

        monitor.setMaximum(100);
        monitor.incrementProgress(3);

        if (!processTOCHeader(reader)) {
        	throw new LoadException("The file does not look like a Shannon Baseband. TOC Mismatch.");
        }

        TOCSectionHeader sec_main = headerMap.get("MAIN");
        TOCSectionHeader sec_boot = headerMap.get("BOOT");

        if (sec_main == null || sec_boot == null) {
          Msg.error(this, "One or more of the required sections [MAIN, BOOT] were not found");
          throw new LoadException("The file does not look like a Shannon Baseband. One or more of the required sections [MAIN, BOOT] were not found.");
        }

        monitor.incrementProgress(10);

        PatternFinder finder = new PatternFinder(
            provider.getInputStream(sec_main.getOffset()), sec_main.getSize(),
            patternDB);

        monitor.incrementProgress(5);

        // purely informational for now
        discoverSocVersion(finder);
        monitor.incrementProgress(5);

        findShannonPatterns(finder, sec_main);
        monitor.incrementProgress(20);

        if (mpuTableOffset != -1) {
          if (!readMPUTable(reader)) {
            throw new LoadException("Error reading MPU table.");
          }

          if (!calculateShannonMemoryMap()) {
            throw new LoadException("Error calculating shannon memory map.");
          }
        }
	monitor.incrementProgress(10);

        if (!loadBasicTOCSections(provider, sec_boot, sec_main)) {
          throw new LoadException("Error loading basic TOC sections.");
        }
	monitor.incrementProgress(10);

        ////////////////////////////////////////
        // All operations use FlatProgramAPI
        // Instead of binary reader
        ////////////////////////////////////////

        if (mpuTableOffset != -1) {
          typeMPUTable();
        }
        monitor.incrementProgress(10);

        if (!doScatterload(program, finder, headerMap.get("MAIN").getLoadAddress())) {
          Msg.warn(this, "Unable to process scatterload table. This table is used to unpack the MAIN image during baseband boot (runtime relocations). We would like to unpack it at load time in order to capture important regions, like TCM. Without this significant portions of critical code and data may appear to be missing.");
        }

        Msg.info(this, "==== Finalizing program trees ====");

        monitor.incrementProgress(30);

        syncProgramTreeWithMemoryMap(program);
        organizeProgramTree(program);
    }

    private boolean typeMPUTable()
    {
        // Type the entries
        DataTypeManager dtm = fapi.getCurrentProgram().getDataTypeManager();
        StructureDataType mpuEntryStruct = new StructureDataType("MPUTableEntry", 0);

        mpuEntryStruct.add(new UnsignedIntegerDataType(), -1, "slotID", "");
        mpuEntryStruct.add(new PointerDataType(), -1, "baseAddress", "");
        mpuEntryStruct.add(new UnsignedIntegerDataType(), -1, "size", "");

        for (int i = 0; i < 6; i++)
          mpuEntryStruct.add(new UnsignedIntegerDataType(), -1, "flag" +String.valueOf(i), "");

        mpuEntryStruct.add(new UnsignedIntegerDataType(), -1, "enabled", "");

        DataType dat = dtm.addDataType(mpuEntryStruct, DataTypeConflictHandler.REPLACE_HANDLER);

        if (mpuEntries.size() == 0)
          return false;

        Address start = fapi.toAddr(headerMap.get("MAIN").getLoadAddress()+mpuTableOffset);
        ArrayDataType adty = new ArrayDataType(dat, mpuEntries.size(), dat.getLength());

        DataType adtyadd = dtm.addDataType(adty, DataTypeConflictHandler.REPLACE_HANDLER);

        try {
          Data array = fapi.createData(start, adtyadd);
          Msg.info(this, String.format("Typed MPUTable as %s", array));
          return true;
        } catch (Exception e) {
          Msg.warn(this, "Failed to type MPUTable", e);
          return false;
        }
    }

    private boolean doScatterload(Program program, PatternFinder finder, long findBase)
    {
        AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        PatternFinder.FindInfo scatterloadFunction = finder.find_pat_earliest("__scatterload");
        ArrayList<ScatterloadEntry> scatterEntries = new ArrayList<>();

        if (!scatterloadFunction.found()) {
          //Msg.warn(this, "Scatter: pattern find returned no results");
          return false;
        }

        Address scatterFn = addressSpace.getAddress(scatterloadFunction.offset + findBase);

        boolean thumbPattern = scatterloadFunction.pattern.type == PatternEntry.PatternType.CODE16;
        Msg.info(this, String.format("Scatter: found scatter function %s (thumb=%s)",
              scatterFn, thumbPattern));

        AddressSet addrSet = new AddressSet(scatterFn, scatterFn.add(0x100));
        ArmDisassembleCommand cmd = new ArmDisassembleCommand(scatterFn, addrSet, thumbPattern);

        Msg.info(this, "Scatter: disassembling function...");
        if (!cmd.applyTo(program)) {
          Msg.error(this, String.format("Scatter: failed to disassemble __scatterload function"));
          return false;
        }

        Msg.info(this, "Scatter: inspecting instructions...");

        Function func = createUniqueFunction(scatterFn, "__scatterload");

        InstructionIterator insnIter = program.getListing().getInstructions(func.getBody(), true);

        if (!insnIter.hasNext()) {
          Msg.error(this, "Scatter: failed to get first instruction of scatter function");
          return false;
        }

        Instruction insn = insnIter.next();
        PcodeOp [] pcode = insn.getPcode();
        // first instruction should be an ADR relative instruction
        PcodeOp memoryRef = pcode[0];

        if (memoryRef.getOpcode() != PcodeOp.COPY) {
          Msg.error(this, "Scatter: first Pcode instruction is not a data reference");
          return false;
        }

        Address tableBase = memoryRef.getInput(0).getAddress();
        // convert address from Pcode out of constant space and into the listing address-space
        tableBase = addressSpace.getAddress(tableBase.getOffset());

        Msg.info(this, "Scatter: extracting table bounds...");

        try {
          Data ref1 = fapi.createDWord(tableBase);
          Data ref2 = fapi.createDWord(tableBase.add(4));

          // These bounds can be negative depending on the table location relative
          // to the function (this is PC-relative)
          long startOffset = ((Scalar)ref1.getValue()).getSignedValue();
          long endOffset = ((Scalar)ref2.getValue()).getSignedValue();
          //long tableSize = endOffset - startOffset;

          Address tableAddress = tableBase.add(startOffset);
          Address tableEndAddress = tableBase.add(endOffset);

          Msg.info(this, String.format("Scatter: recovered bounds [%s %s]. Reading table...",
                tableAddress, tableEndAddress));

          scatterEntries = readScatterTable(tableAddress, tableEndAddress);
          Msg.info(this, String.format("==== Found %d scatterload entries ====", scatterEntries.size()));
        } catch (Exception e) {
          Msg.error(this, "Scatter: unknown error", e);
          return false;
        }

        Map<String, Address> scatterFunctions = new HashMap<>();
        Map<Address, String> invScatterFunctions = new HashMap<>();

        scatterFunctions.put("__scatterload_copy", Address.NO_ADDRESS);
        scatterFunctions.put("__scatterload_zeroinit", Address.NO_ADDRESS);
        scatterFunctions.put("__scatterload_decompress", Address.NO_ADDRESS);
        scatterFunctions.put("__scatterload_decompress2", Address.NO_ADDRESS);

        for (String fn : scatterFunctions.keySet()) {
          PatternFinder.FindInfo finfo = finder.find_pat_earliest(fn);

          if (finfo.found()) {
            Address addr = addressSpace.getAddress(finfo.offset+findBase);
            createUniqueFunction(addr, fn);
            Msg.info(this, String.format("Scatter: Found %s @ %s", fn, addr));
            scatterFunctions.put(fn, addr);
            invScatterFunctions.put(addr, fn);
          }
        }

        for (ScatterloadEntry entry : scatterEntries) {
          // TODO: handle NO OP entries (size=0 and fn=__scatterload+N)
          if (!invScatterFunctions.containsKey(entry.function)) {
            Msg.warn(this, String.format("Scatter: unrecovered/recognized scatter op %s",
                  entry));
            continue;
          }

          String scatterOp = invScatterFunctions.get(entry.function);

          String scatterComment = String.format("%s(src=%s, dst=%s, size=%08x)",
              scatterOp, entry.src, entry.dst, entry.size);
          Msg.info(this, "Scatter: applying "+ scatterComment);

          addrSet = new AddressSet(entry.function, entry.function.add(0x100));
          cmd = new ArmDisassembleCommand(entry.function, addrSet, thumbPattern);

          if (!cmd.applyTo(program)) {
            Msg.error(this, String.format("Scatter: failed to disassemble %s function", scatterOp));
            return false;
          }

          byte [] data = null;
          Address scatterEntrySrcEnd = Address.NO_ADDRESS;

          try {
            if (scatterOp == "__scatterload_zeroinit") {
              data = new byte[(int)entry.size];
              // zeroinit src address is bogus, don't label src
            } else if (scatterOp == "__scatterload_copy") {
              data = fapi.getBytes(entry.src, (int)entry.size);
              scatterEntrySrcEnd = entry.src.add(entry.size);
            } else if (scatterOp == "__scatterload_decompress") {
              ScatterDecompression.DecompressionResult result = ScatterDecompression.Decompress1(fapi, entry.src, (int)entry.size);
              data = result.data;

              // decompression input size is not known beforehand
              scatterEntrySrcEnd = result.inputEnd;
            } else if (scatterOp == "__scatterload_decompress2") {
              ScatterDecompression.DecompressionResult result = ScatterDecompression.Decompress2(fapi, entry.src, (int)entry.size);
              data = result.data;

              // decompression input size is not known beforehand
              scatterEntrySrcEnd = result.inputEnd;
            } else {
              throw new RuntimeException("Unhandled scatterload op " + scatterOp);
            }
          } catch (MemoryAccessException e) {
            Msg.error(this, String.format("Scatter: entry apply error %s", e));
            continue;
          }

          // Emulation is very slow for large regions. Emulation used to validate Java versions of scatter functions
          // Uncomment to debug issues with scatter function patterns and/or implementation
          /*byte [] emuData = entry.emulateEntry(fapi);

          if (emuData != null) {
            Msg.info(this, String.format("Scatter: EMU %s -- Java %s", Hasher.md5(emuData), Hasher.md5(data)));
          }*/

          boolean newDataCopied = scatterEntrySrcEnd.compareTo(Address.NO_ADDRESS) != 0;

          if (memoryHelper.blockExists(entry.dst)) {
            if (!memoryHelper.initializeRange(entry.dst, entry.size)) {
              Msg.error(this, "Scatter: failed to initialize destination memory address");
              continue;
            }

            try {
              byte [] fourcc = fapi.getBytes(entry.dst, 4);
              byte [] DBT = { 0x44, 0x42, 0x54, 0x3a }; // DBT:

              if (Arrays.equals(fourcc, DBT)) {
                // DO NOT OVERWRITE TRACE ENTRIES IF ASKED TO BY SCATTER TABLE
                //
                // Unfortunately Shannon likes to reuse trace entry memory for GP RAM
                // which means some decompilation/listing views will have strange references
                // to trace data. Possibly a Ghidra overlay would solve this, but I tried without
                // much success.
                Msg.info(this, "Scatter: IGNORING entry telling us to wipe debug data (nice try)");
                continue;
              }

              fapi.setBytes(entry.dst, data);
            } catch (MemoryAccessException e) {
              Msg.error(this, String.format("Scatter: entry write error"), e);
              continue;
            }
          } else {
            Msg.warn(this, "Scatter: no backing memory. Conservative memory recreation...");
            if (!addMergeSection(new ByteArrayInputStream(data), "SL_"+entry.dst,
                (long)entry.dst.getUnsignedOffset(), data.length)) {
              Msg.error(this, "Scatter: unable to create memory block");
              continue;
            }
          }

          try {
            fapi.setPlateComment(entry.dst, "ShannonLoader: " + scatterComment);
            fapi.createLabel(entry.dst, "SCATTERED_FROM_" + entry.src, true);

            if (newDataCopied) {
              fapi.setPlateComment(entry.src, "ShannonLoader: " + scatterComment);
              fapi.createLabel(entry.src, "SCATTER_TO_" + entry.dst, true);

              ArrayDataType adty = new ArrayDataType(new ByteDataType(),
                  (int)(long)scatterEntrySrcEnd.subtract(entry.src), 1);

              // Create an array of bytes to prevent autoanalysis from getting greedy on the source scatter
              fapi.createData(entry.src, adty);
            }
          } catch (Exception e) {
            Msg.warn(this, "Scatter: failed to label scatter operation");
          }

          // process sub-scatter functions, if any
          if (newDataCopied) {
            PatternFinder finderSub = new PatternFinder(data, patternDB);
            Msg.info(this, String.format("Scatter: sub-scatter search [%s - %s]",
                  entry.dst, entry.dst.add(data.length)));

            if (doScatterload(program, finderSub, entry.dst.getUnsignedOffset())) {
              Msg.info(this, "Scatter: ============================= sub-scatter processed successfully");
            }
          }
        }

        return true;
    }

    private Function createUniqueFunction(Address start, String functionPrefix)
    {
      int postfix = 0;
      String candidate = functionPrefix;

      // convert to binary postfix search if heavily used (O(log n))
      while (!fapi.getGlobalFunctions(candidate).isEmpty()) {
        candidate = functionPrefix + "_" + String.valueOf(++postfix);
      }

      return fapi.createFunction(start, candidate);
    }

    private boolean loadBasicTOCSections(ByteProvider provider, TOCSectionHeader sec_boot, TOCSectionHeader sec_main)
    {
        Msg.info(this, "==== Inflating primary sections ====");

        if (sec_boot.getLoadAddress() != 0L) {
          if (!addMergeSection(provider, sec_boot, "BOOT_MIRROR", 0L))
            return false;
        }

        List<TOCSectionHeader> headerList = new ArrayList<>(headerMap.values());
        Collections.sort(headerList, (o1, o2) -> o1.getLoadAddress() - o2.getLoadAddress());

        for (TOCSectionHeader header : headerList) {
            // informative section such as OFFSET
            if (header.getLoadAddress() == 0 && !header.getName().equals("BOOT")) {
              Msg.warn(this, String.format("%s: Skipping entry - zero load address",
                  header.getName()));
              continue;
            }

            Msg.info(this, String.format("%s: Add %s", header.getName(), header.toString()));

            if (!addMergeSection(provider, header))
              return false;
        }

        return true;
    }

    private boolean addMergeSection(ByteProvider provider, TOCSectionHeader section)
    {
        return addMergeSection(provider, section, section.getName(), section.getLoadAddress());
    }

    private boolean addMergeSection(ByteProvider provider, TOCSectionHeader section, String name, long loadAddress)
    {
        return addMergeSection(provider, section.getOffset(), name, loadAddress, section.getSize());
    }

    private boolean addMergeSection(ByteProvider provider, long offset, String name, long loadAddress, long size)
    {
        // NV section has no data, just stored as a name
        if (offset == 0L) {
          if (!memoryHelper.blockExists(loadAddress)) {
            Msg.info(this, String.format("%s: TOC rename of 0x%08x requested, but no backing block. Creating RWX block...",
                name, loadAddress));

            // dont hard fail as these informative blocks
            if (!memoryHelper.addUninitializedBlock(name, loadAddress,
                  size, true, true, true)) {
              Msg.warn(this, String.format("%s: Failed to create backing block for address rename", name));
            }
          }

          // dont fail on simple renames
          memoryHelper.renameBlock(name, loadAddress);

          return true;
        }

        try {
          return addMergeSection(provider.getInputStream(offset), name, loadAddress, size);
        } catch (IOException e) {
          e.printStackTrace();
          return false;
        }
    }

    private boolean addMergeSection(InputStream stream, String name, long loadAddress, long size)
    {
        try {
          if (!memoryHelper.blockExists(loadAddress)) {
            Msg.warn(this, String.format("%s: No backing MPU entry. Falling back to RWX permissions",
                  name));
            return memoryHelper.addInitializedBlock(name, loadAddress, stream, size,
                true, true, true);
          } else {
            return memoryHelper.addMergeSection(name, loadAddress, stream, size);
          }
        } catch (AddressOverflowException | AddressOutOfBoundsException e) {
          e.printStackTrace();
          return false;
        }
    }

    private void syncProgramTreeWithMemoryMap(Program program)
    {
        // A hack to sync the ProgramTree view and the memory map
        // Apparently these are different and once the ProgramTree is created,
        // renaming memory map items won't sync the changes

        try {
          // Note that ProgramDB is considered "private" so this can break at any time
          ProgramDB db = (ProgramDB)program;
          TreeManager tree = db.getTreeManager();

          if (tree.getRootModule(TreeManager.DEFAULT_TREE_NAME) == null)
              return;

          tree.removeTree(TreeManager.DEFAULT_TREE_NAME);
          tree.createRootModule(TreeManager.DEFAULT_TREE_NAME);

        } catch (DuplicateNameException e) {
          Msg.warn(this, "Unable to sync program tree to memory map");
        }
    }

    private void organizeProgramTree(Program program)
    {
      //ProgramModule root = program.getListing().getDefaultRootModule();
      try {
        ProgramModule root = program.getListing().createRootModule("Categorized");

        String [] sectionName = {"Low", "Mid", "High"};
        long [] sectionBound = {0x40000000L, 0x80000000L, 0x100000000L};

        for (int i = 0; i < sectionName.length; i++) {
            ProgramModule newSection = root.createModule(sectionName[i]);
            Group[] children = root.getChildren();

            for (Group child : children) {
              if (child instanceof ProgramFragment) {
                ProgramFragment frag = (ProgramFragment)child;

                if (frag.getMinAddress().getUnsignedOffset() < sectionBound[i]) {
                  newSection.reparent(frag.getName(), root);
                  Msg.info(this, String.format("[%s - %s] %s (%s)",
                         frag.getMinAddress(), frag.getMaxAddress(), frag.getName(), sectionName[i]));
                }
              }
            }
        }
      } catch (DuplicateNameException | NotFoundException e) {
        Msg.warn(this, "Failed to create categorized tree. Continuing...");
        e.printStackTrace();
      }
    }

    private void discoverSocVersion(PatternFinder finder)
    {
        java.util.regex.Matcher socFields =
        finder.match_pat("soc_version");

        if (socFields == null) {
          Msg.warn(this, "Unable to find version string in MAIN section");
          return;
        } else {
          String soc = socFields.group("SOC");
          String socDate = socFields.group("date");

          Msg.info(this, String.format("Extracted SoC information: SOC %s, revision %s", soc, socDate));
        }

        java.util.regex.Matcher osVersion =
        finder.match_pat("shannon_version");

        if (osVersion == null) {
          Msg.warn(this, "Unable to find OS version string in MAIN section");
          return;
        } else {
          Msg.info(this, String.format("Extracted OS version: %s", osVersion.group(1)));
        }
    }

    private boolean processTOCHeader(BinaryReader reader)
    {
        TOCSectionHeader tocFirst;

        try {
            tocFirst = new TOCSectionHeader(reader);
        } catch (IOException e) {
            Msg.error(this, "Failed to read initial TOC section header");
            return false;
        }

        Msg.info(this, String.format("ShannonLoader TOC header found at with size=%08x...parsing header",
            tocFirst.getSize()));

        //long prevPointerIndex = reader.getPointerIndex();

        while (reader.getPointerIndex() < tocFirst.getSize()) {
          try {
            TOCSectionHeader header = new TOCSectionHeader(reader);

            // Continue reading until we see a blank or empty section
            if (header.getName().equals("") || header.getSize() == 0)
              break;

            if (headerMap.containsKey(header.getName())) {
              Msg.error(this, String.format("Modem file has a duplicate header: '%s'", header.getName()));
              return false;
            }

            headerMap.put(header.getName(), header);

          } catch (IOException e) {
            Msg.error(this, String.format("Failed to next TOC section header index %d", headerMap.size()));
            return false;
          }
        }

        Msg.info(this, String.format("==== Found %d TOC sections ====", headerMap.size()));

        List<TOCSectionHeader> headerList = new ArrayList<>(headerMap.values());
        Collections.sort(headerList, (o1, o2) -> o1.getLoadAddress() - o2.getLoadAddress());

        for (TOCSectionHeader header : headerList) {
            Msg.info(this, header.toString());
        }

        return true;

    }

    // TODO: add label and types to tables
    private void findShannonPatterns(PatternFinder finder, TOCSectionHeader fromSection)
    {
        mpuTableOffset = finder.find_pat("mpu_table");

        if (mpuTableOffset == -1) {
          Msg.warn(this, "Unable to find Shannon MPU table pattern. MPU recovery is essential for correct section permissions which will improve analysis determining what is code and what is data.");
        } else {
          Msg.info(this, String.format("MPU entry table found in section=MAIN offset=0x%08x (physical address 0x%08x)",
                mpuTableOffset, mpuTableOffset+fromSection.getLoadAddress()));
        }
    }

    private boolean readMPUTable(BinaryReader reader)
    {
        long offset = headerMap.get("MAIN").getOffset()+mpuTableOffset;
        reader.setPointerIndex(offset);

        while (true) {
          try {
            MPUEntry entry = new MPUEntry(reader);

            // Continue reading until we see a blank or empty section
            if (entry.getSlotId() == 0xff)
              break;

            mpuEntries.add(entry);

          } catch (IOException e) {
            Msg.error(this, String.format("Failed read to next MPU entry %d", mpuEntries.size()));
            return false;
          }
        }

        Msg.info(this, String.format("==== Found %d MPU entries ====", mpuEntries.size()));

        for (MPUEntry entry : mpuEntries) {
            Msg.info(this, entry.toString());
            addrEntries.add(new AddressItem(entry, false));
            addrEntries.add(new AddressItem(entry, true));
        }

        return true;
    }

    private boolean calculateShannonMemoryMap()
    {
        // Uncomment if you are debugging MPU table entries
        /*
        for (AddressItem it : addrEntries) {
          Msg.info(this, String.format("%s", it.toString()));
        }
        */

        HashMap<Integer, MPUEntry> active = new HashMap<>();

        /* This is an O(n) algorithm to resolve MPU table overlaps and
         * coalesce them into a flat map where each address has a single
         * primary permission set. Cortex-R MPU entries can overlap
         * in hardware. So what defines their permission priority?
         * Its higher slot numbers. Take this trival layout:
         *
         * 0x0                                   0x3fff
         *  |---------------------------------------|
         *  [slot 0 -- 0x0000-0x3fff  RO            ]
         *             [slot 1 -- 0x1000-0x3fff RW  ]
         *
         * If you feel the need to understand this further, I suggest grabbing
         * your favorite writing utensil and flavor of dead tree to work through it.
         */

        Msg.info(this, "==== Calculated Shannon Memory Map ====");

        Collections.sort(addrEntries, new Comparator<AddressItem>() {
          public int compare(AddressItem o1, AddressItem o2) {
            //long comp = o1.getAddr() - o2.getAddr();

            if (o1.getAddr() < o2.getAddr())
              return -1;
            else if (o1.getAddr() > o2.getAddr())
              return 1;

            return (o1.end ? 1 : 0) - (o2.end ? 1 : 0);
          }
        });

        for (int i = 0; i < addrEntries.size()-1; i++) {
          AddressItem e = addrEntries.get(i);
          AddressItem en = addrEntries.get(i+1);

          if (e.end) {
            active.remove(e.entry.getSlotId());
          } else {
            active.put(e.entry.getSlotId(), e.entry);
          }

          long start = e.end ? e.getAddr() + 1 : e.getAddr();
          long end = en.end ? en.getAddr() : en.getAddr() - 1;

          if (start <= end && active.size() > 0) {
            // get the highest slot ID as this takes precedence
            int highest_key = Collections.max(active.keySet());
            MPUEntry flags = active.get(highest_key);
            Msg.info(this, String.format("[%08x - %08x] %s", start, end, flags.toString()));

            String name = String.format("RAM_MPU%d", i);
            if (!memoryHelper.addUninitializedBlock(name,
                start, end-start+1, flags.isReadable(), flags.isWritable(),
                flags.isExecutable())) {
              Msg.error(this, String.format("Failed to create MPU block %s", name));
              return false;
            }
          }
        }

        return true;
    }

    private ArrayList<ScatterloadEntry> readScatterTable(Address start, Address end)
    {
      ArrayList<ScatterloadEntry> entries = new ArrayList<>();

      DataTypeManager dtm = fapi.getCurrentProgram().getDataTypeManager();
      StructureDataType scatterEntryStruct = new StructureDataType("ScatterLoadEntry", 0);

      scatterEntryStruct.add(new PointerDataType(), -1, "src", "");
      scatterEntryStruct.add(new PointerDataType(), -1, "dst", "");
      scatterEntryStruct.add(new UnsignedIntegerDataType(), -1, "size", "");
      scatterEntryStruct.add(new PointerDataType(), -1, "function", "");

      DataType dat = dtm.addDataType(scatterEntryStruct, DataTypeConflictHandler.REPLACE_HANDLER);

      long elements = (long)end.subtract(start) / dat.getLength();
      ArrayDataType adty = new ArrayDataType(dat, (int)elements, dat.getLength());

      DataType adtyadd = dtm.addDataType(adty, DataTypeConflictHandler.REPLACE_HANDLER);

      try {
        // Create the array of scatter entries
        Data array = fapi.createData(start, adtyadd);

        // for each entry in the Data array
        for (int i = 0; i < array.getNumComponents(); i++) {
          Data entry = array.getComponent(i);
          ScatterloadEntry slEntry = new ScatterloadEntry(
              ((Address)entry.getComponent(0).getValue()),
              ((Address)entry.getComponent(1).getValue()),
              ((Address)entry.getComponent(3).getValue()),
              ((Scalar)entry.getComponent(2).getValue()).getUnsignedValue());

          entries.add(slEntry);
        }

      } catch (Exception e) {
        Msg.error(this, "Scatter: exception creating the scatter entry type", e);

        // blank or partial list
        return entries;
      }

      return entries;
    }

    @Override
    public LoaderTier getTier() 
    {
        return LoaderTier.SPECIALIZED_TARGET_LOADER;
    }

    @Override
    public int getTierPriority() 
    {
        return 0;
    }

    @Override
    public String getName() 
    {
        return LOADER_NAME;
    }
}
