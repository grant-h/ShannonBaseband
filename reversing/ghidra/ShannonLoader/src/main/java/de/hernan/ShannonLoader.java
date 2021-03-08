/**
 * ShannonLoader
 * Created by Grant Hernandez, 2020
 */

package de.hernan;

import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import static java.util.Map.entry;
import java.util.Collection;
import java.util.Scanner;
import java.util.Comparator;
import java.util.List;

import adubbz.nx.loader.common.MemoryBlockHelper;
import de.hernan.TOCSectionHeader;
import de.hernan.util.PatternFinder;
import de.hernan.util.PatternEntry;
import de.hernan.util.ByteCharSequence;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
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
    public static final long MAIN_TCM_ADDRESS = 0x04000000;

    private MemoryBlockHelper memoryHelper = null;
    private HashMap<String, TOCSectionHeader> headerMap = new HashMap<>();
    private ArrayList<AddressItem> addrEntries = new ArrayList<>();
    private ArrayList<MPUEntry> mpuEntries = new ArrayList<>();
    private ArrayList<ShannonMemEntry> memEntries = new ArrayList<>();

    private int mpuTableOffset = -1;
    private int relocationTableOffset = -1;

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
                     "ShannonOS  # Prefix of OS version",
                     ".*?[\\x00] # Match until end of string"))
          )
        ),

        /* This pattern needs explaining. An MPU entry is a table that Shannon
         * will process to populate the MPU table of the Cortex-R series CPU.
         * Each entry is 40 bytes (10 words little-endian) with this layout (each field is 4 bytes):
         *
         * [slot][base][size][access_control]{6}[enable]
         *
         * Slot - the architectual MPU slot number
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

        /* This pattern ALSO needs explaining :)
         * It matches an entry in the boot time relocation table.
         *
         * These relocation entries are 16 bytes (4 words) of (src, dst, size, function).
         * Function is a pointer to memcpy, memset, or lz4_decode and they are called
         * with the first three fields as r0, r1, and r2 (first three args).
         * These relocations are used to load parts of the MAIN image to special memory regions
         * at boot and to decompress other resources into memory.
         *
         * This pattern matches midway (4 bytes) through a particularly stable entry (by inspection).
         * I suspect this is configuration data of some kind that is copied, but not sure beyond that.
         */

        entry("scatterload_table",
          List.of(
            // Cortex-R with TCM (pre-5G)
            // The negative offset of -4 realigns the table match address to start at the 'src' field
            new PatternEntry(String.join("\n",
              "\\x00\\x00\\x80\\x04 # the destination address of 0x04800000, which is right after the TCM region",
              "\\x20\\x0c\\x00\\x00 # the operation size (0xc20)"), -0x4),
            new PatternEntry("\\x00\\x00\\x50\\x47\\x00\\x00\\x00\\x04 # Cortex-A (5G)", -0x4)
          )
        ),

        // https://github.com/SysSec-KAIST/BaseSpec/blob/e027413148ce79f53bfdabb3bd5e6c2ffb291dcc/basespec/scatterload.py#L172
        // Hippity-hoppity your patterns are now my property~
        // Reference: https://developer.arm.com/documentation/dui0474/f/using-scatter-files?lang=en
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
    protected List<Program> loadProgram(ByteProvider provider, String programName,
            DomainFolder programFolder, LoadSpec loadSpec, List<Option> options, MessageLog log,
            Object consumer, TaskMonitor monitor)
                    throws IOException, CancelledException 
    {
        LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
        Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
        CompilerSpec importerCompilerSpec = importerLanguage.getCompilerSpecByID(pair.compilerSpecID);

        Address baseAddr = importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(0);
        Program prog = createProgram(provider, programName, baseAddr, getName(), importerLanguage, importerCompilerSpec, consumer);
        boolean success = false;

        try 
        {
            success = this.loadInto(provider, loadSpec, options, log, prog, monitor);
        }
        finally 
        {
            if (!success) 
            {
                prog.release(consumer);
                prog = null;
            }
        }

        List<Program> results = new ArrayList<Program>();
        if (prog != null) results.add(prog);
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
    protected boolean loadProgramInto(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            MessageLog messageLog, Program program, TaskMonitor monitor) 
                    throws IOException
    {
        BinaryReader reader = new BinaryReader(provider, true);
        memoryHelper = new MemoryBlockHelper(program, messageLog, 0L);

        if (!processTOCHeader(reader))
          return false;

        TOCSectionHeader sec_main = headerMap.get("MAIN");
        TOCSectionHeader sec_boot = headerMap.get("BOOT");

        if (sec_main == null || sec_boot == null) {
          Msg.error(this, "One or more of the required sections [MAIN, BOOT] were not found");
          return false;
        }

        PatternFinder finder = new PatternFinder(
            provider.getInputStream(sec_main.getOffset()), sec_main.getSize(),
            patternDB);

        // purely informational for now
        discoverSocVersion(finder);

        findShannonPatterns(finder, sec_main);

        if (mpuTableOffset != -1) {
          if (!readMPUTable(reader))
            return false;

          if (!calculateShannonMemoryMap())
            return false;
        }

        if (!loadBasicTOCSections(provider, sec_boot, sec_main))
          return false;

        doScatterload(program, finder, reader, provider);

        Msg.info(this, "==== Finalizing program trees ====");

        syncProgramTreeWithMemoryMap(program);
        organizeProgramTree(program);

        return true;
    }

    private boolean doScatterload(Program program, PatternFinder finder, BinaryReader reader, ByteProvider provider)
    {
        if (relocationTableOffset != -1) {
          if (!processRelocationTable(reader))
            return false;
        }

        Msg.info(this, String.format("==== Found %d scatterload entries ====", memEntries.size()));

        FlatProgramAPI fapi = new FlatProgramAPI(program);

        Map<String, Long> scatterFunctions = new HashMap<>();
        Map<Long, String> invScatterFunctions = new HashMap<>();

        scatterFunctions.put("__scatterload_copy", -1L);
        scatterFunctions.put("__scatterload_zeroinit", -1L);
        scatterFunctions.put("__scatterload_decompress", -1L);
        scatterFunctions.put("__scatterload_decompress2", -1L);

        for (String fn : scatterFunctions.keySet()) {
          int offset = finder.find_pat(fn);

          if (offset != -1) {
            long addr = offset+headerMap.get("MAIN").getLoadAddress();
            Msg.info(this, String.format("Scatter: Found %s @ 0x%08x",
                fn, addr));
            scatterFunctions.put(fn, addr);
            invScatterFunctions.put(addr, fn);
          }
        }

        for (ShannonMemEntry entry : memEntries) {
          if (!invScatterFunctions.containsKey(entry.getFunction())) {
            Msg.warn(this, String.format("Scatter: unrecovered/recognized scatter op %s",
                  entry));
            continue;
          }

          String scatterOp = invScatterFunctions.get(entry.getFunction());

          Msg.info(this, String.format("Scatter: applying %s(src=%08x, dst=%08x, size=%08x)",
                scatterOp, entry.getSourceAddress(), entry.getDestinationAddress(), entry.getSize()));

          AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
          Address scatterSrc = addressSpace.getAddress(entry.getSourceAddress());
          Address scatterDst = addressSpace.getAddress(entry.getDestinationAddress());

          byte [] data = null;

          try {
            if (scatterOp == "__scatterload_zeroinit") {
              data = new byte[(int)entry.getSize()];
            } else if (scatterOp == "__scatterload_copy") {
              data = fapi.getBytes(scatterSrc, (int)entry.getSize());
            } else if (scatterOp == "__scatterload_decompress") {
              data = ScatterDecompression.Decompress1(fapi, scatterSrc, (int)entry.getSize());
            } else if (scatterOp == "__scatterload_decompress2") {
              Msg.warn(this, "Scatter: not implemented " + scatterOp);
              continue;
              // TODO: decompress2
              //data = ScatterDecompression.Decompress1(fapi, scatterSrc, (int)entry.getSize());
            } else {
              throw new RuntimeException("Unhandled scatterload op " + scatterOp);
            }
          } catch (MemoryAccessException e) {
            Msg.error(this, String.format("Scatter: entry apply error %s", e));
            break;
          }

          if (!memoryHelper.initializeRange(entry.getDestinationAddress(), entry.getSize()))
            continue;

          try {
            fapi.setBytes(scatterDst, data);
          } catch (MemoryAccessException e) {
            Msg.error(this, String.format("Scatter: entry write error"), e);
          }
        }

        return true;
    }

    private boolean loadBasicTOCSections(ByteProvider provider, TOCSectionHeader sec_boot, TOCSectionHeader sec_main)
    {
        Msg.info(this, "==== Inflating primary sections ====");

        if (sec_boot.getLoadAddress() != 0L) {
          if (!addMergeSection(provider, sec_boot, "BOOT_MIRROR", 0L))
            return false;
        }

        // TODO: rename TCM region

        List<TOCSectionHeader> headerList = new ArrayList<>(headerMap.values());
        Collections.sort(headerList, (o1, o2) -> o1.getLoadAddress() - o2.getLoadAddress());

        for (TOCSectionHeader header : headerList) {
            // informative section such as OFFSET
            if (header.getLoadAddress() == 0) {
              Msg.warn(this, String.format("%s: Skipping entry - zero load address",
                  header.getName()));
              continue;
            }

            Msg.info(this, String.format("%s: %s", header.getName(), header.toString()));

            if (!addMergeSection(provider, header))
              return false;
        }

        return true;
    }

    private boolean addMergeSection(ByteProvider provider, TOCSectionHeader section)
    {
        return addMergeSection(provider, section, section.getName(), section.getLoadAddress());
    }

    private boolean addMergeSection(ByteProvider provider, ShannonMemEntry entry, String name)
    {
        return addMergeSection(provider, entry.getSourceFileOffset(), name, entry.getDestinationAddress(), entry.getSize());
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
          if (!memoryHelper.blockExists(loadAddress)) {
            Msg.warn(this, String.format("%s: No backing MPU entry. Falling back to RWX permissions",
                  name));
            return memoryHelper.addInitializedBlock(name, loadAddress, provider.getInputStream(offset), size,
                true, true, true);
          } else {
            return memoryHelper.addMergeSection(name, loadAddress,
                provider.getInputStream(offset), size);
          }
        } catch (AddressOverflowException | AddressOutOfBoundsException | IOException e) {
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
          Msg.info(this, String.format("Extracted OS version: %s", osVersion.group()));
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

        long prevPointerIndex = reader.getPointerIndex();

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

        relocationTableOffset = finder.find_pat("scatterload_table");

        if (relocationTableOffset == -1) {
          Msg.warn(this, "Unable to find boot-time relocation table pattern. This table is used to unpack the MAIN image during baseband boot, but we need to unpack it at load time in order to capture the TCM region. Without this significant portions of the most critical code will appear to be missing and all xrefs will be broken.");
        } else {
          Msg.info(this, String.format("Boot-time relocation table found in section=MAIN offset=0x%08x (physical address 0x%08x)",
                relocationTableOffset, relocationTableOffset+fromSection.getLoadAddress()));
        }
    }

    private boolean readMPUTable(BinaryReader reader)
    {
        reader.setPointerIndex(headerMap.get("MAIN").getOffset()+mpuTableOffset);

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
            long comp = o1.getAddr() - o2.getAddr();

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

    private boolean processRelocationTable(BinaryReader reader)
    {
        TOCSectionHeader sec_main = headerMap.get("MAIN");

        // this can fall into the middle of the table
        // so we need to scan backwards first
        int table_address_base = sec_main.getOffset()+relocationTableOffset;

        ShannonMemEntry entry = null;

        while (true) {
          try {
            reader.setPointerIndex(table_address_base);
            entry = new ShannonMemEntry(reader, sec_main);
          } catch (IOException e) {
              Msg.error(this, "Failed to read relocation table entry (backwards)");
              return false;
          }

          // discard entries that
          if (entry.getSourceAddress() > (sec_main.getLoadAddress()+sec_main.getSize()) || entry.getSize() >= 0x10000000 ||
              entry.getFunction() > (sec_main.getLoadAddress()+sec_main.getSize()) ||
              entry.getFunction() < sec_main.getLoadAddress()) {
            // undo our stride
            table_address_base += 0x10;
            break;
          }

          table_address_base -= 0x10;
        }

        reader.setPointerIndex(table_address_base);

        // okay we presumably have the table base. scan forwards to collect the entries
        while (true) {
          try {
            // will advance the reader
            entry = new ShannonMemEntry(reader, sec_main);
          } catch (IOException e) {
              Msg.error(this, "Failed to read relocation table entry (forwards)");
              return false;
          }

          // discard entries that
          if (entry.getSourceAddress() > (sec_main.getLoadAddress()+sec_main.getSize()) || entry.getSize() >= 0x10000000 ||
              entry.getFunction() > (sec_main.getLoadAddress()+sec_main.getSize()) ||
              entry.getFunction() < sec_main.getLoadAddress()) {
            break;
          }

          memEntries.add(entry);
        }

        return true;
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
