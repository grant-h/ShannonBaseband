/**
 * ShannonLoader
 * Created by Grant Hernandez, 2020
 */

package de.hernan;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Collection;
import java.util.Scanner;
import java.util.Comparator;
import java.util.List;

import adubbz.nx.loader.common.MemoryBlockHelper;
import de.hernan.TOCSectionHeader;
import de.hernan.util.PatternFinder;

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

        PatternFinder finder = new PatternFinder(provider.getInputStream(sec_main.getOffset()), sec_main.getSize());

        if (!findShannonPatterns(finder, sec_main))
          return false;

        if (!readMPUTable(reader))
          return false;

        if (!processRelocationTable(reader))
          return false;

        ShannonMemEntry main_tcm_entry = null;

        Msg.info(this, String.format("==== Found %d relocation entries ====", memEntries.size()));

        for (ShannonMemEntry entry : memEntries) {
          Msg.info(this, String.format("%s", entry.toString()));

          if (entry.getDestinationAddress() == MAIN_TCM_ADDRESS) {
            main_tcm_entry = entry;
            // don't break so can show all of the things we aren't currently handling
            //break;
          }
        }

        Msg.warn(this, "Only the TCM relocation entry is currently supported!");

        // TODO: handle all memory addresses instead of just TCM
        if (main_tcm_entry == null) {
          Msg.error(this, "Unable to find memory copy operations for TCM region");
          return false;
        }

        if (!calculateShannonMemoryMap())
          return false;

        long tcm_offset = main_tcm_entry.getSourceAddress() - sec_main.getLoadAddress() + sec_main.getOffset();

        Msg.info(this, "==== Inflating primary sections ====");

        try {
          if (!memoryHelper.addMergeSection("TCM", MAIN_TCM_ADDRESS,  provider.getInputStream(tcm_offset),
              main_tcm_entry.getSize()))
            return false;

          if (!memoryHelper.addMergeSection("BOOT_MIRROR", 0L,
              provider.getInputStream(sec_boot.getOffset()), sec_boot.getSize()))
            return false;

          if (!memoryHelper.addMergeSection("BOOT", sec_boot.getLoadAddress(),
              provider.getInputStream(sec_boot.getOffset()), sec_boot.getSize()))
            return false;

          if (!memoryHelper.addMergeSection("MAIN", sec_main.getLoadAddress(),
              provider.getInputStream(sec_main.getOffset()), sec_main.getSize()))
            return false;

        } catch(AddressOverflowException | AddressOutOfBoundsException e) {
          e.printStackTrace();
          return false;
        }

        Msg.info(this, "==== Finalizing program trees ====");

        syncProgramTreeWithMemoryMap(program);
        organizeProgramTree(program);

        return true;
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
        finder.match("(?<SOC>[S][0-9]{3,}(AP)) # SOC-ID\n" +
                    ".{0,10}                   # garbage or unknown (usually underscores)\n" +
                    "(?<date>[0-9]{8})         # Date as YYYYMMDD (for rough SoC revision)\n" +
                    "[^\\x00]*                 # null terminator");

        if (!socFields.find()) {
          Msg.warn(this, "Unable to find version string in MAIN section");
        }

        String soc = socFields.group("SOC");
        String socDate = socFields.group("date");

        Msg.info(this, String.format("Extracted SoC information: SOC %s, revision %s", soc, socDate));
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
        Collections.sort(headerList, (o1, o2) -> o1.getOffset() - o2.getOffset());

        for (TOCSectionHeader header : headerList) {
            Msg.info(this, header.toString());
        }

        /* Not clear what VSS is in reality. Its not that important for Shannon security research
         * to the best of my knowledge though. More reversing needed to confirm this.
         */
        Msg.warn(this, "This loader only supports BOOT and MAIN section loading. VSS audio DSP (?) not handled");

        return true;

    }

    // TODO: add label and types to tables
    private boolean findShannonPatterns(PatternFinder finder, TOCSectionHeader fromSection)
    {
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
         * SO...now about this pattern. Well this pattern is matching the first MPU entry:
         *
         * [\x00]{8} - matches a slot ID of 0 and base address of 0x00000000
         * \x1c\x00\x00\x00 - matches a size code 0x8000 bytes
         * (....){6} - matches 6 arbitrary 4-byte values
         * \x01\x00\x00\x00 - matches an enable of 1
         * \x01\x00\x00\x00 - matches the next entry slot ID of 1
         * \x00\x00\x00\x04 - matches address 0x04000000 which is the Cortex-R Tightly Coupled Memory (TCM) region
         * \x20 - matches the size code of 0x20000 
         */

        mpuTableOffset = finder.find("[\\x00]{8}\\x1c\\x00\\x00\\x00(....){6}\\x01\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x04\\x20");

        if (mpuTableOffset == -1) {
          Msg.error(this, "Unable to find Shannon MPU table pattern. MPU recovery is essential for correct section permissions which will improve analysis determining what is code and what is data.");
          return false;
        }

        Msg.info(this, String.format("MPU entry table found in section=MAIN offset=0x%08x (physical address 0x%08x)",
              mpuTableOffset, mpuTableOffset+fromSection.getLoadAddress()));

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
         *
         * \x00\x00\x80\x04 - the destination address of 0x04800000, which is right after the TCM region
         * \x20\x0c\x00\x00 - the operation size (0xc20)
         *
         * The negative offset of -4 realigns the table match address to start at the 'src' field.
         */

        relocationTableOffset = finder.find("\\x00\\x00\\x80\\x04\\x20\\x0c\\x00\\x00", -0x4);

        if (relocationTableOffset == -1) {
          Msg.error(this, "Unable to find boot-time relocation table pattern. This table is used to unpack the MAIN image during baseband boot, but we need to unpack it at load time in order to capture the TCM region. Without this significant portions of the most critical code will appear to be missing and all xrefs will be broken.");
          return false;
        }

        Msg.info(this, String.format("Boot-time relocation table found in section=MAIN offset=0x%08x (physical address 0x%08x)",
              relocationTableOffset, relocationTableOffset+fromSection.getLoadAddress()));

        return true;
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
            entry = new ShannonMemEntry(reader);
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
            entry = new ShannonMemEntry(reader);
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
