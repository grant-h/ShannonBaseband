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
import adubbz.nx.util.UIUtil;
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
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ShannonLoader extends BinaryLoader 
{
    public static final String LOADER_NAME = "Samsung Shannon Modem Binary";
    public static final LanguageID LANG_ID = new LanguageID("ARM:LE:32:v8");
    public static final long MAIN_TCM_ADDRESS = 0x04000000;

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
        TOCSectionHeader tocFirst;

        try {
            tocFirst = new TOCSectionHeader(reader);
        } catch (IOException e) {
            Msg.error(this, "Failed to read initial TOC section header");
            return false;
        }

        Msg.info(this, tocFirst.toString());

        long prevPointerIndex = reader.getPointerIndex();

        HashMap<String, TOCSectionHeader> headerMap = new HashMap<>();

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

            Msg.info(this, header.toString());
          } catch (IOException e) {
            Msg.error(this, String.format("Failed to next TOC section header index %d", headerMap.size()));
            return false;
          }
        }

        Msg.info(this, String.format("Found %d TOC sections", headerMap.size()));

        // required sections
        TOCSectionHeader sec_main = headerMap.get("MAIN");
        TOCSectionHeader sec_boot = headerMap.get("BOOT");

        if (sec_main == null || sec_boot == null) {
          Msg.error(this, "One or more of the sections [MAIN, BOOT] were not found");
          return false;
        }

        MemoryBlockHelper memory = new MemoryBlockHelper(monitor, program, messageLog, provider, 0L);

        PatternFinder finder = new PatternFinder(provider.getInputStream(sec_main.getOffset()), sec_main.getSize());
        int match = finder.find("\\x30\\x0c\\x80\\x04\\x28\\x00\\x00\\x00", -0x24);

        if (match == -1) {
          Msg.error(this, "Unable to find Shannon memory table pattern");
          return false;
        }

        Msg.info(this, String.format("Memory table 0x%08x", match));

        int match_mpu = finder.find("[\\x00]{8}\\x1c\\x00\\x00\\x00(....){6}\\x01\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x04\\x20");

        if (match_mpu == -1) {
          Msg.error(this, "Unable to find Shannon MPU table pattern");
          return false;
        }

        Msg.info(this, String.format("MPU table 0x%08x", match_mpu));

        ArrayList<AddressItem> addrEntries = new ArrayList<>();
        ArrayList<MPUEntry> mpuEntries = new ArrayList<>();
        reader.setPointerIndex(sec_main.getOffset()+match_mpu);

        while (true) {
          try {
            MPUEntry entry = new MPUEntry(reader);

            // Continue reading until we see a blank or empty section
            if (entry.getSlotId() == 0xff)
              break;

            mpuEntries.add(entry);

            addrEntries.add(new AddressItem(entry, false));
            addrEntries.add(new AddressItem(entry, true));

            Msg.info(this, entry.toString());
          } catch (IOException e) {
            Msg.error(this, String.format("Failed read to next MPU entry %d", mpuEntries.size()));
            return false;
          }
        }

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

        for (AddressItem it : addrEntries) {
          Msg.info(this, String.format("%s", it.toString()));
        }

        HashMap<Integer, MPUEntry> active = new HashMap<>();

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
            int highest_key = Collections.max(active.keySet());
            MPUEntry flags = active.get(highest_key);
            Msg.info(this, String.format("[%08x - %08x] %s", start, end, flags.toString()));

            memory.addUninitializedBlock(String.format("MPU_RAM%d", i),
                start, end-start+1, flags.isReadable(), flags.isWritable(),
                flags.isExecutable());
          }
        }

        reader.setPointerIndex(sec_main.getOffset()+match);

        ShannonMemEntry main_tcm_entry = null;

        // TODO: handle all memory addresses instead of just TCM
        while (true) {
          ShannonMemEntry entry = new ShannonMemEntry(reader);

          if (entry.getDestinationAddress() == MAIN_TCM_ADDRESS) {
            main_tcm_entry = entry;
            break;
          }

          if (entry.getSourceAddress() > 0x50000000 || entry.getSize() >= 0x10000000 ||
          entry.getFunction() > 0x50000000 || entry.getFunction() < 0x40010000) {
            break;
          }
        }

        if (main_tcm_entry == null) {
          Msg.error(this, "Unable to find memory copy operations for TCM region");
          return false;
        }

        long tcm_offset = main_tcm_entry.getSourceAddress() - sec_main.getLoadAddress() + sec_main.getOffset();

        try {
          memory.addMergeSection("MAIN", sec_main.getLoadAddress(),
              provider.getInputStream(sec_main.getOffset()), sec_main.getSize());
          memory.addMergeSection("MAIN_TCM", MAIN_TCM_ADDRESS,  provider.getInputStream(tcm_offset),
              main_tcm_entry.getSize());
          memory.addMergeSection("BOOT", sec_boot.getLoadAddress(),
              provider.getInputStream(sec_boot.getOffset()), sec_boot.getSize());

        } catch(AddressOverflowException | AddressOutOfBoundsException e) {
          e.printStackTrace();
          return false;
        }

        // Ensure memory blocks are ordered from first to last.
        // Normally they are ordered by the order they are added.
        UIUtil.sortProgramTree(program);

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
