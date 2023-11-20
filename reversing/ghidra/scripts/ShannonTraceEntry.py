# Utilities to work with Shannon baseband TraceEntries
# @author Grant Hernandez (https://github.com/grant-h)
# @category Shannon
## Copyright (c) 2023, Grant Hernandez
## SPDX-License-Identifier: MIT

from __future__ import print_function
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SourceType
from ghidra.util import Msg
from ghidra.program.model.data import BuiltInDataTypeManager, DataTypeConflictHandler, StructureDataType

import os
import re

BADCHARS = re.compile(r'[^A-Za-z0-9_\[\]{}]')
PRINTFARG = re.compile(r'[^%](%[0-9lh]*[a-zA-Z])')

DEBUG_FIND = False
DEBUG_FIND_MAX_ENTRIES = 8000
DEBUG_RETYPE = False
DEBUG_RETYPE_SKIP = 0 # change to right before the entry giving errors

# Change to false if you don't want your output window to be spammed
SHOW_OUTPUT = True

FIND_STEP = 10000

def create_trace_entry():
    """create_trace_entry

    struct TraceEntry {
        uint magic;
        uint unk1;
        uint unk2;
        uint unk_magic;
        char * message;
        uint linenum;
        char * file;
    };
    """
    handler = DataTypeConflictHandler.REPLACE_HANDLER
    bi_dtm = BuiltInDataTypeManager.getDataTypeManager()
    dtm = currentProgram.getDataTypeManager()

    structure = StructureDataType("TraceEntry", 0)
    str_ptr = bi_dtm.getPointer(bi_dtm.getDataType("/string"))
    uint_ty = bi_dtm.getDataType("/uint")

    structure.add(uint_ty, 4, "magic", "")
    structure.add(uint_ty, 4, "unk1", "")
    structure.add(uint_ty, 4, "unk2", "")
    structure.add(uint_ty, 4, "unk_magic", "")
    structure.add(str_ptr, 4, "message", "")
    structure.add(uint_ty, 4, "linenum", "")
    structure.add(str_ptr, 4, "file", "")

    dtm.addDataType(structure, handler)

def fixup_format_string(fmt):
    """fixup_format_string

    :param fmt: The format string to reformat for GHIDRA names
    """
    arg_count = 1
    while True:
        match = re.search(PRINTFARG, fmt)
        if match is None:
            break
        repl = "{ARG%d_%s}" % (arg_count, match.group(1).replace("%", ""))

        fmt = fmt[:match.start(1)] + repl + fmt[match.end(1):]
        arg_count += 1

    message_str_fixed = re.sub(BADCHARS, "_", fmt.strip())
    message_str_fixed = re.sub(r'_+', "_", message_str_fixed)
    message_str_fixed = re.sub(r'(^_+)|(_+$)', "", message_str_fixed)

    return message_str_fixed


def force_create_string(fapi, addr, max_len):
    """force_create_string

    Creates a NULL terminated C-string at `addr'.

    :param fapi: The GHIDRA FlatProgramAPI instance
    :param addr: The start address of the string
    :param max_len: The potential maximum length of the string
    """
    try:
        data = fapi.getBytes(addr, max_len).tolist()
        strlen = data.index(0)
        fapi.clearListing(addr, addr.add(strlen))
    except ghidra.program.model.mem.MemoryAccessException as e:
        print("ERROR: force_create_string failed: %s" % str(e))
        return None

    return fapi.createAsciiString(addr)


def dump_trace_entries(fapi, filename, trace_entry_addrs):
    """dump_trace_entries

    :param fapi: The GHIDRA FlatProgramAPI instance
    :param filename: The output file
    :param trace_entry_addrs: Array of TraceEntry
    """
    fp = open(filename, 'w')

    print("Saving entries to '%s'" % (filename))
    maximum = len(trace_entry_addrs)

    monitor.setIndeterminate(False)
    monitor.initialize(maximum)
    monitor.setCancelEnabled(True)
    monitor.setProgress(0)
    monitor.setMessage("Saving TraceEntries...")

    for cur, caddr in enumerate(trace_entry_addrs):
        if monitor.isCancelled():
            break

        monitor.incrementProgress(1)

        trace_entry = getDataAt(caddr)

        # Still-unknown fields
        unk = [
            trace_entry.getComponent(1),
            trace_entry.getComponent(2),
            trace_entry.getComponent(3)]

        message_field = trace_entry.getComponent(4)
        line_field = trace_entry.getComponent(5)
        file_field = trace_entry.getComponent(6)

        message_addr = message_field.getValue()
        message_str = getDataAt(message_addr)

        line_field = line_field.getValue()
        line_str = line_field.getValue()

        file_addr = file_field.getValue()
        file_str = getDataAt(file_addr)

        # the compiler will reuse the suffixes of strings, so force creating
        # new strings will cause some flap between string start points
        if message_str is None or not isinstance(
                message_str.getValue(), unicode):
            message_str = force_create_string(fapi, message_addr, 1024)

            if message_str is None:
                fp.write("[%d/%d] Missing message string @ %s\n" %
                    (cur + 1, maximum, message_addr))
                continue

            if SHOW_OUTPUT:
                print(
                    "[%d/%d] Created missing message string @ %s" %
                    (cur + 1, maximum, message_addr))

        if file_str is None or not isinstance(file_str.getValue(), unicode):
            file_str = force_create_string(fapi, file_addr, 1024)

            if file_str is None:
                fp.write("[%d/%d] Missing file string @ %s\n" %
                    (cur + 1, maximum, file_addr))
                continue

            if SHOW_OUTPUT:
                print(
                    "[%d/%d] Created missing file string @ %s" %
                    (cur + 1, maximum, file_addr))

        message_str = message_str.getValue()
        file_str = file_str.getValue()

        for i in range(len(unk)):
            unk[i] = unk[i].getValue().getValue()

        fp.write("[%d/%d] [%s] %08x %08x %08x %08x [%s] %s\n" %
            (cur + 1, maximum, caddr,
             unk[0], unk[1], unk[2],
             line_str, file_str, message_str))

    fp.close()

    print("Wrote %d entries to '%s'" % (maximum, filename))

def main():
    fapi = FlatProgramAPI(currentProgram)


    te_list = fapi.getDataTypes("TraceEntry")

    if len(te_list) == 0:
        create_trace_entry()
        te_list = fapi.getDataTypes("TraceEntry")

        if len(te_list) == 0:
            print("ERROR: failed to create TraceEntry data type")
            return

    te = te_list[0]

    caddr = fapi.toAddr(0)

    monitor.setCancelEnabled(True)
    monitor.setIndeterminate(True)

    trace_entry_addrs = []
    while caddr is not None and not monitor.isCancelled():
        # Ghidra findBytes returns one address more than requested at a really
        # high offset; hence, we need to manual limit the amount of entries.
        caddrs = fapi.findBytes(caddr, "DBT:", FIND_STEP, 4)[:FIND_STEP]

        if not caddrs:
            break

        trace_entry_addrs += caddrs

        caddr = caddrs[-1].add(4)

        monitor.setMessage("Found %d TraceEntries" % len(trace_entry_addrs))

        if DEBUG_FIND and len(trace_entry_addrs) > DEBUG_FIND_MAX_ENTRIES:
            break

    print("Found %d TraceEntry structures" % len(trace_entry_addrs))

    # Uncomment if you just want to dump the entries
    #dump_trace_entries(fapi, "trace-entries.txt", trace_entry_addrs); return

    maximum = len(trace_entry_addrs)
    monitor.setIndeterminate(False)
    monitor.initialize(maximum)
    monitor.setCancelEnabled(True)

    monitor.setProgress(0)
    monitor.setMessage("Typing TraceEntries...")

    for cur, caddr in enumerate(trace_entry_addrs):
        if monitor.isCancelled():
            break

        monitor.incrementProgress(1)

        if DEBUG_RETYPE and cur < DEBUG_RETYPE_SKIP:
            continue

        try:
            fapi.clearListing(caddr, caddr.add(te.getLength()))

            trace_entry = fapi.createData(caddr, te)
            message_field = trace_entry.getComponent(4)
            file_field = trace_entry.getComponent(6)

            message_addr = message_field.getValue()
            message_str = getDataAt(message_addr)

            file_addr = file_field.getValue()
            file_str = getDataAt(file_addr)

            if message_str is None or not isinstance(
                    message_str.getValue(), unicode):
                message_str = force_create_string(fapi, message_addr, 1024)
                if message_str is None:
                    continue
                if SHOW_OUTPUT:
                    print(
                        "[%d/%d] Created missing message string @ %s" %
                        (cur + 1, maximum, message_addr))

            if file_str is None or not isinstance(file_str.getValue(), unicode):
                file_str = force_create_string(fapi, file_addr, 1024)
                if file_str is None:
                    continue
                if SHOW_OUTPUT:
                    print(
                        "[%d/%d] Created missing file string @ %s" %
                        (cur + 1, maximum, file_addr))

            #print(type(message_str.getValue()), message_str.getValue())

            message_str = message_str.getValue()
            if message_str is None:
                continue
            file_str = file_str.getValue()

            message_str_fixed = fixup_format_string(message_str)

            #print("[%s] %s" % (file_str, message_str_fixed))
            base_file = os.path.basename(file_str).split(".")[0]
            symbol_name = "TraceEntry::%s::%s" % (base_file, message_str_fixed)
            # limit the length
            symbol_name_assign = symbol_name[:min(len(symbol_name), 60)]
            fapi.createLabel(
                caddr,
                symbol_name_assign,
                True,
                SourceType.USER_DEFINED)

            if SHOW_OUTPUT:
                print("[%d/%d] [%s] %s" % (cur + 1, maximum, caddr, symbol_name))
        except ghidra.program.model.mem.MemoryAccessException:
            # this happens with the false positive match of "DBT:String too long"
            print(
                "[%d/%d] [%s] Invalid TraceEntry signature!" %
                (cur + 1, maximum, caddr))
        except ghidra.program.model.util.CodeUnitInsertionException:
            print(
                "[%d/%d] Something else already at %s" %
                (cur + 1, maximum, caddr))
            # Uncomment this raise, if you want to catch all strangeness
            # raise

    print('Done!')

main()
