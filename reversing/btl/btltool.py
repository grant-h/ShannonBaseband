#!/usr/bin/env python3
## Copyright (c) 2023, Grant Hernandez (https://github.com/grant-h)
## SPDX-License-Identifier: MIT
#
# A python script to decode Samsung .BTL files that are generated during
# Shannon modem dumps / crashes. Check out the 'BTL' task in the modem
# for hints as how this file is generated

import sys
import re
import struct
import binascii
import argparse
from minilz4 import lz4_decompress_sequences

BTL_SUPPORTED_VERSION = b"1100"
SLOG_MAGIC = b"SLOG"
CBUF_MAGIC = b"CBUF"
BUFN_MAGIC = [b"BUF1", b"BUF2", b"BUF3", b"BUF4"]
BTL_MIN_HEADER_SIZE = 0x30
FORMAT_SPECIFIER = re.compile('%?%[0-9lh.]*[a-zA-Z]')

class BadFileError(Exception):
    def __init__(self, message):
        super(BadFileError, self).__init__(message)

def process_btl(data):
    btl_magic = data[:4]

    if btl_magic != b"BTL:":
        raise BadFileError("Invalid BackTraceLog (BTL) magic")

    if  len(data) < BTL_MIN_HEADER_SIZE:
        raise BadFileError("BTL size is smaller than minium length")

    offset = 0
    btl_buffer_size = struct.unpack("I", data[4:0x8])[0]
    btl_version = data[8:0xc]

    if btl_version != BTL_SUPPORTED_VERSION:
        raise BadFileError("Unsupported BTL version '%s' (expected '%s')" % (btl_version, BTL_SUPPORTED_VERSION))

    offset += 0xc
    sub_buffer_count1, sub_buffer_count2, buf1, buf2, buf3, buf4 = struct.unpack("6I", data[offset:offset+6*4])

    buffers = [buf1, buf2, buf3, buf4]

    for i, buf in enumerate(buffers):
        buf_start = buf + offset - 0xc
        process_bufn(data[buf_start:])

    offset += 4*6
    cbuf_magic, cbuf_end_offset, cbuf_size = struct.unpack("3I", data[offset:offset+3*4])

    # process 'N' SLOG entries
    slog_start = data[offset+3*4:]

    while is_likely_slog(slog_start):
        decompressed, skip_amount = process_slog_compressed(slog_start)
        process_slog(decompressed)
        slog_start = slog_start[skip_amount:]

def is_likely_slog(data):
    return len(data) > 0x10 and data[:4] == SLOG_MAGIC

def process_slog_compressed(data):
    if not is_likely_slog(data):
        raise BadFileError("Invalid SLOG magic or header is too small")

    compressed_size = struct.unpack("I", data[4:8])[0]
    log_id = struct.unpack("I", data[8:0xc])[0]
    uncompressed_size = struct.unpack("I", data[0xc:0x10])[0]

    if len(data)-0x10 < compressed_size:
        raise BadFileError("Truncated SLOG (header requests %u bytes, but only have %u left)" % (compressed_size, len(data)-0x10))

    dst_buf = bytearray()
    lz4_decompress_sequences(memoryview(data)[0x10:0x10+compressed_size], dst_buf)

    if len(dst_buf) != uncompressed_size:
        raise BadFileError("SLOG head uncompressed size does match file size (expected %u, got %u)" % (uncompressed_size, len(dst_buf)))

    # output buffer, skip amount
    return dst_buf, compressed_size+0x10

def process_bufn(data):
    bufn_magic = data[:4]

    if bufn_magic not in BUFN_MAGIC:
        raise BadFileError("Unexpected BUFn magic %s (need one of %s)" % (bufn_magic, BUFN_MAGIC))

    buf_offset, buf_len = struct.unpack("2I", data[4:0xc])

    try:
        process_slog(data[0xc:0xc+buf_len])
    except ValueError as e:
        raise BadFileError("Error when decoding SLOG frames: %s" % e)

def hex_dump(data):
    hx = binascii.hexlify(data)

    for i, d in enumerate(data):
        if i % 2 == 0 and i > 0:
            sys.stdout.write(" ")

        sys.stdout.write("%02x" % d)

    sys.stdout.write("\n");

def read_modem(address, size):
    offset = address - 0x40010000

    if offset < 0:
        raise ValueError("Modem read address 0x%08x is invalid. This is likely the result of a mismatched modem.bin/*.BTL file pair" % (address))

    return MODEM_DATA[offset:offset+size]

def read_cstring(data, maxlen=0x200):
    st = b""
    i = 0

    while i < len(data) and i < maxlen and data[i] != 0:
        st += bytes(data[i:i+1])
        i += 1

    return st.decode('ascii', 'ignore')

def read_modem_bytes(address, size):
    return read_modem(address, size).tobytes()

def vsprintf(fmt, entry):
    argv_resolved = []

    res = FORMAT_SPECIFIER.findall(fmt)

    for i, r in enumerate(res):
        if r[0] == '%' and r[1] == '%':
            continue

        arg_size = 4
        arg = struct.unpack("I", entry[:4])[0]

        if r[-1] == 's':
            if arg == 0:
                arg = "(NULL)"
            else:
                # TODO: make variable length
                arg = read_cstring(read_modem(arg, 0x200))
        elif r[-1] == 'C':
            fmt = fmt.replace(r, r[:-1] + "c")
        elif r[-1] == 'p':
            fmt = fmt.replace(r, "0x%08x")

        argv_resolved += [arg]
        entry = entry[arg_size:]

    try:
        formatted = fmt % tuple(argv_resolved[:len(res)])
    except (TypeError, ValueError) as e:
        formatted = "FORMAT ERROR: [%s] [%s] [%s]" % (str(fmt), str(res), str(argv_resolved))

    return formatted

def process_slog(data):
    ptr = data

    while len(ptr) > 4:
        eptr = ptr
        slog_entry_header = eptr[0:3]
        start_of_frame, size = struct.unpack("=BH", slog_entry_header)

        if start_of_frame != 0x7f:
            raise BadFileError("Invalid start-of-frame")

        # move to next slog entry
        ptr = ptr[2+size:]

        eptr = eptr[4:size+2] # skip header and padding
        sub_length = struct.unpack("H", eptr[:2])[0] # 2-byte sub length

        if sub_length != len(eptr)-1:
            raise BadFileError("Entry sub-length does not match entry length")

        if eptr[-1] != 0x7e:
            raise BadFileError("Invalid end-of-frame")

        eptr = eptr[2:]
        unk2 = eptr[:10]

        # TODO: reverse engineer these fields
        # 0000 a1 45 01 840f0000 00
        # 14ea a1 45 01 850f0000 e2
        # 0000 a1 45 01 850f0000 00
        # 1c02 a1 45 01 850f0000 00
        # 0000 a1 45 01 850f0000 1e
        # 0000 a1 45 01 860f0000 00
        flag1, flag2, flag3, flag4, uptime, flag5 = struct.unpack("=HBBBIB", unk2)

        if flag4 != 1:
            print("[WARN] Skipping unhandled entry type 0x%02x" % flag4)
            continue

        eptr = eptr[10:]
        entry = eptr
        trace_entry_p = struct.unpack("I", entry[:4])[0]
        entry = entry[6:]
        format_arg_count = entry[0]
        entry = entry[1:]

        trace_entry = struct.unpack("7I", read_modem(trace_entry_p, 0x4*7))
        te_magic, te_unk1, te_unk2, te_unk_magic, te_fmt, te_linenum, te_file = trace_entry

        fmt = read_cstring(read_modem(te_fmt, 0x200))
        file_name = read_cstring(read_modem(te_file, 0x200))

        try:
            formatted = vsprintf(fmt, entry)
            #print("[%.2f] flag1=0x%x flag2=0x%x flag3=0x%x flag4=0x%x flag5=0x%x 0x%08x: [%s:%d] %s" % (
            #    uptime, flag1, flag2, flag3, flag4, flag5, trace_entry_p, file_name, te_linenum, formatted.rstrip()))
            print("[%.2f] 0x%08x: [%s:%d] %s" % (uptime, trace_entry_p, file_name, te_linenum, formatted.rstrip()))
        except ValueError as e:
            print("[ERROR %s]: %s" % (str(e), fmt))

def main():
    parser = argparse.ArgumentParser()
    # this is the MAIN TOC entry in the overall modem.bin
    parser.add_argument("modem_file", help="Path to the MAIN section extracted from modem.bin. Required to resolve debugging strings.")
    parser.add_argument("cplog_file", help="Path to the BTL log file.")

    args = parser.parse_args()

    btl_data = ""

    try:
        global MODEM_DATA
        MODEM_DATA = memoryview(open(args.modem_file, 'rb').read())
    except IOError as e:
        print("Unable to open modem image: %s" % e)
        return 1

    try:
        btl_data = open(args.cplog_file, 'rb').read()
    except IOError as e:
        print("Unable to open profile BTL file: %s" % e)
        return 1

    try:
        process_btl(btl_data)
    except KeyboardInterrupt as e:
        return 130
    except BadFileError as e:
        print("Error when processing BTL file: %s" % e)
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
