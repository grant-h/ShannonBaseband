MIN_MATCH = 4

def lz4_decompress_sequences(src_buf, dst_buf):
    src_len = len(src_buf)
    src_ptr = 0
    while src_ptr < src_len:
        token = memoryview(src_buf)[src_ptr: src_ptr + 1]
        src_ptr += 1
        # get literal length
        lit_len = (token[0] >> 4) & 0x0F
        if lit_len == 15:
            while src_buf[src_ptr] == 255:
                lit_len += 255
                src_ptr += 1
            lit_len += src_buf[src_ptr]
            src_ptr += 1
        # copy literal
        dst_buf += src_buf[src_ptr: src_ptr + lit_len]
        src_ptr += lit_len
        if src_ptr >= src_len:  # last literal
            break
        # get match offset
        offset = int.from_bytes(src_buf[src_ptr:src_ptr + 2], 'little')
        src_ptr += 2
        # get match length
        match_len = token[0] & 0x0F
        if match_len == 15:
            while src_buf[src_ptr] == 255:
                match_len += 255
                src_ptr += 1
            match_len += src_buf[src_ptr]
            src_ptr += 1
        match_len += MIN_MATCH
        # copy match
        match_ptr = len(dst_buf) - offset
        while match_len > 0:
            dst_buf.append(dst_buf[match_ptr])
            match_ptr += 1
            match_len -= 1
