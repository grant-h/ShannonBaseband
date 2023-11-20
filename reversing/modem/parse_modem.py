#!/usr/bin/env python2
## Copyright (c) 2023, Grant Hernandez (https://github.com/grant-h)
## SPDX-License-Identifier: MIT
import os
import struct
import sys
import argparse

class TOC(object):
	def __init__(self, fstream, fpos = None):
		try:
			if fpos != None:
				fstream.seek(fpos)
			self.buf = fstream.read(32)
		except IOError:
			print("Not enough bytes in stream")
			self.buf = []

	def unpack(self):
		self.name = str(self.buf[:12]).strip("\x00")
		self.offset = struct.unpack("i", self.buf[12:16])[0] 
		self.load_address = struct.unpack("i", self.buf[16:20])[0] 
		self.size = struct.unpack("i", self.buf[20:24])[0]
		self.unk1 = struct.unpack("i", self.buf[24:28])[0]
		self.id = struct.unpack("i", self.buf[28:32])[0]

	def info(self):
		print("TOC Name: %s" % self.name)
		print("Load address: 0x%08x" % self.load_address)
		print("Offset: 0x%08x" % self.offset)
		print("Size: 0x%08x" % self.size)
		print("Unk: 0x%08x" % self.unk1)
		print("ID: %d" % self.id)

def unpack_toc_struct(fmw, name):
	hdr = TOC(fmw)
	hdr.unpack()
	hdr.pprint()
	assert(hdr.name == name)
	return hdr

def unpack_img(fmw, hdr, Type):
	img = Type(fmw, hdr)
	img.unpack()
	return img

def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--unpack-all", action="store_true",
                help="Unpack all of the sections in the TOC file")
        parser.add_argument("modem_image",
                help="Path to the modem.bin image to extract")
        args = parser.parse_args()

        print("TOC Extractor v1.0")

        # TODO: we need a way to discover TOC version for backwards compatibility
        with open(args.modem_image, "rb") as fmw:
            toc_header = TOC(fmw)
            toc_header.unpack()

            headers = []
            last_header = toc_header

            while fmw.tell() < toc_header.size:
                hdr = TOC(fmw)
                hdr.unpack()

                if hdr.name != "":
                    headers += [hdr]
                else:
                    break

            print("Found [%s] sections...\n" % ", ".join([x.name for x in headers]))

            for section in headers:
                section.info()
                name = section.name

                if args.unpack_all:
                    fmw.seek(section.offset)

                    output_name = '%s_%s_%08x' % (args.modem_image, name, section.load_address)
                    data_out = ""
                    data_size = 0

                    print("Extracting %s -> %s" % (name, output_name))

                    # Only extract sections that are non-virtual (actually present in the TOC)
                    if section.offset > 0:
                        if name == "BOOT":
                            data_size = section.size - 512 - 4*4
                        else:
                            data_size = section.size

                        data_out = fmw.read(data_size)

                    if len(data_out) != data_size:
                        print("ERROR: short read (wanted %d, got %d)" % (data_size, len(data_out)))
                        return 1

                    with open(output_name, 'wb') as fp:
                        fp.write(data_out)

                print("")

if __name__ == "__main__":
	main()
