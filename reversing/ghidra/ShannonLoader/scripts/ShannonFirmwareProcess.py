#!/usr/bin/env python3
## Copyright (c) 2023, Grant Hernandez (https://github.com/grant-h)
## SPDX-License-Identifier: MIT
import argparse
import tempfile
import sys
import logging
import os
import tarfile
import hashlib
from pathlib import Path
import glob

from subprocess import Popen, PIPE

log = logging.getLogger(__name__)

class GhidraHeadless:
    def __init__(self, ghidra_headless):
        self.ghidra_headless = ghidra_headless

    def load(self, project_path, project_name, binary_path):
        return self._exec(project_path, project_name, binary_path)

    def load_overwrite(self, project_path, project_name, binary_path, overwrite=True):
        return self._exec(project_path, project_name, binary_path, overwrite=overwrite)

    def _exec(self, project_path, project_name, binary_path, analyze=False, overwrite=False):
        args = [self.ghidra_headless, project_path, project_name,
                "-loader", "ShannonLoader"]

        if not analyze:
            args += ["-noanalysis"]

        if overwrite:
            args += ["-overwrite"]

        args += ["-import", binary_path]
        args += ["-log", "ghidra.log"]

        proc = Popen(args)
        proc.communicate()

        retval = proc.returncode

        with tempfile.TemporaryFile() as tfile:
            # Ghidra error codes are inconsistent
            for line in tfile.readlines():
                # TODO: handle this error detection better as we may not be just importing
                if "ERROR REPORT: Import failed":
                    retval = 1

        return not bool(retval)

def main():
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument("project_path")
    parser.add_argument("project_name")
    parser.add_argument("binary_path")
    args = parser.parse_args()

    tmpdir = tempfile.TemporaryDirectory()

    log.info("Using temporary directory for intermediate results %s",
            tmpdir.name)

    if "GHIDRA_INSTALL_DIR" not in os.environ:
        log.error("GHIDRA_INSTALL_DIR not provided")
        return 1

    ghidra_headless = Path(os.environ["GHIDRA_INSTALL_DIR"]) / "support" / "analyzeHeadless"

    if not os.access(ghidra_headless, os.X_OK):
        log.error("Unable to find analyzeHeadless binary")
        return 1

    ghidra_cmd = GhidraHeadless(ghidra_headless)

    candidate_images = []
    binary_list = []
    seen_hash = {}

    if os.path.isdir(args.binary_path):
        log.info("%s is a directory. Finding shannon binaries to analyze...",
                args.binary_path)

        candidate_images = []
        candidate_images += glob.glob(args.binary_path + "/*.tar*")
        candidate_images += glob.glob(args.binary_path + "/*.bin*")
        candidate_images = sorted(list(set(candidate_images)))
    else:
        candidate_images += [args.binary_path]

    log.info("Processing %d potential firmware images...", len(candidate_images))

    while len(candidate_images) > 0:
        image = candidate_images.pop()
        image_basename = str(os.path.basename(image)).split(".")[0]
        proc = Popen(["file", "--brief", "--mime-type", image], stdout=PIPE, stderr=PIPE)
        result, _ = proc.communicate()

        if proc.returncode != 0:
            log.warning("Unable to get mime type from %s", image)
            continue

        mime_type = result.decode().strip()

        #print("\n=====> Process %s (%s)" % (image, mime_type))

        if mime_type == "application/x-lz4":
            decompressed_path = Path(tmpdir.name) / os.path.basename(image)
            log.info("Decompressing %s...", image)
            proc = Popen(["lz4", "-f", "-d", image, decompressed_path], stdout=PIPE, stderr=PIPE)
            proc.communicate()

            if proc.returncode != 0:
                log.error("Failed to lz4 decompress %s", image)
            else:
                log.info("Decompressed %s", image)
                candidate_images += [decompressed_path]
        elif mime_type == "application/x-tar":
            with tarfile.open(image) as tarfp:
                members = tarfp.getnames()

                member_to_extract = None
                for member in members:
                    if "modem.bin" in member:
                        member_to_extract = member
                        break

                if member_to_extract is None:
                    log.warning("Unable to find modem.bin in tar file %s",
                            image)
                else:
                    if member_to_extract.startswith("/") or ".." in member_to_extract:
                        log.warning("Refusing to extract member %s from %s due to dangerous file path",
                                member_to_extract, image)
                    else:
                        new_name = image_basename + "_" + member_to_extract
                        extracted_dir = Path(tmpdir.name) / (image_basename + "_tarext")
                        extracted_path = extracted_dir / os.path.basename(new_name)

                        try:
                            os.mkdir(extracted_dir)
                        except FileExistsError:
                            pass
                        with tarfp.extractfile(member_to_extract) as fp:
                            with open(extracted_path, 'wb') as newfp:
                                newfp.write(fp.read())

                        log.info("Extracted %s image from %s", member_to_extract, image)
                        candidate_images += [extracted_path]
        elif mime_type == "application/octet-stream":
            with open(image, 'rb') as fp:
                fourcc = fp.read(4)

                if fourcc != b"TOC\x00":
                    log.warning("Unknown binary: %s", image)
                    continue

                firmware_hash = hashlib.md5(fourcc + fp.read()).hexdigest()
                if firmware_hash in seen_hash:
                    log.warning("Ignoring duplicate modem binary %s. MD5 %s matches already seen binary %s",
                            image, firmware_hash, seen_hash[firmware_hash])
                else:
                    seen_hash[firmware_hash] = image
                    binary_list += [image]
        else:
            log.warning("Unhandled mime type %s for %s",
                    mime_type, image)

    binary_list = sorted(binary_list, key=lambda x: os.path.basename(x))
    log.info("Successfully found %d modem images", len(binary_list))

    all_okay = True

    log.info("Will analyze %d modem images to Ghidra project %s/%s",
            len(binary_list), args.project_path, args.project_name)

    for binary in binary_list:
        log.info("Analyzing %s", binary)
        if not shannon_analyze(ghidra_cmd, args.project_path, args.project_name, binary):
            all_okay = False

    del tmpdir
    # invert error code
    return int(not all_okay)

def shannon_analyze(ghidra_cmd, project_path, project_name, binary_path):
    if not os.access(binary_path, os.R_OK):
        log.error("Binary to analyze %s doesn't exist", binary_path)
        return False

    if not ghidra_cmd.load_overwrite(project_path, project_name, binary_path):
        log.info("Failed to load binary %s", binary_path)
        return False

    return True

if __name__ == "__main__":
    sys.exit(main())


