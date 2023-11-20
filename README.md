# Samsung's Shannon Baseband Tool Repository [![Build and test ShannonLoader](https://github.com/grant-h/ShannonBaseband/actions/workflows/ShannonLoader.yml/badge.svg)](https://github.com/grant-h/ShannonBaseband/actions/workflows/ShannonLoader.yml)

Scripts, tools, and information to help reverse engineer Samsung's EXYNOS cellular baseband platform, codenamed Shannon.
These tools were released for the talk ["Emulating Samsung's Shannon Baseband for Security Testing"](https://www.blackhat.com/us-20/briefings/schedule/#emulating-samsungs-baseband-for-security-testing-20564) at Black Hat USA'2020, August 5th.

## Index

### [ShannonLoader: `reversing/ghidra/ShannonLoader`](reversing/ghidra/ShannonLoader)
A Ghidra extension for loading `modem.bin` binaries from nearly all known modems to date. All firmware images from https://github.com/grant-h/ShannonFirmware are loaded during CI tests for the loader to ensure its compatibility.

### [Ghidra Scripts: `reversing/ghidra/scripts`](reversing/ghidra/scripts)
Ghidra post-loading Python scripts that help annotate Shannon modem images.
This includes recovering debug strings and auto-naming functions.
Use after loading with ShannonLoader.

### [Modem Binary Scripts: `reversing/modem`](reversing/modem)
Raw `modem.bin` extraction script into sub parts and others as they are developed.

### [Modem Log File Processing: `reversing/btl`](reversing/btl)
Scripts and info to parse Back Trace Log (BTL) files. These are included during modem crashes / dumps or via the "CP RAM Logging" functionality.
These are compressed log files from the actual running modem.

### [Extracted Firmware Structures: `firmware/`](firmware/)
Information on firmware acquistion and some extracted data dumps.

## Getting started with Shannon Firmware
Here's a quick tutorial to start reversing this firmware with [GHIDRA](https://ghidra-sre.org/).

1. Download the firmware binary of choice. Make sure you have extracted the CP partition from official Samsung firmware and have further extracted the `modem.bin` file. Make sure to unlz4 the binary if it is compressed.
1. Install the ShannonLoader at the splash screen using *File* &raquo; *Install Extensions...*. Target the `ShannonLoader.zip` release that is in the latest release tag
1. Now start a new GHIDRA project and add a new file. Select the `modem.bin` file. You should see that this file's loader is automatically selected as "Samsung Shannon Modem Binary". If you do not see this, make sure that you have loaded the right file and installed the extension properly. Open GHIDRA debug console (bottom right on splash screen) to double check if there are any errors.
1. Import the file, let the loader finish and once again make sure there were no errors during loading.
1. Double click on the imported file to open CodeBrowser and hit no to auto-analysis for now.
1. Now run the `ShannonTraceEntry.py` python script from Script Manager under the "Shannon" category. Make sure to either place scripts into your user home directory at `~/ghidra_scripts` (Linux) or add the path to them in the manager. This script will identify all trace debugging information before analysis and avoid diassembling data.
1. Go to *Analysis* &raquo; *Auto analyze...*, and **uncheck the "Non-returning Functions - Discovered" analyzer** as this causes broken recovery of the `log_printf` function, leading to broken disassembly throughout the binary. If you do not uncheck this, you will need to restart your import from scratch.
1. Hit analyze and let GHIDRA churn away until it settles.
1. Next optionally run the auto-renamer script, `ShannonRename.py`. This will help you navigate the binary, but remember that the names are heuristically determined, so quality may vary. Functions with the same guessed name will have a numeric prefix appended.
1. Start reversing!

If you want a quick look around, [we exported a GHIDRA project for a 2017 modem image](https://mega.nz/file/S04TWSLD#9fUma__iIz4mpvGlTRnDjCfm7hjUo9IIpirx51-CqjY).

## Related Resources

* ShannonRE (Comsecuris, REcon 2016) - https://github.com/Comsecuris/shannonRE
* Awesome Baseband Research - https://github.com/lololosys/awesome-baseband-research

## License

The repository's license is MIT. NOTE: The top-level license covers only files that explicitly contain SPDX markings, not the entire repository. For other files, they may not be licensable (e.g. binary dumps, firmware) or may contain other permissive licenses.
