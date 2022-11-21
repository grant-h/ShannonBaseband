## ShannonLoader

A GHIDRA loader for Samsung's "Shannon" modem binaries. These modem binaries can be found in Samsung factory firmware images within tar files like `CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar.md5`.
Extract this tar file into its two components, `modem.bin` and `modem_debug.bin`. Load `modem.bin` using GHIDRA after installing this extension. Modem files may be compressed using lz4 - be sure to decompress them using `lz4 -d modem.bin.lz4` before loading. Some older Cortex-R modem images (<2014) have only modem.bin.

## Baseband Support

* TOC Header parsing and sectioning
* SoC version detection

### Cortex-R SoC (Pre-5G basebands)
* Image-agnostic MPU table extraction for an accurate memory map
* Image-agnostic boot time relocation table processing (for a more accurate static modem image)

### Cortex-A SoC (5G and above basebands)
* Only basic TOC extraction support at the moment
* Roadmap: MMU map recovery

## Building and Testing
- Ensure you have ``JAVA_HOME`` set to the path of your JDK 17 installation (the default).
- Set ``GHIDRA_INSTALL_DIR`` to your Ghidra install directory. This can be done in one of the following ways:
    - **Windows**: Running ``set GHIDRA_INSTALL_DIR=<Absolute path to Ghidra without quotations>``
    - **macos/Linux**: Running ``export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra>``
    - Using ``-PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>`` when running ``./gradlew``
    - Adding ``GHIDRA_INSTALL_DIR`` to your Windows environment variables.
- Run ``./gradlew``
- You'll find the output zip file inside `./dist`

To build, install, and test all at once on Linux, use the [`./scripts/workflow.sh`](./scripts/workflow.sh). For example:

```
GHIDRA_INSTALL_DIR=<Absolute path to Ghidra> ./scripts/workflow.sh <path to modem.bin> <path to existing or temporary ghidra project directory>
```

Note that your modem can deeply nested via compression or tar archives and this script will still work. You can pass a directory of modem files to try as well.

## Installation
- Start Ghidra and use the "Install Extensions" dialog (``File -> Install Extensions...``).
- Press the ``+`` button in the upper right corner.
- Select the zip file in the file browser, then restart Ghidra.
