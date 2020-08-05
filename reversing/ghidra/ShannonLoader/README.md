## ShannonLoader

A GHIDRA loader for Samsung's ``Shannon'' modem binaries. These modem binaries can be found in Samsung factory firmware images within tar files like `CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar.md5`. Extract this tar file into its two components, `modem.bin` and `modem_debug.bin`. Load `modem.bin` using GHIDRA after installing this extension.

## Notable Features
* Image-agnostic run-time copy table processing (for a more accurate static modem image)
* Image-agnostic MPU table extraction for an accurate memory map

## Building
- Ensure you have ``JAVA_HOME`` set to the path of your JDK 11 installation (the default).
- Set ``GHIDRA_INSTALL_DIR`` to your Ghidra install directory. This can be done in one of the following ways:
    - **Windows**: Running ``set GHIDRA_INSTALL_DIR=<Absolute path to Ghidra without quotations>``
    - **macos/Linux**: Running ``export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra>``
    - Using ``-PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>`` when running ``./gradlew``
    - Adding ``GHIDRA_INSTALL_DIR`` to your Windows environment variables.
- Run ``./gradlew``
- You'll find the output zip file inside `./dist`

## Installation
- Start Ghidra and use the "Install Extensions" dialog (``File -> Install Extensions...``).
- Press the ``+`` button in the upper right corner.
- Select the zip file in the file browser, then restart Ghidra.
