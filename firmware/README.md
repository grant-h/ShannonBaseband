# Shannon Firmware
Shannon baseband firmware can be found in Samsung factory firmware images or on Android devices directly within the RADIO partition (root required). We have included a link to some public firmware to avoid the long download times of some firmware repositories (*for research purposes only*).

## Extracted Data

There is a lot of interesting data in Shannon modem images. Spending time extracting it and making it into C structs or enums for import in GHIDRA is well worth your time. Here are some random things we extracted using ad hoc scripts:

* IRQ names
* AT command list
* ATI task queue message IDs to names
* RTOS queue names 

See [`extdata/G973FXXU3ASG8/`](extdata/G973FXXU3ASG8/) for the files for this specific firmware image (SM-G973F - Samsung S10, 2019-07-01).

## Firmware Samples

* Mirror 1: GitHub - https://github.com/grant-h/ShannonFirmware
* Mirror 2: Mega - https://mega.nz/file/z9Q3FKzI#OopljcMAJgckEK1m09w4lPgrhjUfoNkiFy62ynqdSHg (382MB, ZIP, 19 images)

Contents:
```
CP_G930FXXU3ERHC_CL878338_QB10643129_SIGNED.tar.md5
CP_G930W8VLU2BQH1_CL12046623_QB14540952_REV00_user_low_ship.tar.md5
CP_G935FXXU1DPLT_CL10273029_QB12087657_REV00_user_low_ship.tar.md5
CP_G935FXXU1DQE7_CL514081_QB6495812_SIGNED.tar.md5
CP_G935FXXU1DQER_CL514081_QB6561685_SIGNED.tar.md5
CP_G950FXXU1AQG5_CP6916881_CL11814589_QB14182663_REV00_user_low_ship.tar.md5
CP_G950FXXU1AQI7_CP7556320_CL12291751_QB15039738_REV00_user_low_ship.tar.md5
CP_G950NKOU1AQG7_CP6957753_CL11814589_QB14236284_REV00_user_low_ship.tar.md5
CP_G950NKOU1AQG8_CP7101662_CL11814589_QB14448033_REV00_user_low_ship.tar.md5
CP_G955FXXU1AQDG_CP6321788_CL11168760_QB13362118_REV00_user_low_ship.tar.md5
CP_G955FXXU1AQG5_CP6916883_CL11814589_QB14182672_REV00_user_low_ship.tar.md5
CP_G955NKOU1AQG7_CP6956744_CL11814589_QB14234409_REV00_user_low_ship.tar.md5
CP_G955NKOU1AQG8_CP7102173_CL11814589_QB14448914_REV00_user_low_ship.tar.md5
CP_G960FXXU1ARCC_CP9270665_CL13138374_QB17445640_REV01_user_low_ship.tar.md5
CP_G960FXXU1ARCD_CL717541_QB9295882_SIGNED.tar.md5
CP_G960FXXU7DTA3_CP14809213_CL17633310_QB28374072_REV01_user_low_ship.tar.md5
CP_G973FXXS5CTD1_CP15661447_CL18242812_QB30535823_REV01_user_low_ship.tar.md5
CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar.md5
CP_G988BXXU1ATCH_CP15392364_CL18186339_QB29827627_REV01_user_low_ship_MULTI_CERT.tar.md5
```
