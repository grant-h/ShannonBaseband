# Back Trace Log (BTL)
This file can be found within a Shannon modem after a crash or induced dump. Its format hasn't been publicly documented and was reverse engineered enough to extract out the log messages from the actual on-target modem. It could aid in understanding the actual root cause of a modem crash.

## Using `btltool.py`

We created a tool that can extract modem logs from the BTL version 1100. Its usage is as follows:

```
./btltool.py test/modem_MAIN_40010000.bin test/cpcrash_cplog_dump_umts_20200226-1624.BTL
```

We included an actual modem dump and the corresponding MAIN image to allow for extraction of the log messages.
Not all fields of the SLOG container are understood so input here / pull requests for the tool are appreciated.

## Format Diagram
Here are diagrams designed to illustrate the BTL file format.

![BTL file format diagram](img/btl-file-format.png?raw=true)
