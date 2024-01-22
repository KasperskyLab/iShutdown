## iShutdown scripts: extracts, analyzes, and parses Shutdown.log forensic artifact from iOS Sysdiagnose archives

There are three Python3 scripts in this project, and each one has a different supporting role in analyzing a Sysdiagnose archive or Shutdown.log file. 
- iShutdown_detect.py: meant to analyze a Sysdiagnose tar archive for anomalous entries that can infer a potential malware indicator. This process does not extract the target Shutdown.log artifact, but rather the detection/analysis process happens in the background.
- iShutdown_parse.py: meant to extract the Shutdown.log artifact from a target Sysdiagnose tar archive, and parses it. The output is a CSV file containing the entries in a readable format, along with the artifact's hashes (MD5, SHA1, SHA256) and processing timestamps.
- iShutdown_stats.py: meant to extract reboot stats from a target Shutdown.log artifact. For example, first reboot, last reboot, reboots per month, etc.

For more information, please read [Securelist](https://securelist.com/shutdown-log-lightweight-ios-malware-detection-method/111734/)

Contact: [intelreports@kaspersky.com](mailto:intelreports@kaspersky.com)

## Prerequisites

The scripts relies on the following Python dependencies respectively:
- datetime, os, re, sys, tarfile, termcolor
- argparse, csv, datetime, hashlib, os, re, shutil, tarfile
- argparse, collections, datetime, re 

## Installation

The scripts can be run as-is, provided the dependencies mentioned above are installed:

```
python3 <iShutdown_script>.py 
```


## Usage

To make use of the scripts, it's essential to generate and collect a Sysdiagnose dump from a target iOS phone, you can follow [Apple's instructions](https://it-training.apple.com/tutorials/support/sup075). Once the tar archive is available on your PC, you are ready to use the scripts.

### iShutdown_detect

```
Usage: python3 iShutdown_detect.py /path/to/your/sysdiagnose_file.tar.gz
```

The script is straightforward and doesn't require much input except the target Sysdiagnose archive. It will check for anomalies we suspect they can detect potential iOS malware. For example, several delays before a reboot or a process under /private/var/db/ or /private/var/tmp/, are common anomalies across mobile malware infections we analyzed.

Example output:

```
+++ Detected 41 reboot(s). Good practice to follow.
*** Detected 29 reboot(s) with 3 or more delays before a reboot.
.......
.......
2021-mm-dd hh:mm:ss UTC
*** Suspicious processes in '/private/var/db/' occurred 4 time(s). Further 
investigation needed!
*** The suspicious processes are:
com.apple.xpc.roleaccountd.staging/mptbd/42286BD8-3758-3B85-B19F-6E1FDB2CB030)
com.apple.xpc.roleaccountd.staging/mptbd/42286BD8-3758-3B85-B19F-6E1FDB2CB030)
com.apple.xpc.roleaccountd.staging/mptbd/42286BD8-3758-3B85-B19F-6E1FDB2CB030)
com.apple.xpc.roleaccountd.staging/mptbd/42286BD8-3758-3B85-B19F-6E1FDB2CB030)
*** Detected during reboot(s) on:
2021-mm-dd hh:mm:ss UTC
+++ No suspicious processes detected in '/private/var/tmp/'. Last reboot 
was on: 2021-mm-dd hh:mm:ss UTC
```


### iShutdown_parse

```
Usage: iShutdown_parse.py [-h] -e EXTRACT [-p] [-o OUTPUT]

A tool to extract and parse iOS shutdown logs from a .tar.gz archive. Expected output is a csv file, summary file, and the log file.

optional arguments:
  -h, --help            show this help message and exit
  -e EXTRACT, --extract EXTRACT
                        Path to the .tar.gz archive for extracting shutdown.log file.
  -p, --parse           Flag to indicate if the extracted log should be parsed.
  -o OUTPUT, --output OUTPUT
                        Path to save the output.
```

This script has several objectives. First it aim at extracting the Shutdown.log file from the Sysdiagnose tar archive, then if instructed, it will parse the log file and create a CSV file containing a human readable output. The CSV output contains the decoded reboot time in UTC, the process ID seen, and the respective system path of the process. At the end of the processing, there will be an extraction summary file that contains the processing timestamps, file paths, and related hashes. 

Example output:

```
extraction_summary.txt
parsed_shutdown.csv
<shutdown.log hash>.log
```


### iShutdown_stats


```
usage: iShutdown_stats.py [-h] logfile

Process an iOS shutdown.log file to create stats on reboots.

positional arguments:
  logfile     The path to the log file to be analyzed.

optional arguments:
  -h, --help  show this help message and exit
```

This script aims at creating a telemetry file of a target iOS device's reboots. It requires the log file to be extracted using iShutdown_parse script above.

Example output:

```
======================================================
Number of reboots in the log: 40
First reboot detected in the log: yyyy-mm-dd hh:mm:ss
Last reboot detected in the log: yyyy-mm-dd hh:mm:ss
======================================================
Reboots counts per month:
yyyy-mm: 1
yyyy-mm: 3
..........
..........
yyyy-mm: 4
yyyy-mm: 10
```

## Updates: 22 January 2024

* Updated README (typos and related Securelist link)
* Fixed an issue in iShutdown_parse to handle cross-platform temp folder for extraction
* Added cross-platform compiled versions for all scripts using Pyinstaller


## To Do and Future Work

* We are aiming to introduce more heuristics for detecting unusal processes in the Shutdown.log artifact
* More research on iOS malware detection through Sysdiagnose analysis
