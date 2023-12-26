# © 2023 AO Kaspersky Lab. All Rights Reserved.
# Creates reboot statistics from Shutdown.log forensic artifact

import re
import collections
import argparse
from datetime import datetime

# Create an argument parser for command-line execution
parser = argparse.ArgumentParser(
    description="Process an iOS shutdown.log file to create stats on reboots."
)
parser.add_argument(
    "logfile", help="The path to the log file to be analyzed."
)
args = parser.parse_args()

# Initialize counters and storage
sigterm_count = 0
first_sigterm_time = None
last_sigterm_time = None
sigterm_per_month = collections.defaultdict(int)

# Process the log file
with open(args.logfile, 'r') as file:
    for line in file:
        match = re.search(r'SIGTERM: \[(\d+)\]', line)
        if match:
            sigterm_count += 1
            timestamp = int(match.group(1))
            timestamp = datetime.fromtimestamp(timestamp)

            if first_sigterm_time is None or timestamp < first_sigterm_time:
                first_sigterm_time = timestamp
            if last_sigterm_time is None or timestamp > last_sigterm_time:
                last_sigterm_time = timestamp

            month_key = '{year}-{month:02}'.format(
                year=timestamp.year, month=timestamp.month
            )
            sigterm_per_month[month_key] += 1

# Output the results
print("======================================================")
print(f"Number of reboots in the log: {sigterm_count}")
if first_sigterm_time:
    print(f"First reboot detected in the log: {first_sigterm_time}")
if last_sigterm_time:
    print(f"Last reboot detected in the log: {last_sigterm_time}")
print("======================================================")
print("Reboots counts per month:")
for month, count in sorted(sigterm_per_month.items()):
    print(f"{month}: {count}")

