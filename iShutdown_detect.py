# © 2023 AO Kaspersky Lab. All Rights Reserved.
# Checks Sysdiagnose archives for traces of possible iOS infections using malware such as Pegasus

import os
import sys
import re
import tarfile
from datetime import datetime


def count_occurrences(content, target_phrase):
    return content.count(target_phrase)


def print_colored(text, color):
    if color == 'red':
        print("\033[91m {}\033[00m" .format(text))
    elif color == 'yellow':
        print("\033[93m {}\033[00m" .format(text))
    elif color == 'green':
        print("\033[92m {}\033[00m" .format(text))
    else:
        print(text)


def find_anomalies_before_sigterm(content, anomaly_phrase, threshold=3):
    sigterm_pattern = re.compile(r'SIGTERM: \[(\d+)\]')
    content_lines = content.splitlines()

    anomalies_timestamps = []
    anomaly_count = 0

    for line in content_lines:
        if anomaly_phrase in line:
            anomaly_count += 1
        elif sigterm_match := sigterm_pattern.search(line):
            if anomaly_count >= threshold:
                unix_timestamp = int(sigterm_match.group(1))
                anomalies_timestamps.append(datetime.utcfromtimestamp(unix_timestamp))
            anomaly_count = 0

    return anomalies_timestamps


def process_hits(content, hit_phrase):
    count = 0
    decoded_dates = []
    values = []
    sigterm_pattern = re.compile(r'SIGTERM: \[(\d+)\]')
    found_hit = False
    last_decoded_date = None

    for line in content.splitlines():
        if hit_phrase in line:
            count += 1
            found_hit = True
            value = line.split(hit_phrase, 1)[1].strip()
            values.append(value)
        match = sigterm_pattern.search(line)
        if match:
            unix_timestamp = int(match.group(1))
            date = datetime.utcfromtimestamp(unix_timestamp)
            if found_hit:
                decoded_dates.append(date.strftime('%Y-%m-%d %H:%M:%S UTC'))
            found_hit = False
            last_decoded_date = date.strftime('%Y-%m-%d %H:%M:%S UTC')

    return count, decoded_dates, values, last_decoded_date


def extract_target_file_contents(tar_file_path, target_file_name):
    with tarfile.open(tar_file_path, 'r:gz') as tar:
        for member in tar.getmembers():
            if member.name.endswith(target_file_name):
                with tar.extractfile(member) as target_file:
                    return target_file.read().decode('utf-8')


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("##############################################################################")
        print("## Usage: python3 iShutdown_detect.py /path/to/your/sysdiagnose_file.tar.gz ##")
        print("##############################################################################")
        sys.exit(1)

    tar_file_path = sys.argv[1]
    target_file_name = "shutdown.log"

    if os.path.isfile(tar_file_path):
        target_file_contents = extract_target_file_contents(
            tar_file_path, target_file_name
        )
        if target_file_contents:
            occurrences = count_occurrences(target_file_contents, "SIGTERM")
            print_colored(
                f"+++ Detected {occurrences} reboot(s). Good practice to follow.", 'green'
            )

            # Find delay anomalies before SIGTERM reboot
            anomaly_phrase = "these clients are still here"
            anomalies_timestamps = find_anomalies_before_sigterm(target_file_contents, anomaly_phrase)

            if anomalies_timestamps:
                print_colored(f"*** Detected {len(anomalies_timestamps)} reboot(s) with 3 or more delays before a reboot.", 'red')
                for timestamp in anomalies_timestamps:
                    print_colored(timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'), 'yellow')
            else:
                print_colored("+++ No anomalies detected with the specified conditions.", 'green')

            # Find entries in common malware path
            # List of paths to check
            paths_to_check = ["/private/var/db/", "/private/var/tmp/"]

            # Loop through each path and process hits
            for path in paths_to_check:
                hit_count, decoded_dates, values, last_decoded_date = process_hits(target_file_contents, path)

                if hit_count > 0:
                    print_colored(
                        f"*** Suspicious processes in '{path}' occurred {hit_count} time(s). Further investigation needed!", 'red'
                    )
                    print_colored("*** The suspicious processes are:\n" + '\n'.join(values), 'red')
                    print_colored("*** Detected during reboot(s) on:\n" + '\n'.join(decoded_dates), 'yellow')
                elif last_decoded_date:
                    print_colored(f"+++ No suspicious processes detected in '{path}'. Last reboot was on: {last_decoded_date}", 'green')

        else:
            print(f"Target file '{target_file_name}' not found in the archive.")
    else:
        print(f"File not found: {tar_file_path}")

