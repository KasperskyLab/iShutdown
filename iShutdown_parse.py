# © 2023 AO Kaspersky Lab. All Rights Reserved.
# Extracts and parses Shutdown.log forensic artifact

import tarfile
import hashlib
import os
import csv
import re
from datetime import datetime
import argparse
import shutil
import tempfile


def extract_log(tar_path, output_path):
    temp_dir = os.path.join(tempfile.gettempdir(), "shutdown_log_extraction")

    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    with tarfile.open(tar_path, 'r:gz') as archive:
        for member in archive.getmembers():
            if 'shutdown.log' in member.name:
                member.name = os.path.basename(member.name)  # Rename file to avoid long path
                archive.extract(member, path=temp_dir)
                log_path = os.path.join(temp_dir, member.name)
                shutil.copy(log_path, output_path)
                return os.path.join(output_path, os.path.basename(member.name))

    raise Exception("The specific log file was not found in the archive.")


def get_file_hashes(file_path):
    hasher_md5 = hashlib.md5()
    hasher_sha1 = hashlib.sha1()
    hasher_sha256 = hashlib.sha256()

    with open(file_path, 'rb') as file:
        buf = file.read()
        hasher_md5.update(buf)
        hasher_sha1.update(buf)
        hasher_sha256.update(buf)

    return hasher_md5.hexdigest(), hasher_sha1.hexdigest(), hasher_sha256.hexdigest()


def parse_log(log_path, output_path):
    with open(log_path, 'r') as log_file:
        log_content = log_file.readlines()

    csv_path = os.path.join(output_path, 'parsed_shutdown.csv')
    with open(csv_path, 'w', newline='') as csvfile:
        log_md5, log_sha1, log_sha256 = get_file_hashes(log_path)
        csvfile.write(f"Log MD5: {log_md5}\n")
        csvfile.write(f"Log SHA1: {log_sha1}\n")
        csvfile.write(f"Log SHA256: {log_sha256}\n")
        csvfile.write(
            "Parsing Completion: "
            f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        )

        fieldnames = ['entry number', 'reboot time', 'client pid', 'path']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        entry_num = 1
        entries = []
        for line in log_content:
            pid_match = re.search(r'remaining client pid: (\d+) \((.*?)\)', line)
            if pid_match:
                pid, path = pid_match.groups()
                entries.append((pid, path))

            sigterm_match = re.search(r'SIGTERM: \[(\d+)\]', line)
            if sigterm_match:
                timestamp = int(sigterm_match.group(1))
                reboot_time = datetime.utcfromtimestamp(timestamp).strftime(
                    '%Y-%m-%d %H:%M:%S UTC'
                )
                for pid, path in entries:
                    writer.writerow({
                        'entry number': entry_num,
                        'reboot time': reboot_time,
                        'client pid': pid,
                        'path': path
                    })
                    entry_num += 1
                entries = []


def main():
    parser = argparse.ArgumentParser(
        description=(
            'A tool to extract and parse iOS shutdown logs from a .tar.gz archive. '
            'Expected output is a csv file, summary file, and the log file.'
        )
    )
    parser.add_argument(
        '-e', '--extract',
        help='Path to the .tar.gz archive for extracting shutdown.log file.',
        required=True
    )
    parser.add_argument(
        '-p', '--parse',
        action='store_true',
        help='Flag to indicate if the extracted log should be parsed.',
        required=False
    )
    parser.add_argument(
        '-o', '--output',
        help='Path to save the output.',
        default=".",
        required=False
    )

    args = parser.parse_args()

    print("Starting extraction process...")
    log_path = extract_log(args.extract, args.output)
    print(f"File extracted to {log_path}.")

    _, log_sha1, _ = get_file_hashes(log_path)
    renamed_path = os.path.join(args.output, f"{log_sha1}.log")
    os.rename(log_path, renamed_path)

    md5, sha1, sha256 = get_file_hashes(args.extract)
    summary_path = os.path.join(args.output, 'extraction_summary.txt')
    with open(summary_path, 'w') as summary_file:
        summary_file.write(
            "Extraction Completion: "
            f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        )
        summary_file.write(f'Original Archive: {args.extract}\n')
        summary_file.write(f'File Size: {os.path.getsize(args.extract)} bytes\n')
        summary_file.write(f'MD5: {md5}\n')
        summary_file.write(f'SHA1: {sha1}\n')
        summary_file.write(f'SHA256: {sha256}\n\n')

        summary_file.write(f'Extracted Log (Renamed to SHA1 hash): {renamed_path}\n')
        summary_file.write(f'File Size: {os.path.getsize(renamed_path)} bytes\n')
        log_md5, log_sha1, log_sha256 = get_file_hashes(renamed_path)
        summary_file.write(f'MD5: {log_md5}\n')
        summary_file.write(f'SHA1: {log_sha1}\n')
        summary_file.write(f'SHA256: {log_sha256}\n')

    if args.parse:
        print("Starting parsing process...")
        parse_log(renamed_path, args.output)
        print("Parsing completed.")


if __name__ == '__main__':
    main()

