#!/usr/bin/env python3

import subprocess
import shutil
import os
from datetime import date, datetime

class ClamScan:
    def __init__(self, scan_config = {}):

        # Get clamscan EXE
        clam_exe = scan_config.get(
            "clam_exe", "/usr/bin/clamscan"
        )
        cmd = [clam_exe]

        notify_send_exe = scan_config.get(
            "notify_send_exe", "/usr/bin/notify-send"
        )
        if not isinstance(notify_send_exe, list):
            notify_send_exe = [notify_send_exe]

        # If set, then you will be notifed when the scan is clean
        notify_clean = scan_config.get(
            "notify_clean", False
        )

        # If set, then it will make sure anothing scan isnt in progress
        check_already_scanning = scan_config.get(
            "check_already_scanning", True
        )

        # Scan occuance, This does nothing other then change the word used in the nofication.
        scan_occurnace = scan_config.get(
            "scan_occurnace", "last"
        ).lower()

        # Get directories
        dirs = scan_config.get(
            "scan_directories", ["~/"]
        )
        scan_directories = [os.path.expanduser(d) for d in dirs]
        if scan_directories != []:
            cmd += (['-r'] + scan_directories)
        dirs = scan_config.get(
            "exclude_directories", []
        )
        exclude_directories = [os.path.expanduser(d) for d in dirs]
        for directories in exclude_directories:
            cmd += (['--exclude-dir='+directories])
        files = scan_config.get(
            "ignore_files", []
        )
        ignore_files = [os.path.expanduser(f) for f in files]
        for file in ignore_files:
            cmd += (['--exclude='+file])

        # get custom options
        clamscan_option = scan_config.get(
            "clamscan_option", []
        )
        cmd += clamscan_option

        # Set Log paths
        log_path =  str(os.path.expanduser(
            scan_config.get(
                "log_path", "~/.local/state/clamav/logs/scan.log"
            ).replace("{date}", str(date.today()))
        ))
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        if log_path != "":
            cmd += ["--log="+log_path]
        virus_report = str(os.path.expanduser(
            scan_config.get(
                "virus_report", os.path.dirname(log_path)+"/virus_report.{date}.log"
            ).replace("{date}", str(date.today()))
        ))
        infected_count = -1
        error_message = ""

        print(cmd)

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )


        for line in process.stdout:
            print(line, end="")
            if "Infected files:" in line:
                try:
                    infected_count = int(line.split(':')[1])
                except Exception as e:
                    error_message += f"Issue getting infected count: {e}\n"
                    pass
        for line in process.stderr:
            error_message += f"{line}"

        process.wait()

        no_log_warn="No log stored."
        switches = ['--app-icon=clamav']
        if infected_count > 0:
            switches += ['--icon=security-low', '--urgency=critical']
            title = "Possible Infection Detected!"
            message =  f"{scan_occurnace.title()} scan found {infected_count} infections."
            if log_path != "" and virus_report != "":
                try:
                    self.copy_latest_log(log_path, virus_report)
                    log_message = f" See {virus_report} for virus report."
                    switches += ['-A', 'View Virus Report']
                    notify = (True, virus_report)
                except Exception as e:
                    message += f"\nCan't write virus report: {e}. You can View Results instead."
                    log_message = f"See {log_path} for scan results."
                    switches += ['-A', 'View Results']
                    notify = (True, None)
            else:
                notify = (True, None)
                log_message = no_log_warn
                message += no_log_warn + " Enable logging to save virus report."
        elif infected_count == 0:
            switches += ['--icon=security-high', '-e']
            title = f"{scan_occurnace.title()} scan found no infections."
            message = f"Nothing to report from {scan_occurnace} scan."
            if log_path != "":
                switches += ['-A', 'View Results']
                log_message = f"See {log_path} for scan results."
                notify = (notify_clean, log_path)
            else:
                log_message = no_log_warn
                notify = (notify_clean, None)
        else:
            switches += ['--icon=security-medium','--urgency=critical']
            title = f"Something went wrong with the {scan_occurnace} scan."
            if log_path != "":
                switches += ['-A', 'View Results']
                message = error_message
                log_message = f"See {log_path} for more info"
                notify = (True, log_path)
            else:
                log_message = no_log_warn
                message = no_log_warn + " Enable logging to learn more."
                notify = (True, None)


        print("\n\n"+title)
        print(message, log_message)
        if notify[0]:
            result = self.__sendNotification(notify_send_exe, title, message, switches)
            if result.stdout == b"0\n":
                subprocess.run(['xdg-open', notify[1]])

    def __sendNotification(self, notify_send_exe, title, message, switches=[]):
        return subprocess.run(notify_send_exe + switches + ['-a', 'ClamAV', f"{title}", f"{message}"], capture_output=True)


    def copy_latest_log(self, log_path, virus_report, marker=None):
        if marker == None:
            marker = "-------------------------------------------------------------------------------\n"
        last_pos = 0
        with open(log_path, "rb") as f:  # open in binary mode for exact byte positions
            while True:
                line_start_pos = f.tell()
                line = f.readline()
                if not line:
                    break
                if line == marker.encode():  # compare in bytes
                    last_pos = f.tell()  # position **after** the marker
        # Second pass: stream from last_pos to output file
        with open(log_path, "rb") as infile, open(virus_report, "ab") as outfile:
            outfile.write("\n".encode())
            outfile.write(marker.encode())
            infile.seek(last_pos)
            while True:
                chunk = infile.read(1024*1024)  # read 1MB at a time
                if not chunk:
                    break
                outfile.write(chunk)

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Scan"
    )
    parser.add_argument(
        "--config",
        nargs="?",          # Makes it optional
        default=None,
        help="Path to scan config JSON file (optional)"
    )
    args = parser.parse_args()

    if args.config:
        with open(args.config, "r", encoding="utf-8") as f:
            scan_config = json.load(f)
    else: scan_config = {}

    ClamScan(scan_config)


