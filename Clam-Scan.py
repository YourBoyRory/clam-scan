#!/usr/bin/env python3

import subprocess
import shutil
import pwd
import os
from datetime import date, datetime

class ClamScan:

    config = {}

    def __init__(self, config = {}):
        self.config = config

    def quarantine(self, filePath, quarantine_config = None):
        if quarantine_config == None:
            quarantine_config = self.config.get("quarantine_config", {})

        quarantine_config.get("quarantine_config", {})


    def scanNow(self, scan_config = None):
        if scan_config == None:
            scan_config = self.config.get("scan_config", {})

        # Get clamscan EXE
        cmd = [scan_config.get("clam_exe", "/usr/bin/clamdscan")]
        # get custom options
        cmd += ["--fdpass", "--multiscan"]
        cmd += scan_config.get("clamscan_options", [])

        # This mess is to set Log paths
        scan_name = scan_config.get(
            "scan_name", "last"
        ).lower()
        if scan_name != "last": default_log = scan_name+"_scan.log"
        else: default_log = "scan.log"
        log_path = str(os.path.expanduser(
            scan_config.get(
                "log_path", f"~/.local/state/clamav/logs/{default_log}"
            ).replace("{date}", str(date.today()))
        ))
        scan_config['log_path'] = log_path
        virus_report = str(os.path.expanduser(
            scan_config.get(
                "virus_report", os.path.dirname(log_path)+"/virus_report.{date}.log"
            ).replace("{date}", str(date.today()))
        ))
        scan_config['virus_report'] = virus_report
        if log_path != "" and virus_report != "":
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            cmd += ["--log="+log_path]
        else:
            raise ValueError("Log paths must not be empty")

        # Get directories
        dirs = scan_config.get(
            "scan_directories", ["~/test"]
        )
        cmd += [os.path.expanduser(d) for d in dirs]

        # Start Scan
        self.scan_config = scan_config
        scan_results = {}
        error_messages = ""

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
                    scan_results['infected_count'] = int(line.split(':')[1].strip())
                except Exception as e:
                    error_messages += f"{e}"

        for line in process.stderr:
            print(line, end="")
            error_messages += f"{line}"

        scan_results['exit_code'] = process.wait()
        scan_results['scan_name'] = scan_name
        if error_messages != "":
            scan_results['error_messages'] = error_messages

        self.__process_results(scan_config, scan_results)

    def __process_results(self, scan_config, scan_results):

        # Get log paths
        log_path = scan_config['log_path']
        virus_report = scan_config['virus_report']
        results_path = log_path

        # Get results
        scan_name = scan_results.get("scan_name", "last").lower()
        exit_code = scan_results.get("exit_code", -1)
        error_messages = scan_results.get("error_messages", "An unknown error has occured.")
        infected_count = scan_results.get("infected_count", -1)
        if infected_count == 1: infected_text = f"{infected_count} infection"
        elif infected_count < 0: infected_text = f"infection(s)"
        else: infected_text = f"{infected_count} infections"

        # Get Notification config
        notification_config = {}
        notification_config['env'] = scan_config.get("notification_config", {})
        notify_clean = notification_config['env'].get(
            "notify_clean", True
        )

        if exit_code == 1:
            notification_config['enable_notify'] = True
            notification_config['notification_switches'] = ['--icon=security-low', '--urgency=critical']
            notification_config['notification_title'] = "Possible Infection Detected!"
            notification_config['notification_message'] =  f"{scan_name.title()} scan found {infected_text}. "
            try:
                self.__copy_latest_log(log_path, virus_report)
                notification_config['notification_switches'] += ['-A', 'View Virus Report']
                results_path = virus_report
            except Exception as e:
                notification_config['notification_switches'] += ['-A', 'View Results']
                notification_config['notification_message'] += f"\nCan't write virus report: {e}. You can View Results instead."
        elif exit_code == 0 or infected_count == 0:
            notification_config['enable_notify'] = notify_clean
            notification_config['notification_switches'] = ['--icon=security-high', '-A', 'View Results']
            notification_config['notification_title'] = f"{scan_name.title()} scan found no infections."
            if exit_code != 0: notification_config['notification_message'] = f"Something went wrong with the {scan_name} scan. \n{error_messages}"
            else: notification_config['notification_message'] = f"Nothing to report from {scan_name} scan."
        else:
            notification_config['enable_notify'] = True
            notification_config['notification_switches'] = ['--icon=security-medium','--urgency=critical', '-A', 'View Results']
            notification_config['notification_title'] = f"Something went wrong with the {scan_name} scan."
            notification_config['notification_message'] = f"{error_messages}"

        print("\n\n"+notification_config['notification_title'])
        print(notification_config['notification_message'])
        print(f"See {results_path} for scan results.")
        if notification_config['enable_notify']:
            result = self.__sendNotification(notification_config)
            if result.stdout == b"0\n":
                subprocess.run(['xdg-open', results_path])

    def __sendNotification(self, notification_config = {}):



        # Notification Display
        title = notification_config.get("notification_title", "")
        message = notification_config.get("notification_message", "")
        switches = notification_config.get("notification_switches", "")

         # Notification Env
        notification_env = notification_config.get("env",{})
        default_display = notification_env.get("default_display", ":0")
        username = notification_env.get("notify_user", None)
        notify_send_exe = notification_env.get("notify_send_exe", "/usr/bin/notify-send")
        if not isinstance(notify_send_exe, list):
            notify_send_exe = [notify_send_exe]

        defaults = notify_send_exe + switches + ['--app-icon=clamav', '-a', 'ClamAV', f"{title}", f"{message}"]

        try:
            if username == None:
                base_path = "/run/user"
                for entry in os.listdir(base_path):
                    full_path = os.path.join(base_path, entry)
                    dbus_address = f"unix:path={full_path}/bus"
                    if entry.isdigit() and os.path.isdir(full_path):
                        uid = int(entry)
                        username = pwd.getpwuid(uid).pw_name
                        env = [
                            "sudo",
                            "-u",
                            username,
                            f"DISPLAY={default_display}",
                            f"DBUS_SESSION_BUS_ADDRESS={dbus_address}",
                        ]
                        result = subprocess.run(env + defaults, capture_output=True)
                        if result.returncode == 0:
                            print(f"Successfuly notified user: {username}:{uid}")
                            return result
                if result.returncode == None:
                    print("No users found to notify.")
                    return subprocess.run(defaults, capture_output=True)
            else:
                # User was Provided
                uid = pwd.getpwnam(username).pw_uid
                dbus_address = f"unix:path=/run/user/{uid}/bus"
                env = [
                    "sudo",
                    "-u",
                    username,
                    f"DISPLAY={default_display}",
                    f"DBUS_SESSION_BUS_ADDRESS={dbus_address}",
                ]
                result = subprocess.run(env + defaults, capture_output=True)
                if result.returncode == 0:
                    print(f"Successfuly forced notification to: {username}:{uid}")
                    return result
                else:
                    print(f"{username}:{uid} not found to notify.")
                    return subprocess.run(defaults, capture_output=True)
        except Exception as e:
            # If we cant find a currently logged in user, just attempt to send it without a env..
            print("Failed to invoke env:", e)
            return subprocess.run(defaults, capture_output=True)


    def __copy_latest_log(self, log_path, virus_report, marker=None):

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

    clamScan = ClamScan()
    clamScan.scanNow(scan_config)


