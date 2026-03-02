import subprocess
import os
import pwd



def __sendNotification(notification_config, title,  message, switches=[]):

    default_display = notification_config.get(
        "default_display", ":0"
    )
    username = notification_config.get(
        "notify_user", None
    )
    notify_send_exe = notification_config.get(
        "notify_send_exe", "/usr/bin/notify-send"
    )
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
                        print(f"Found user to notify: {username}:{uid}")
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
                print(f"Forcing notification to: {username}:{uid}")
                return result
            else:
                print(f"{username}:{uid} not found to notify.")
                return subprocess.run(defaults, capture_output=True)
    except Exception as e:
        # If we cant find a currently logged in user, just attempt to send it without a env..
        print("Failed to invoke env:", e)
        return subprocess.run(defaults, capture_output=True)

notification_config = {
    "notify_user": "rory"
}

print(__sendNotification(notification_config, "ClamAV", "Testing").returncode)
