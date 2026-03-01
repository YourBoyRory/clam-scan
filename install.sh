#!/usr/bin/env bash

# Install Script
sudo cp ./Clam-Scan.py /usr/local/bin/auto-clamscan
sudo chmod 755 /usr/local/bin/auto-clamscan
sudo cp ./config.json /tmp/auto-clamscan-config.json
sudo jq --arg user "$USER" --arg display "$DISPLAY" --arg dbus_address "$DBUS_SESSION_BUS_ADDRESS"  \
   '.notify_send_exe = [
      "sudo",
      "-u",
      $user,
      "DISPLAY=\($display)",
      "DBUS_SESSION_BUS_ADDRESS=\($dbus_address)",
      "/usr/bin/notify-send"
   ]' /tmp/auto-clamscan-config.json | sudo tee /root/auto-clamscan-config.json > /dev/null
sudo rm /tmp/auto-clamscan-config.json
sudo chmod 600 /root/auto-clamscan-config.json


# Install cron job
cron_line="0 2 * * 0 /usr/local/bin/auto-clamscan --config=/root/auto-clamscan-config.json"

sudo crontab -l > current_jobs.txt
current_line=$(grep "# WEEKLY_CLAMAV_AUTOSCAN" current_jobs.txt)
cron_line_fixed="$(printf '%s\n' "$cron_line" | sed 's/[][\/.^$*]/\\&/g') # WEEKLY_CLAMAV_AUTOSCAN"
current_line_fixed=$(printf '%s\n' "$current_line" | sed 's/[][\/.^$*]/\\&/g')
if [[ "$current_line_fixed" != "" ]] ; then
    sed -i "s|$current_line_fixed|$cron_line_fixed|" current_jobs.txt
else
    echo "$cron_line" >> current_jobs.txt
fi
sudo crontab current_jobs.txt
rm current_jobs.txt

echo "Install Done!"

