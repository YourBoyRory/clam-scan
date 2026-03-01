#!/bin/bash

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

echo "Install Done!"
echo "Add the following line to roots crontab:"
echo "0 0 * * 0 /usr/local/bin/auto-clamscan --config=/root/auto-clamscan-config.json"
