#!/bin/bash

sudo cp ./Clam-Scan.py /usr/local/bin/auto-clamscan
sudo chmod 755 /usr/local/bin/auto-clamscan
sudo cp ./config.json /root/auto-clamscan-config.json
sudo chmod 600 /root/auto-clamscan-config.json

echo "Install Done!"
echo "Add the following line to roots crontab:"
echo "0 0 * * 0 /usr/local/bin/auto-clamscan --config=/root/auto-clamscan-config.json"
