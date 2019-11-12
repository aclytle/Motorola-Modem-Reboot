# Motorola-Modem-Reboot
I wrote this so I could reboot my modem on a cron job without any extra hardware.
It uses the JSON flavor of the defunct HNAP protocol to signal the modem to reboot.
I've only tested it on the MB8600 model, let me know if it works on other models.

Requirements:
* Python3
* Requests

```
usage: modem_reboot.py [-h] [--host HOST] [--password PASSWORD] [--dryrun]

optional arguments:
  -h, --help           show this help message and exit
  --host HOST          Hostname or IP of your modem (Default: 192.168.100.1)
  --password PASSWORD  Admin password (Default: motorola)
  --dryrun, -d         Logs in but doesn't reboot
  ```
