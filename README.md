# Step 1 - convert ASIC to SN2410M
Connect on switch, enable _shell command with license:
enable
configure terminal
license install LK2-RESTRICTED_CMDS_GEN2-88A1-NEWD-BPNB-1
configuration write
exit
_shell
[admin@switch-70563e ~]# cd /opt/tms/bin/

Here we will find fw-SPC-rel-13_2008_3318-FIT.mfa, which we need to copy to our python Machine. For example via SCP.

Afterwards we need to use a script (Use https://raw.githubusercontent.com/BeTeP-STH/mft-scripts/refs/heads/master/mfa_extract.py)

python3 mfa_extract.py fw-SPC-rel-13_2008_3226-FIT.mfa HPE0000000011 # this is the firmware for SN2410M

When extracted you need to SCP the new firmware to the switch. On the Switch Shell you need to burn it.

flint -d 03:00.0 -i HPE0000000011.bin -allow_psid_change burn

# Step 2 - get an EEPROM dump
dd if=/sys/bus/i2c/devices/8-0051/eeprom of=eeprom_dump.bin bs=1k

SCP it again to a python enabled machine.

# Step 3 - generate ONIE commands for generating the correct EEPROM
python .\fixeeprom.py c:\Users\julian\Documents\fru_backup.bin --disable-license

Afterwards reboot the switch to ONIE.

# Step 3 - erase EEPROM with onie
onie-syseeprom -e

# Step 4 - create new eeprom with output from Python script

# Step 5 - reinstall ONYX. Profit.
