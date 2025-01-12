# Step 1 - get an EEPROM dump
dd if=/sys/bus/i2c/devices/8-0051/eeprom of=eeprom_dump.bin bs=1k

# Step 2 - generate ONIE commands for generating the correct EEPROM
python .\fixeeprom.py c:\Users\julian\Documents\fru_backup.bin --disable-license

# Step 3 - erase EEPROM with onie
onie-syseeprom -e

# Step 4 - create new eeprom with output from Python script

# Step 5 - reinstall ONYX. Profit.
