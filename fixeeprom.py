import argparse
import sys

TLV_CODES = {
    0x21: "Product Name",
    0x22: "Part Number", 
    0x23: "Serial Number",
    0x24: "Base MAC Address",
    0x25: "Manufacture Date",
    0x26: "Device Version",
    0x27: "Label Revision",
    0x28: "Platform Name",
    0x29: "ONIE Version",
    0x2A: "MAC Addresses",
    0x2B: "Manufacturer",
    0x2C: "Country Code",
    0x2D: "Vendor Name",
    0x2E: "Diag Version",
    0x2F: "Service Tag",
    0xFD: "Vendor Extension",
    0xFE: "CRC-32"
}

LICENSE_PATTERN = bytes.fromhex('000081190046000207ae000031023800')
DISABLED_LICENSE = bytes.fromhex('0000811900 0E0002078100003000380000000000000000')

def check_for_license(data):
    return LICENSE_PATTERN in data

def decode_vendor_extension(value):
    if len(value) < 3:
        return "Invalid vendor extension"
    vendor_id = int.from_bytes(value[0:2], 'big')
    data = value[2:]
    
    # Create hex representation
    hex_str = ' '.join([f'{b:02x}' for b in data])
    
    # Create ASCII representation (printable chars only)
    ascii_str = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in data])
    
    return {
        'vendor_id': vendor_id,
        'hex': hex_str,
        'ascii': ascii_str,
        'raw': data.hex()
    }

def read_hex_file(filename):
    try:
        with open(filename, 'rb') as f:
            content = f.read()
        # Convert binary to hex string
        return ''.join([f'{b:02x}' for b in content])
    except FileNotFoundError:
        print(f"Error: File {filename} not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {str(e)}")
        sys.exit(1)

def parse_tlv(hex_data, disable_license=False):
    # Convert hex string to bytes
    data = bytes.fromhex(hex_data)
    pos = 0
    tlv_data = {}  # Store TLV entries for ONIE command generation
    vendor_extensions = []  # List to store all vendor extensions
    
    # Verify TlvInfo header
    if data[0:7].decode() != "TlvInfo":
        return "Invalid TLV header"
        
    print("Header:", data[0:7].decode())
    print("Version:", data[7:9].hex())
    total_len = int.from_bytes(data[9:11], 'big')
    print(f"Total Length: {total_len}")
    pos = 11  # Start after header, version and length

    if disable_license and check_for_license(data):
        print("\nLicense protection detected - will generate command to disable it")

    while pos < len(data):
        if pos + 2 > len(data):
            break
            
        type_code = data[pos]
        length = data[pos + 1]
        
        if pos + 2 + length > len(data):
            break
            
        value = data[pos + 2:pos + 2 + length]
        
        if type_code in TLV_CODES:
            name = TLV_CODES[type_code]
            try:
                print(f"\nType: {hex(type_code)} ({name})")
                print(f"Length: {length}")
                
                # Store the value for ONIE command generation
                if type_code == 0x24:  # MAC Address
                    tlv_data[type_code] = ':'.join([f'{x:02x}' for x in value])
                elif type_code == 0x25:  # Date
                    tlv_data[type_code] = value.decode()
                elif type_code == 0x26:  # Device Version
                    tlv_data[type_code] = value.hex()
                    print(f"Value (hex): {value.hex()}")
                elif type_code == 0x28:  # Platform Name
                    decoded = value.decode('ascii', errors='ignore').strip('\x00')
                    if '!' in decoded:
                        decoded = decoded.split('!')[0]
                    tlv_data[type_code] = decoded.strip()
                elif type_code == 0x2A:  # MAC Addresses
                    num_macs = int.from_bytes(value, 'big')
                    tlv_data[type_code] = str(num_macs)
                    print(f"Value: {num_macs} (hex: {value.hex()})")
                elif type_code == 0xFD:  # Vendor Extension
                    vendor_ext = decode_vendor_extension(value)
                    vendor_extensions.append(vendor_ext)
                    print(f"Value:")
                    print(f"  Vendor ID: {vendor_ext['vendor_id']:04x}")
                    print(f"  Hex: {vendor_ext['hex']}")
                    print(f"  ASCII: {vendor_ext['ascii']}")
                elif type_code == 0xFE:
                    tlv_data[type_code] = value.hex()
                else:
                    decoded = value.decode('ascii', errors='ignore').rstrip('\x00')
                    if decoded:
                        tlv_data[type_code] = decoded
                    else:
                        tlv_data[type_code] = value.hex()
                
                # Print values as before
                if type_code != 0xFD:  # We already printed vendor extensions
                    print(f"Value: {tlv_data[type_code]}")
                    
            except Exception as e:
                print(f"Value (hex): {value.hex()}")
                print(f"Decode error: {str(e)}")
                
        pos += 2 + length
    
    # Generate ONIE commands
    print("\nONIE-compatible commands:")
    for type_code, value in tlv_data.items():
        if type_code == 0xFE:  # Skip only CRC
            continue
        print(f"onie-syseeprom -s 0x{type_code:02x}=\"{value}\"")
            
    # Print all vendor extensions in hex byte format
    for vendor_ext in vendor_extensions:
        vendor_bytes = vendor_ext['vendor_id'].to_bytes(2, 'big')
        data_bytes = bytes.fromhex(vendor_ext['raw'])
        full_data = vendor_bytes + data_bytes
        
        # Check if this is the license vendor extension
        if disable_license and LICENSE_PATTERN in full_data:
            hex_str = ' '.join([f'0x{b:02x}' for b in DISABLED_LICENSE])
            print(f'# Original license data replaced with disabled version')
        else:
            hex_str = ' '.join([f'0x{b:02x}' for b in full_data])
            
        print(f'onie-syseeprom -s 0xfd="{hex_str}"')

def main():
    parser = argparse.ArgumentParser(description='Parse TLV EEPROM data from file')
    parser.add_argument('filename', help='File containing hex dump of EEPROM')
    parser.add_argument('--disable-license', action='store_true', 
                      help='Disable license protection if detected')
    args = parser.parse_args()
    
    hex_data = read_hex_file(args.filename)
    parse_tlv(hex_data, args.disable_license)

if __name__ == "__main__":
    main()
