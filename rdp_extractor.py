import subprocess
import re
import argparse
import requests


def parse_ntlm_info(output):
    # Define regular expressions for parsing NTLM info
    regex_target_name = re.compile(r"Target_Name:\s*(\S+)")
    regex_netbios_domain_name = re.compile(r"NetBIOS_Domain_Name:\s*(\S+)")
    regex_netbios_computer_name = re.compile(r"NetBIOS_Computer_Name:\s*(\S+)")
    regex_dns_domain_name = re.compile(r"DNS_Domain_Name:\s*(\S+)")
    regex_dns_computer_name = re.compile(r"DNS_Computer_Name:\s*(\S+)")
    regex_dns_tree_name = re.compile(r"DNS_Tree_Name:\s*(\S+)")
    regex_product_version = re.compile(r"Product_Version:\s*(\S+)")

    # Extract information using regular expressions
    target_name = regex_target_name.search(output)
    netbios_domain_name = regex_netbios_domain_name.search(output)
    netbios_computer_name = regex_netbios_computer_name.search(output)
    dns_domain_name = regex_dns_domain_name.search(output)
    dns_computer_name = regex_dns_computer_name.search(output)
    dns_tree_name = regex_dns_tree_name.search(output)
    product_version = regex_product_version.search(output)

    # Organize the extracted information
    ntlm_info = {
        "Target Name": target_name.group(1) if target_name else None,
        "NetBIOS Domain Name": netbios_domain_name.group(1) if netbios_domain_name else None,
        "NetBIOS Computer Name": netbios_computer_name.group(1) if netbios_computer_name else None,
        "DNS Domain Name": dns_domain_name.group(1) if dns_domain_name else None,
        "DNS Computer Name": dns_computer_name.group(1) if dns_computer_name else None,
        "DNS Tree Name": dns_tree_name.group(1) if dns_tree_name else None,
        "Product Version": product_version.group(1) if product_version else None,
    }

    return ntlm_info

def build_cpe(ntlm_info):
    # Build CPE based on the extracted information
    vendor = "Microsoft"  # You can adjust this based on the actual vendor
    product = "Windows"   # You can adjust this based on the actual product

    if ntlm_info["Product Version"]:
        version = ntlm_info["Product Version"]
    else:
        version = "unspecified"

    cpe = f"cpe:2.3:a:{vendor.lower()}:{product.lower()}:{version.lower()}"

    return cpe

def get_screenshot():
    pass

def scan_rdp(ip_address, port, output_file):
    try:
        # Run rdp-ntlm-info script
        result_ntlm_info = subprocess.run(
            ["nmap", "-p", str(port), "--script", "rdp-ntlm-info", ip_address],
            capture_output=True,
            text=True
        )

        # Parse NTLM info
        ntlm_info = parse_ntlm_info(result_ntlm_info.stdout)

        # Build CPE
        cpe = build_cpe(ntlm_info)

        with open(output_file, 'w') as f:
            f.write("************ RDP-NTLM-Info Results ************\n")
            f.write(f"Target Name: {ntlm_info['Target Name']}\n")
            f.write(f"NetBIOS Domain Name: {ntlm_info['NetBIOS Domain Name']}\n")
            f.write(f"NetBIOS Computer Name: {ntlm_info['NetBIOS Computer Name']}\n")
            f.write(f"DNS Domain Name: {ntlm_info['DNS Domain Name']}\n")
            f.write(f"DNS Computer Name: {ntlm_info['DNS Computer Name']}\n")
            f.write(f"DNS Tree Name: {ntlm_info['DNS Tree Name']}\n")
            f.write(f"Product Version: {ntlm_info['Product Version']}\n")
            f.write(f"CPE: {cpe}\n")

        print("RDP-NTLM-Info scan successful. Results saved to", output_file)

        # Run rdp-enum-encryption script and append to the same file
        result_enum_encryption = subprocess.run(
            ["nmap", "-p", str(port), "--script", "rdp-enum-encryption", ip_address],
            capture_output=True,
            text=True
        )

        # Parse enum-encryption info if needed

        with open(output_file, 'a') as f:
            f.write("\n\n************ RDP-Enum-Encryption Results ************\n")
            f.write(result_enum_encryption.stdout)

        print("RDP-Enum-Encryption scan successful. Results appended to", output_file)

    except Exception as e:
        print("Error:", e)

def main():
    parser = argparse.ArgumentParser(description="RDP Scanner")
    parser.add_argument("ip_address", help="IP address to scan")
    parser.add_argument("port", type=int, help="Port to scan")
    parser.add_argument("output_file", help="Output file path")

    args = parser.parse_args()

    scan_rdp(args.ip_address, args.port, args.output_file)

if __name__ == "__main__":
    main()

