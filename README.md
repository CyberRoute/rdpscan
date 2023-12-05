## RDP Scanner
This Python script performs an RDP (Remote Desktop Protocol) scan on a specified IP address and port. The script utilizes the nmap tool to run two NSE (Nmap Scripting Engine) scripts: rdp-ntlm-info and rdp-enum-encryption. It then extracts relevant information, including NTLM details, and builds a Common Platform Enumeration (CPE) string. The results are saved to an output file.

##Prerequisites
Ensure that nmap is installed on your system.

## Usage
```
python rdp_extractor.py <ip_address> <port> <output_file>

```

Example Output
```
(env) alessandro@xps:~/Development/rdp$ python rdp_extractor.py 207.81.231.54 3389 rep
RDP-NTLM-Info scan successful. Results saved to rep
RDP-Enum-Encryption scan successful. Results appended to rep
(env) alessandro@xps:~/Development/rdp$ cat rep 
************ RDP-NTLM-Info Results ************
Target Name: OFFICE
NetBIOS Domain Name: OFFICE
NetBIOS Computer Name: SERVER2020-RDP
DNS Domain Name: office.local
DNS Computer Name: server2020-rdp.office.local
DNS Tree Name: office.local
Product Version: 10.0.17763
CPE: cpe:2.3:a:microsoft:windows:10.0.17763


************ RDP-Enum-Encryption Results ************
Starting Nmap 7.80 ( https://nmap.org ) at 2023-12-05 11:44 CET
Nmap scan report for d207-81-231-54.bchsia.telus.net (207.81.231.54)
Host is up (0.29s latency).

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
| rdp-enum-encryption: 
|   Security layer
|     CredSSP (NLA): SUCCESS
|     CredSSP with Early User Auth: SUCCESS
|_    RDSTLS: SUCCESS

Nmap done: 1 IP address (1 host up) scanned in 7.35 seconds

```

# Script Components

1. parse_ntlm_info(output)
Parses the output of the rdp-ntlm-info script using regular expressions.
Extracts information such as Target Name, NetBIOS Domain Name, NetBIOS Computer Name, DNS Domain Name, DNS Computer Name, DNS Tree Name, and Product Version.

2. build_cpe(ntlm_info)
Builds a CPE string based on the extracted NTLM information.
Uses the vendor "Microsoft," product "Windows," and the product version (if available).

3. get_screenshot()
[To be implemented] Function to capture an RDP screenshot.

4. scan_rdp(ip_address, port, output_file)
Runs the rdp-ntlm-info script using nmap.
Parses NTLM information and builds a CPE string.
Saves the results to the specified output file.
[Optional] Runs the rdp-enum-encryption script and appends the results to the same output file

# CVE helper script

With the informations gathered byt the above script is possible to easily figure out the CPE of the relative system
eg: cpe:2.3:a:microsoft:windows:10.0.17763 is cpe:2.3:o:microsoft:windows_10:1809 > this is how I figured out to query
the NVD database of CVEs see - https://nvd.nist.gov/products/cpe/detail/1EFCEE85-EB7B-4D97-8675-57A3A5DA72DE?namingFormat=2.3&orderBy=CPEURI&keyword=cpe%3A2.3%3Ao%3Amicrosoft%3Awindows_10_1809&status=FINAL%2CDEPRECATED

```
(env) alessandro@xps:~/Development/rdp$ python3 cve.py -cpe "cpe:2.3:o:microsoft:windows_10:1809"
CVEs for Windows version cpe:2.3:o:microsoft:windows_10:1809:
CVE-2013-3900
CVE-2015-6184
CVE-2016-0088
CVE-2016-0089
CVE-2016-0090
CVE-2015-8823
CVE-2016-0168
CVE-2016-0170
CVE-2016-0171
CVE-2016-0173
CVE-2016-0174
CVE-2016-0175
CVE-2016-0176
CVE-2016-0179
CVE-2016-0180
CVE-2016-0196
CVE-2016-0197
CVE-2016-3215
CVE-2016-4171
CVE-2016-8008

```