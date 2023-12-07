import ssl
import socket
import struct
import urllib.parse

SERVER_NAME = 1
DOMAIN_NAME = 2
SERVER_FQDN = 3
DOMAIN_FQDN = 4
PARENT_DOMAIN = 5

REQ_FOR_CHALLENGE_BYTES = bytes([78, 84, 76, 77, 83, 83, 80, 0, 1, 0, 0, 0, 7, 130, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

class TargetStruct:
    def __init__(self, target_url):
        self.target_url = urllib.parse.urlparse(target_url)
        self.challenge = Type2ChallengeStruct()

    def get_challenge(self):
        if self.target_url.scheme == "rdp":
            self.get_rdp_challenge()
        else:
            raise ValueError("Unrecognized URL scheme.")

        if b"NTLMSSP\x00" in self.challenge.raw_challenge:
            self.challenge.raw_challenge = self.challenge.raw_challenge[self.challenge.raw_challenge.index(b"NTLMSSP\x00"):]
            self.challenge.decode()
        else:
            raise ValueError("Invalid NTLMSSP response.")

    def get_rdp_challenge(self):
        if ":" not in self.target_url.netloc:
            self.target_url = self.target_url._replace(netloc=self.target_url.netloc + ":3389")
        challenge = bytearray(2048)
        with socket.create_connection((self.target_url.hostname, self.target_url.port), timeout=10) as sock:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=self.target_url.hostname) as conn:
                nla_data = bytearray(b"\x30\x37\xa0\x03\x02\x01\x60\xa1\x30\x30\x2e\x30\x2c\xa0\x2a\x04\x28") + REQ_FOR_CHALLENGE_BYTES + bytearray(b"\x00\x00\x0a\x00\x63\x45\x00\x00\x00\x0f")
                conn.sendall(nla_data)
                read_len = conn.recv_into(challenge)
                challenge = challenge[23:read_len]
                self.challenge.raw_challenge = bytes(challenge)

    def print_info(self):
        if self.challenge.raw_challenge:
            print("+%s+%s+" % (("-" * 19), ("-" * 47)))
            print("| %17s | %-45s |" % ("Server Name", self.challenge.server_name))
            print("| %17s | %-45s |" % ("Domain Name", self.challenge.domain_name))
            print("| %17s | %-45s |" % ("Server FQDN", self.challenge.server_fqdn))
            print("| %17s | %-45s |" % ("Domain FQDN", self.challenge.domain_fqdn))
            print("| %17s | %-45s |" % ("Parent Domain", self.challenge.parent_domain))
            print("| %17s | %-45s |" % ("OS Version Number", self.challenge.os_version_number))
            print("| %17s | %-45s |" % ("OS Version", self.challenge.os_version_string))
            print("+%s+%s+" % (("-" * 19), ("-" * 47)))


class Type2ChallengeStruct:
    def __init__(self):
        self.raw_challenge = b""
        self.server_name = ""
        self.domain_name = ""
        self.server_fqdn = ""
        self.domain_fqdn = ""
        self.parent_domain = ""
        self.os_version_number = ""
        self.os_version_string = ""

    def decode(self):
        offset = struct.unpack("<H", self.raw_challenge[44:46])[0]
        data = self.raw_challenge[offset:]

        for i in range(5):
            data_type = struct.unpack("<H", data[0:2])[0]
            data_length = struct.unpack("<H", data[2:4])[0] + 4
            text = data[4:data_length].decode("utf-8").replace("\x00", "")
            
            if data_type == SERVER_NAME:
                self.server_name = text
            elif data_type == DOMAIN_NAME:
                self.domain_name = text
            elif data_type == SERVER_FQDN:
                self.server_fqdn = text
            elif data_type == DOMAIN_FQDN:
                self.domain_fqdn = text
            elif data_type == PARENT_DOMAIN:
                self.parent_domain = text

            data = data[data_length:]

        if offset > 48:
            major = int(self.raw_challenge[48])
            minor = int(self.raw_challenge[49])
            build = struct.unpack("<H", self.raw_challenge[50:52])[0]
            self.os_version_number = f"{major}.{minor}.{build}"

            version_key = f"{major}.{minor}"
            if version_key == "5.0":
                self.os_version_string = f"Windows 2000 (Build {build})"
            elif version_key == "5.1":
                self.os_version_string = f"Windows XP/Server 2003 (R2) (Build {build})"
            elif version_key == "5.2":
                self.os_version_string = f"Windows XP/Server 2003 (R2) (Build {build})"
            elif version_key == "6.0":
                self.os_version_string = f"Windows Vista/Server 2008 (Build {build})"
            elif version_key == "6.1":
                self.os_version_string = f"Windows 7/Server 2008 R2 (Build {build})"
            elif version_key == "6.2":
                self.os_version_string = f"Windows 8/Server 2012 (Build {build})"
            elif version_key == "6.3":
                self.os_version_string = f"Windows 8.1/Server 2012 R2 (Build {build})"
            elif version_key == "10.0":
                if build >= 22000:
                    self.os_version_string = f"Windows 11/Server 2022 (Build {build})"
                elif build >= 20348:
                    self.os_version_string = f"Windows 10/Server 2022 (Build {build})"
                elif build >= 17623:
                    self.os_version_string = f"Windows 10/Server 2019 (Build {build})"
                else:
                    self.os_version_string = f"Windows 10/Server 2016 (Build {build})"
            else:
                self.os_version_string = f"{major}.{minor}.{build}"



def main():
    target_url = "rdp://85.234.199.59"
    target = TargetStruct(target_url)

    try:
        target.get_challenge()
        target.print_info()
    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    main()
