import sys
import socket
import ssl
from scapy.all import IP, TCP, send, sr1, sniff

def perform_rdp_handshake(target_ip, target_port, output_file):
    # Craft an RDP connection initiation (X.224) packet
    initiation_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S") / "\x03\x00\x00\x13\x0E\xE0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00\x00\x00"

    # Send the initiation packet and receive the SYN-ACK response
    syn_ack_response = sr1(initiation_packet, timeout=2)

    if syn_ack_response is not None and TCP in syn_ack_response and syn_ack_response[TCP].flags & 0x12 == 0x12:
        # Craft the ACK packet to complete the handshake
        ack_packet = IP(dst=target_ip) / TCP(dport=target_port, sport=syn_ack_response[TCP].dport, seq=syn_ack_response[TCP].ack, ack=syn_ack_response[TCP].seq + 1, flags="A")

        # Send the ACK packet
        send(ack_packet)

        print("RDP handshake completed successfully.")

        # Create a TCP socket and wrap it with SSL/TLS
        with socket.create_connection((target_ip, target_port)) as client_socket:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_socket = context.wrap_socket(client_socket, server_hostname=target_ip)

            # Sniff responses for a short period (e.g., 20 seconds)
            responses = sniff(count=20, timeout=20, filter=f"host {target_ip} and port {target_port}", session=TLSSession)

            # Write captured responses to the output file
            with open(output_file, 'w') as file:
                for response in responses:
                    print(response.summary())
                    file.write(str(response) + '\n')
                    response.show()

            print(f"Captured responses written to {output_file}")

            # Close the TLS connection

            ssl_socket.close()

    else:
        print("Failed to establish RDP connection.")

def main():
    # Check command-line arguments
    if len(sys.argv) != 4:
        print("Usage: python rdp_extractor.py <ip_address> <port> <output_file>")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    output_file = sys.argv[3]

    # Perform RDP handshake and capture responses
    perform_rdp_handshake(target_ip, target_port, output_file)

if __name__ == "__main__":
    main() 