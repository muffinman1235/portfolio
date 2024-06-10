
from scapy.all import send, IP, TCP, UDP, Raw, ICMP, sr1,sniff,show_interfaces
from tkinter import scrolledtext, filedialog, Menu, colorchooser, simpledialog,messagebox
from tkinter.font import Font
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from scapy.all import IP, ICMP, send, sr1, sniff
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
init(autoreset=True)



def help_hacking():
    print("""
    
 _   _            _    _               __   __           _      
| | | | __ _  ___| | _(_)_ __   __ _  |  \\/  | ___   __| | ___
| |_| |/ _` |/ __| |/ / | '_ \\ / _` | | |\\/| |/ _ \\ / _` |/ _ \\
|  _  | (_| | (__|   <| | | | | (_| | | |  | | (_) | (_| |  __/
|_| |_|\\__,_|\\___|_|\\_\\_|_| |_|\\__, | |_|  |_|\\___/ \\__,_|\\___|
                               |___/

        1. spam_ping - floods a server
        2. nslookup - gets ip of website
        3. send_ping - sends ping to website
        4. scan_port - scan website for open ports
        5. sniff - sniffs
    
    """)
hacking=True
if hacking:
            
    def get_ip(hostname):
        """Perform a DNS lookup to find the IP addresses associated with a hostname and print the results directly."""
        try:
            # Use socket to get the IP addresses
            ips = socket.gethostbyname_ex(hostname)
            print(f"Name: {ips[0]}")
            print(f"Aliases: {', '.join(ips[1])}")
            print(f"Addresses: {', '.join(ips[2])}")
        except socket.gaierror:
            print("Unable to get IP: the hostname could not be resolved.")
        except Exception as e:
            print(f"An error occurred: {str(e)}")


    def send_ping(target_ip):
        try:
            packet = IP(dst=target_ip) / ICMP()
            response = send(packet, verbose=False)
            if response:
                print(f"Ping sent to {target_ip}")
        except Exception as e:
            print(f"Failed to send ping to {target_ip}: {str(e)}")

    def spam_ping(target_ip,count):
        ad=0
        for x in range(count):
            send_ping(target_ip)
            ad+=1
            if ad%483==0:
                print(f"{ad} pings sent")
    def tcp_syn_scan(target_ip):
        """
        Perform a TCP SYN scan on a range of ports for a given IP address.
        """
        port_range=[20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 137, 138, 139, 143, 161, 162, 179,
    201, 389, 443, 445, 500, 514, 515, 520, 587, 636, 993, 995, 1025, 1433, 1434, 1521,
    1723, 2049, 2082, 2083, 2181, 2302, 2483, 2484, 3306, 3389, 3544, 3689, 3690, 5432,
    5900, 5984, 5985, 5986, 6379, 6667, 8000, 8080, 8443, 8888, 9000, 9092, 11211, 27017,
    27018, 27019]
        openg=[]
        for port in port_range:
            packet = IP(dst=target_ip) / TCP(dport=port, flags='S')
            response = sr1(packet, timeout=1, verbose=0)
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                print(f"Port {port} is open")
                openg.append(port)
            else:pass
                #print(f"Port {port} is closed")
    doesntwork=False
    if doesntwork==True:
        def packet_callback(packet):
            """
            Callback function to process packets.
            Extracts necessary data from packets and formats it for JSON serialization.
            """
            # Check if the packet contains an IP layer
            if packet.haslayer('IP'):
                packet_details = {
                    "source": packet['IP'].src,
                    "destination": packet['IP'].dst,
                    "protocol": packet['IP'].proto,
                    "length": len(packet)
                }
                return packet_details
            else:
                # Optionally handle non-IP packets or return None or some default data
                return None
        def dec_sniff(packet):
            if packet.haslayer(IP):
                ip_layer = packet.getlayer(IP)
                try:
                    # Attempt to get the payload as raw data
                    payload = ip_layer.payload.load.decode('utf-8', errors='ignore')
                    print("Payload:", payload)
                except AttributeError:
                    # Some packets might not have a payload
                    print("No payload")
                print(f"Packet from {ip_layer.src} to {ip_layer.dst}")
                print("Details:", packet.summary())
        def http_payload(packet):
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    # This is HTTP traffic (unencrypted)
                    print("HTTP Data:", packet[Raw].load)
                    
        def sniff_packets(filter=None, count=50):
            """
            Sniff network packets, process them, and store the results in a JSON file.
            """
            print(show_interfaces())
            print("Starting packet sniffing...")
            packets = sniff(filter=filter, count=count, prn=packet_callback, store=False)

            # Collect non-None results from the callback
            packet_details_list = [packet for packet in packets if packet is not None]

            # Writing to JSON file
            try:
                with open('captured_packets.json', 'w') as f:
                    json.dump(packet_details_list, f, indent=4)
                print(f"Results have been written to 'captured_packets.json'. Total packets captured: {len(packet_details_list)}")
            except Exception as e:
                print(f"Failed to write to file: {str(e)}")
    else:
        def unified_packet_callback(packet):
            """
            A unified callback to process and display various types of packet details.
            Writes the output to 'packets.txt' instead of printing to the console.
            """
            with open('packets.txt', 'a') as file:  # Open the file in append mode
                if packet.haslayer(IP):
                    # General IP layer info
                    packet_details = {
                        "source": packet[IP].src,
                        "destination": packet[IP].dst,
                        "protocol": packet[IP].proto,
                        "length": len(packet)
                    }
                    file.write(json.dumps(packet_details, indent=4) + '\n')

                    # Attempt to decode payload if it exists
                    if packet.haslayer(Raw):
                        try:
                            payload = packet[Raw].load.decode('utf-8', errors='ignore')
                            file.write("Payload: " + payload + '\n')
                        except Exception as e:
                            file.write("Could not decode payload: " + str(e) + '\n')

                    # Specific checks for HTTP traffic
                    if packet.haslayer(TCP):
                        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                            http_data = "HTTP Data: " + (packet[Raw].load.decode('utf-8', errors='ignore') if packet.haslayer(Raw) else "No Data")
                            file.write(http_data + '\n')

                    file.write("Packet Summary: " + packet.summary() + '\n\n\n')

                else:
                    file.write("Non-IP Packet detected, not processed.\n")

        def sniff_packets(filter=None, count=1910):
            """
            Sniff network packets, process them, and write the results to a text file instead of printing.
            """
            log_file = open('packet_capture_log.txt', 'w')
            
            try:
                log_file.write("Starting packet sniffing...\n")
                packets = sniff(filter=filter, count=count, prn=unified_packet_callback, store=False)

                # Collect non-None results from the callback
                packet_details_list = [unified_packet_callback(packet) for packet in packets if packet is not None]

                # Write to text file
                log_file.write(json.dumps(packet_details_list, indent=4) + '\n')
                log_file.write(f"Results have been written to 'captured_packets.json'. Total packets captured: {len(packet_details_list)}\n")
            except Exception as e:
                log_file.write(f"Failed to write to file: {str(e)}\n")
            finally:
                log_file.close()


def mini_shell():
    """Simple command-line interface."""
    commands = {
        
        'help': help_normal,
        'help_hacking':help_hacking,
        'spam_ping': spam_ping,
        'nslookup':get_ip,
        'send_ping':send_ping,
        'scan_port':tcp_syn_scan,
        'sniff':sniff_packets,
    }

    while True:
        current_dir = os.getcwd()
        cmd_input = input(f"{current_dir}> ").strip().split()
        if not cmd_input:
            continue
        cmd = cmd_input[0]
        args = cmd_input[1:]  # All other parts are considered arguments

        if cmd == 'exit':
            print("Exiting mini-shell.")
            break
        elif cmd in commands:
            try:
                # Ensure the command is called with the required number of arguments
                if cmd == 'nslookup' and len(args) != 1:
                    print("Usage: nslookup <hostname>")
          #      if cmd == 'sniff' and len(args) !=
                elif cmd == 'spam_ping':
                    if len(args) == 2:
                        target_ip = args[0]
                        try:
                            count = int(args[1])
                            spam_ping(target_ip, count)
                        except ValueError:
                            print("Usage: spam_ping <target_ip> <count> (count must be an integer)")
                    else:
                        print("Usage: spam_ping <target_ip> <count>")
                else:
                    commands[cmd](*args)
            except TypeError as e:
                print(f"Error: Incorrect usage of {cmd}.")
                print(f"Usage error for {cmd}. Please check the arguments.")
            except Exception as e:
                print(f"Error executing {cmd}: {str(e)}")

        else:
            print(f"Unknown command: {cmd}")

if __name__ == "__main__":
    mini_shell()
