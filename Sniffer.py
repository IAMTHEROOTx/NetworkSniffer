import socket
import struct
import platform

# ---------------------------------------------------------------------------------------------------------
class Windows:
    @staticmethod
    def sniff():
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        host = socket.gethostbyname(socket.gethostname())
        sniffer.bind((host, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        print(f"Sniffer démarré sur {host} (Windows)")
        return sniffer

    @staticmethod
    def traitement(packet):
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        ttl = ip_header[5]
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dst_ip = socket.inet_ntoa(ip_header[9])

        print("==== Nouveau paquet ====")
        print(f"Version IP: {version}")
        print(f"IHL (Header Length): {ihl * 4} bytes")
        print(f"TTL: {ttl}")
        print(f"Protocol: {protocol}")
        print(f"IP Source: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print("========================\n")

# ---------------------------------------------------------------------------------------------------------
class Linux:
    @staticmethod
    def sniff():
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        print("Sniffer démarré sur Linux")
        return sniffer

    @staticmethod
    def traitement(packet):
        ip_header = packet[14:34]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        ttl = iph[5]
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        print("==== Nouveau paquet ====")
        print(f"Version IP: {version}")
        print(f"IHL (Header Length): {ihl * 4} bytes")
        print(f"TTL: {ttl}")
        print(f"Protocol: {protocol}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print("========================\n")

# ---------------------------------------------------------------------------------------------------------
def main():
    system = platform.system().lower()

    if system == 'windows':
        sniffer = Windows.sniff()
        try:
            while True:
                packet, _ = sniffer.recvfrom(65535)
                Windows.traitement(packet)
        except KeyboardInterrupt:
            print("\nSniffer arrêté...")
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sniffer.close()

    elif system == 'linux':
        sniffer = Linux.sniff()
        try:
            while True:
                packet, _ = sniffer.recvfrom(65535)
                Linux.traitement(packet)
        except KeyboardInterrupt:
            print("\nSniffer arrêté...")
            sniffer.close()
    else:
        print("Système non pris en charge.")

if __name__ == "__main__":
    main()
