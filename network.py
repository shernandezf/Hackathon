#!/usr/bin/env python

import scapy.all as scapy
import optparse
parse = optparse.OptionParser()
def getparametros():
    parse.add_option("-r","--range", dest="ip",help="no sea bruto")
    (options, arguments) = parse.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    final = broadcast/arp_request

    (resultado, nosirve) = scapy.srp(final, timeout=1)
    print(resultado.show())
    for element in resultado:
        print(element)
        print("---------------------")
    retorno=[]
    for element in resultado:

        Diccionario = {"ip":element[1].psrc, "MAC":element[1].hwsrc}
        retorno.append(Diccionario)
    return retorno

opciones=getparametros()

ipstring=str(opciones.ip)
print(ipstring)
recibir= scan(ipstring)
for element in recibir:
    print( element["ip"]+ "       "+element["MAC"])
