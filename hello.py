#!/usr/bin/ env python
import subprocess
import optparse
import re

parse = optparse.OptionParser()

optparse.OP
def get_arguments():
    parse.add_option("-i", "--interface", dest="interface", help="no sea bruto")
    parse.add_option("-m", "--mac", dest="mac", help="no sea bruto")
    (options, arguments) = parse.parse_args()
    print(options,"ohla")
    return options 

def change_mac(interface, mac):
    print("[+]se ha cambiado la mac adress de la interface: " + interface + " por  " + mac)
    subprocess.call("ifconfig " + interface + " down", shell=True)
    subprocess.call("ifconfig " + interface + " hw ether " + mac, shell=True)
    subprocess.call("ifconfig " + interface + " up", shell=True)


opciones = get_arguments()
change_mac(opciones.interface, opciones.mac)
validar = subprocess.check_output(["ifconfig", opciones.interface])
print(validar)
hola=re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", validar)
if(hola.group(0)==opciones.mac):
    print("todo ha salido bien")


