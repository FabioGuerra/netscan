#! /usr/bin/python3
import socket
import scapy.all as scapy
import sys
from tabulate import tabulate
from mac_vendor_lookup import MacLookup
import nmap
import pprint
import os


class Constantes:
    IP = "IP"
    MAC = "MAC"
    BROADCAST_MAC_ADDRESS = "ff:ff:ff:ff:ff:ff"
    VENDOR = "VENDOR"
    SCAN = "scan"
    OUTPUT_FILE = "output.txt"


def valida_ip(ip):
    try:
        if "/" in ip:
            ip = ip.split("/")[0]

        socket.inet_aton(ip)
        return True

    except Exception as e:
        print(f"Ip inválido!!\n{e}")
        return False


def scan(ip, iface):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst=Constantes.BROADCAST_MAC_ADDRESS)  # Ethernet frame  to retrieve mac address

    responses_list = list()

    arp = broadcast / arp_request

    # sending the packet
    answered_response_list, _ = scapy.srp(arp, timeout=1, iface=iface)
    # send and receive (with custom ether) retorna duas listas: pacotes recebidos e não recebidos

    for answer in answered_response_list:
        response_dict = dict()
        mac = MacLookup()
        # mac.update_vendors() # demora muito!!!

        response_dict[Constantes.IP] = answer[1].psrc
        response_dict[Constantes.MAC] = answer[1].hwsrc

        try:
            response_dict[Constantes.VENDOR] = mac.lookup(answer[1].hwsrc)
        except:
            response_dict[Constantes.VENDOR] = "UNKNOWN"

        responses_list.append(response_dict)

    return responses_list


def nmap_scan(ip):
    scan = nmap.PortScanner()
    return scan.scan(ip, ports="1-65535", arguments="-T4 -A -sS")


def get_interfaces():
    interfaces = os.listdir('/sys/class/net/')
    iface_dict = dict()
    print("Choose an interface: ")
    for i, iface in enumerate(interfaces):
        iface_dict[str(i)] = iface
        print(f"{i}: {iface}")

    choice = input()
    try:
        return iface_dict[choice]
    except Exception as e:
        print(f"Invalid choice, using defaults ({iface_dict['0']})") # Defaults = first interface
        return iface_dict["0"]


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Missing params!!")
        sys.exit()

    ip = sys.argv[1]
    if not valida_ip(ip):
        sys.exit()
    # Interfaces
    iface = get_interfaces()

    resposta = scan(ip, iface)

    if len(resposta) == 0:
        print("Nothing to show!")
        sys.exit()

    with open(Constantes.OUTPUT_FILE, "w") as saida:
        saida.write("SCAN OUTPUT\n\n")
        saida.write(tabulate(resposta, headers="keys"))
        saida.write("\n\n")

    print(tabulate(resposta, headers="keys", tablefmt="fancy_grid"))
    print("\n\n\n")

    do_nmap_scan = input("Deseja fazer um scan com os hosts descobertos? (Enter para cancelar) ")

    if do_nmap_scan:
        print("Starting NMAP scan: \n")

        ### Cria um arquivo de saída vazio

        for host in resposta:
            print(f"\nHost: {host[Constantes.IP]} -> {host[Constantes.VENDOR]}")
            scan_result = nmap_scan(ip=host[Constantes.IP])
            pprint.pprint(scan_result[Constantes.SCAN])

            with open(Constantes.OUTPUT_FILE, "a") as saida:
                saida.write(f"\nHost: {host[Constantes.IP]} -> {host[Constantes.VENDOR]}\n")
                saida.write(str(pprint.pformat(scan_result[Constantes.SCAN])))
                saida.write("\n")

####  Notes

# print(broadcast.summary()) # sumário
# print(scapy.ls(scapy.Ether())) # Mostra os campos do módulo solicitado
