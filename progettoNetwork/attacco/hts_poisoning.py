#!/usr/bin/python3
import scapy.all as scapy


"""----------------------- Sezione costanti e variabili di utilità -----------------------"""

source_ip = "10.0.0.3"
destination_ip = "10.0.0.1"
source_mac = "00:00:00:00:00:03"

"""----------------------- Fine sezione costanti e variabili di utilità -----------------------"""

"""----------------------- Sezione metodi di utilità -----------------------"""


def invio_ping(src_ip, dst_ip, src_mac):
    livello_datalink = scapy.Ether(src=src_mac)

    livello_ip = scapy.IP(src=src_ip, dst=dst_ip)

    livello_icmp = scapy.ICMP()

    packet = livello_datalink / livello_ip / livello_icmp

    risposta = scapy.srp1(packet, timeout=1, verbose=0)

    if risposta:
        print(f"Risposta da {dst_ip}: {risposta.summary()}")
    else:
        print(f"Nessuna risposta da {dst_ip}")


"""----------------------- Fine sezione metodi di utilità -----------------------"""


if __name__ == '__main__':
    invio_ping(source_ip, destination_ip, source_mac)
