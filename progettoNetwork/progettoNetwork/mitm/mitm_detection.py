#!/usr/bin/python3
import http.server
import json
import requests
from requests.auth import HTTPBasicAuth
import host_probing_hpke as hpke
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

"""----------------------- Sezione costanti e variabili di utilità -----------------------"""
IP_HOST = '0.0.0.0'
PORTA_HOST = 8080
URL_CONTROLLER = 'http://172.17.0.2:8181/onos/v1/network/configuration/hosts/'
ONOS_USERNAME = "onos"
ONOS_PASSWORD = "rocks"

hexPublicKeyH1 = "3059301306072a8648ce3d020106082a8648ce3d0301070342000485ad0eb6edaa7d7d1ce30a38319e9577c8c938519a565a5912037c2a782907fe1acf7fd1d7a80dc5e376817cf94ab2f0f2e9e79b574be956dea50b20a0729ee5"
hexPublicKeyH2 = "3059301306072a8648ce3d020106082a8648ce3d0301070342000498f2c8333abe9d85a1e57516e4459514280e60838f60449825650e4c951ea4cde0a8ba94d155007d90802da259b4a5aaac74cda9c1c7e9b2cfd84d801a908dfb"
hexPublicKeyH3 = "3059301306072a8648ce3d020106082a8648ce3d030107034200041009e90153e15fe741e749b65dd55dcb8d7159680dfe2cea489a5e5497e78bf18c944ec07ddd89eb41031642f38478cb077b7d7dfd5852d2451d95d495c8e0d1"
hexPublicKeyH4 = "3059301306072a8648ce3d020106082a8648ce3d030107034200043bb53d8481c35b9631d301f3c3f37e8310552e43f3ba17d4ea077ea310d19e60ac78298d055cd9dc1dc14192108b70c4ca7bbbe7cce3191bdaeeca1d9ae69d02"

# Corrispondenze ip-chiavi

chiavi = {
    '10.0.0.1': hexPublicKeyH1,
    '10.0.0.2': hexPublicKeyH2,
    '10.0.0.3': hexPublicKeyH3,
    '10.0.0.4': hexPublicKeyH4
}

flows = {}
switch = None
flow_id = None
mac_malevolo = None

"""----------------------- Fine sezione costanti e variabili di utilità -----------------------"""


"""----------------------- Classe proxy -----------------------"""


class GestoreRichiesteHttp(http.server.SimpleHTTPRequestHandler):

    def do_POST(self):
        lunghezza_richiesta = int(self.headers['Content-Length'])
        corpo_richesta = self.rfile.read(lunghezza_richiesta)
        try:
            corpo_json = self.valida_richiesta_post(corpo_richesta)
        except Exception as e:
            print(e)
            self.send_response(400)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(str(e).encode('utf-8'))
            return

        risposta = requests.post(URL_CONTROLLER, auth=HTTPBasicAuth(ONOS_USERNAME, ONOS_PASSWORD),
                                 headers={'Content-Type': 'application/json'}, json=corpo_json)

        self.send_response(risposta.status_code)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(risposta.content)
        self.close_connection = True

    def do_DELETE(self):
        lunghezza_richiesta = int(self.headers['Content-Length'])
        corpo_richiesta = self.rfile.read(lunghezza_richiesta)
        try:
            _, firma_valida = self.valida_firma(corpo_richiesta)

        except Exception as e:
            print(e)
            self.send_response(400)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(str(e).encode('utf-8'))
            return
        if firma_valida:
            risposta = requests.delete(URL_CONTROLLER, auth=HTTPBasicAuth(ONOS_USERNAME, ONOS_PASSWORD))

            self.send_response(risposta.status_code)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(risposta.content)
            self.close_connection = True

    def valida_richiesta_post(self, corpo_richiesta):
        try:
            corpo_in_chiaro, _ = self.valida_firma(corpo_richiesta)
            corpo_in_chiaro = json.loads(corpo_in_chiaro)
        except Exception as e:
            raise ValueError('Fallimento in fase di validazione della firma')

        # Se si vuole provare l'attacco commentare fino alla raise
        if mitm_detection(corpo_in_chiaro, self.client_address[0]):
            banna_attaccante(self.client_address[0])
            raise ValueError(f"Compromissione della Rete rilevata! Espulso l'host malevolo avente ip: {self.client_address[0]}")
        return corpo_in_chiaro

    def valida_firma(self, payload):
        payload = payload.split(b"separatore")
        firma, messaggio = payload[0], payload[1]

        try:

            public_key = hpke.converti_chiave_pubblica(chiavi[self.client_address[0]])
            public_key.verify(firma, messaggio, ec.ECDSA(hashes.SHA256()))
            result = True
            return messaggio, result
        except Exception as e:
            print(e)
            raise ValueError('Errore nella validazione della firma')


"""----------------------- Fine classe proxy -----------------------"""


"""----------------------- Sezione metodi di utilità -----------------------"""


def acquisisci_snapshot():
    risposta = requests.get("http://172.17.0.2:8181/onos/v1/hosts/", auth=HTTPBasicAuth("onos", "rocks"))
    return risposta.json()


def mitm_detection(corpo_richiesta, ip_mittente):
    topologia = acquisisci_snapshot()
    ips = None
    locations = None
    for dato in corpo_richiesta:
        ips = corpo_richiesta[dato]["basic"]["ips"]
        locations = corpo_richiesta[dato]["basic"]["locations"]

    if ip_mittente != ips[0]:
        return True

    for location in locations:
        for host in topologia['hosts']:
            for l in host['locations']:
                verifica = f"{l['elementId']}/{l['port']}"
                if location == verifica:
                    if ip_mittente == ips[0] and ips[0] == host['ipAddresses'][0]:
                        continue
                    return True
    return False


def banna_attaccante(ip_malevolo):
    global switch
    global flow_id
    global mac_malevolo
    topologia = acquisisci_snapshot()

    for host in topologia['hosts']:

        if host['ipAddresses'][0] == ip_malevolo:
            switch = host['locations'][0]['elementId']
            mac_malevolo = host['mac']

    # Installiamo una regola di flusso nel controller per negare la connettività all'host malevolo
    payload = {
        "flows": [
            {
                "priority": 50000,
                "timeout": 0,
                "isPermanent": True,
                "deviceId": switch,
                "treatment": {
                    "instructions": []
                },
                "selector": {
                    "criteria": [
                        {
                            "type": "ETH_SRC",
                            "mac": mac_malevolo
                        }
                    ]
                }
            }
        ]
    }

    risposta = requests.post("http://172.17.0.2:8181/onos/v1/flows/", auth=HTTPBasicAuth("onos", "rocks"),
                             headers={'Content-Type': 'application/json'}, json=payload).json()

    switch = risposta["flows"][0]["deviceId"]
    flow_id = risposta["flows"][0]["flowId"]

    flows[flow_id] = switch

    # Rimuoviamo l'host dall'elenco degli hosts
    requests.delete(f"http://172.17.0.2:8181/onos/v1/hosts/{mac_malevolo}/None",
                    auth=HTTPBasicAuth("onos", "rocks"))


def avvio(server_class=http.server.HTTPServer, handler_class=GestoreRichiesteHttp):
    ip_server = (IP_HOST, PORTA_HOST)
    httpd = server_class(ip_server, handler_class)
    print(f'Avviato MITM Detection su {IP_HOST}:{PORTA_HOST}')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nTerminazione di MITM Detection.")
        httpd.server_close()


"""----------------------- Fine sezione metodi di utilità -----------------------"""

if __name__ == '__main__':
    avvio()
