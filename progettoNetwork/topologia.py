#!/usr/bin/python3
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink
from mininet.nodelib import NAT
import os
import time
import requests
from requests.auth import HTTPBasicAuth

def start_mininet_major():
    setLogLevel('info')
    net = Mininet(link=TCLink, switch=OVSSwitch)
    controller = net.addController('onos', controller=RemoteController, ip='172.17.0.2', port=6653)
    switches = []
    hosts = []

    for switch in range(10):
        switches.append(net.addSwitch(f's{switch + 1}', switch=OVSSwitch, protocols='OpenFlow13'))

    hosts.append(net.addHost('h1', ip='10.0.0.1', mac='00:00:00:00:00:01'))
    net.addLink(hosts[0], switches[0])

    for i in range(len(switches) - 1):
        net.addLink(switches[i], switches[i + 1])

    hosts.append(net.addHost('nat0', cls=NAT, ip='10.0.0.254/24', mac='00:00:00:00:00:05', inNamespace=False))
    net.addLink(hosts[1], switches[0])

    for host in range(1, 19):

        if (host + 1) < 10:
            if (host + 1) == 5:
                hosts.append(net.addHost(f'h{host + 1}', ip=f'10.0.0.{host + 1}', mac=f'00:00:00:00:01:00'))
            else:
                hosts.append(net.addHost(f'h{host + 1}', ip=f'10.0.0.{host + 1}', mac=f'00:00:00:00:00:0{host + 1}'))
        else:
            hosts.append(net.addHost(f'h{host + 1}', ip=f'10.0.0.{host + 1}', mac=f'00:00:00:00:00:{host + 1}'))

    for indice in range(2, len(hosts) - 1, 2):
        net.addLink(hosts[indice], switches[indice//2])
        net.addLink(hosts[indice + 1], switches[(indice//2)])

    net.start()
    # Configura il NAT
    hosts[1].configDefault()

    for host in hosts:
        if host != hosts[1]:
            host.cmd('ip route add default via 10.0.0.254')

    return net, len(hosts)

def start_mininet():
    # Imposta il livello di log
    setLogLevel('info')

    # Crea una rete Mininet
    net = Mininet(link=TCLink, switch=OVSSwitch)

    # Aggiungi un controller remoto (sostituisci 'ip_controller' con l'IP del tuo container ONOS)
    controller = net.addController('onos', controller=RemoteController, ip='172.17.0.2', port=6653)

    # Aggiungi gli switch
    s1 = net.addSwitch('s1', switch=OVSSwitch, protocols='OpenFlow13')
    s2 = net.addSwitch('s2', switch=OVSSwitch, protocols='OpenFlow13')

    # Aggiungi gli host
    h1 = net.addHost('h1', ip='10.0.0.1', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4', mac='00:00:00:00:00:04')

    # Configura i link
    net.addLink(h1, s1)
    net.addLink(s1, s2)
    net.addLink(h2, s2)
    net.addLink(h3, s2)
    net.addLink(h4, s2)

    # Aggiungo un nodo NAT per consentire agli host di connettersi a Internet
    nat = net.addHost('nat0', cls=NAT, ip='10.0.0.254/24', mac='00:00:00:00:00:05', inNamespace=False)
    net.addLink(nat, s1)

    net.start()

    # Configura il NAT
    nat.configDefault()

    # Aggiungo regole di routing per gli host
    for host in [h1, h2, h3, h4]:
        host.cmd('ip route add default via 10.0.0.254')

    return net, 5


def add_safety_aead_gcm(net, nhosts):

    url_host_provider = f"http://172.17.0.2:8181/onos/v1/applications/org.onosproject.hostprovider/active"

    response = requests.delete(url_host_provider, auth=HTTPBasicAuth("onos", "rocks"))

    if response.status_code == 204:
        print("Host Location Provider APP disattivata con successo.")
    else:
        print(f"Errore nella disattivazione dell'applicazione di Host Location Provider: {response.status_code}")

    # Endpoint per attivare e disattivare l'applicazione di mitm detection
    url_mitm_detection = f"http://172.17.0.2:8181/onos/v1/applications/org.onosproject.mitmdetection/active"

    # Invio la richiesta POST per attivare l'applicazione
    response = requests.post(url_mitm_detection, auth=HTTPBasicAuth("onos", "rocks"))

    if response.status_code == 200:
        print("MITM Detection App attivata con successo.")
    else:
        print(f"Errore nell'attivazione dell'applicazione di MITM Detection: {response.status_code}")
    
    time.sleep(1)
    
    nat0 = net.get('nat0')
    nat0.cmd("python3 difesa/mitm_detection.py &")
    
    # Avviamo il Probing
    for id_host in range(1, nhosts):
        host = net.get(f'h{id_host}')
        host.cmd("python3 difesa/host_probing_aead.py &")

    # time.sleep(2)
    # inizio = time.time()
    for i in range(1, nhosts - 1):
        host1 = net.get(f'h{i}')
        host2 = net.get(f'h{i + 1}')
        host1.cmd(f'ping -c 1 {host2.IP()}')
    # fine = time.time() - inizio
    # print(f"Tempo pingall = {fine}")
    CLI(net)
    net.stop()

    # Invio la richiesta DELETE per disattivare l'applicazione di mitm detection
    response = requests.delete(url_mitm_detection, auth=HTTPBasicAuth("onos", "rocks"))

    if response.status_code == 204:
        print("MITM Detection APP disattivata con successo.")
    else:
        print(f"Errore nella disattivazione dell'applicazione di MITM Detection: {response.status_code}")

    response = requests.post(url_host_provider, auth=HTTPBasicAuth("onos", "rocks"))

    if response.status_code == 200:
        print("Host Location Provider APP attivata con successo.")
    else:
        print(f"Errore nell'attivazione dell'applicazione di Host Location Provider: {response.status_code}")

 
def add_safety_hpke(net, nhosts):

    url_host_provider = f"http://172.17.0.2:8181/onos/v1/applications/org.onosproject.hostprovider/active"

    risposta = requests.delete(url_host_provider, auth=HTTPBasicAuth("onos", "rocks"))

    if risposta.status_code == 204:
        print("Host Location Provider APP disattivata con successo.")
    else:
        print(f"Errore nella disattivazione dell'applicazione di Host Location Provider: {risposta.status_code}")

    # Endpoint per attivare e disattivare l'applicazione di mitm detection
    url_mitm_detection = f"http://172.17.0.2:8181/onos/v1/applications/org.onosproject.mitmdetection2/active"

    # Invio la richiesta POST per attivare l'applicazione
    risposta = requests.post(url_mitm_detection, auth=HTTPBasicAuth("onos", "rocks"))

    if risposta.status_code == 200:
        print("MITM Detection App 2 attivata con successo.")
    else:
        print(f"Errore nell'attivazione dell'applicazione di MITM Detection 2: {risposta.status_code}")
    
    time.sleep(1)
    
    nat0 = net.get('nat0')
    nat0.cmd("python3 difesa/mitm_detection.py &")
    
    # Avviamo il Probing
    h1 = net.get('h1')
    h1.cmd("python3 difesa/host_probing_hpke.py --host h1 &")
    h2 = net.get('h2')
    h2.cmd("python3 difesa/host_probing_hpke.py --host h2 &")
    h3 = net.get('h3')
    h3.cmd("python3 difesa/host_probing_hpke.py --host h3 &")
    h4 = net.get('h4')
    h4.cmd("python3 difesa/host_probing_hpke.py --host h4 &")

    # time.sleep(2)
    # inizio = time.time()
    for i in range(1, nhosts - 1):
        host1 = net.get(f'h{i}')
        host2 = net.get(f'h{i + 1}')
        host1.cmd(f'ping -c 1 {host2.IP()}')
    # fine = time.time() - inizio
    # print(f"Tempo pingall = {fine}")
    CLI(net)
    net.stop()

    # Invio la richiesta DELETE per disattivare l'applicazione di mitm detection
    risposta = requests.delete(url_mitm_detection, auth=HTTPBasicAuth("onos", "rocks"))

    if risposta.status_code == 204:
        print("MITM Detection APP 2 disattivata con successo.")
    else:
        print(f"Errore nella disattivazione dell'applicazione di MITM Detection 2: {risposta.status_code}")
    
    risposta = requests.post(url_host_provider, auth=HTTPBasicAuth("onos", "rocks"))

    if risposta.status_code == 200:
        print("Host Location Provider APP attivata con successo.")
    else:
        print(f"Errore nell'attivazione dell'applicazione di Host Location Provider: {risposta.status_code}")


if __name__ == '__main__':
    # Permettiamo di scegliere se avviare la rete con la mitigazione oppure senza
    scelta = input("\nVuoi avviare la rete in modo safe? [Y/n]: ").strip()

    while scelta not in ("Y", "y", "", "N", "n", ):
        print("Hai effettuato una scelta non valida, per favore riprova...")
        scelta = input()
    print("\n")    

    # Abilitiamo l'ip forwarding per permettere agli host di contattare il controller attraverso il nat
    os.system("sudo sysctl -w net.ipv4.ip_forward=1")
    os.system("sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE")
    net, nhosts = start_mininet()
    # net, nhosts = start_mininet_major()
    
    # Rimuoviamo eventuali flows inseriti in esecuzioni precedenti
    response = requests.get("http://172.17.0.2:8181/onos/v1/flows", auth=HTTPBasicAuth("onos", "rocks"))

    # Verifica se la richiesta ha avuto successo (status code 200)
    if response.status_code == 200:
        json_flows = response.json()
        for flow in json_flows.get("flows"):
            if ("org.onosproject.rest" in flow.get("appId") or "org.mitmdetection.app" in flow.get("appId")
                    or "org.mitmdetection2.app" in flow.get("appId")):
                delete_response = requests.delete(f"http://172.17.0.2:8181/onos/v1/flows/{flow.get('deviceId')}/"
                                                  f"{flow.get('id')}", auth=HTTPBasicAuth("onos", "rocks"))

    if scelta in ('Y', 'y', ''):
        scelta = input("Hai scelto di attivare la rete in modo sicuro. Quale algoritmo di crittografico vuoi usare?"
                       "\n\tPremi 1 per AES_GCM\n\tPremi 2 per HPKE\n").strip()
        while scelta not in ("1", "2"):
            print("Mi dispiace hai premuto un tasto scorretto!\nRiprova...")
            scelta = input()
        if scelta == "1":
            add_safety_aead_gcm(net, nhosts)
        else:
            add_safety_hpke(net, nhosts)

    elif scelta in ('N', 'n'):
        time.sleep(2)
        # inizio = time.time()
        for i in range(1, nhosts - 1):
            host1 = net.get(f'h{i}')
            host2 = net.get(f'h{i + 1}')
            host1.cmd(f'ping -c 1 {host2.IP()}')
        # fine = time.time() - inizio
        # print(f"Tempo pingall = {fine}")
        CLI(net)
        net.stop()

