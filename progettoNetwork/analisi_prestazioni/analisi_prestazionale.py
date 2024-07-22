import psutil
import time
import csv
from threading import Thread
from scapy.all import sniff


"""--------------------- Sezione analisi utilizzo di RAM e CPU ---------------------"""


def raccogli_metriche_hardware():
    utilizzo_cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()
    utilizzo_ram = ram.percent
    return utilizzo_cpu, utilizzo_ram


def salva_metriche_hardware(nomefile):
    with open(nomefile, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Utilizzo CPU (%)", "Utilizzo RAM (%)"])
        inizio = time.time()

        try:
            while time.time() - inizio < 80:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                utilizzo_cpu, utilizzo_ram = raccogli_metriche_hardware()
                writer.writerow([timestamp, utilizzo_cpu, utilizzo_ram])
                print(f"{timestamp} - CPU: {utilizzo_cpu}% - RAM: {utilizzo_ram}%")
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("Analisi prestazioni terminata.")


"""--------------------- Fine sezione analisi utilizzo di RAM e CPU ---------------------"""

"""--------------------- Sezione analisi consumo larghezza di banda ---------------------"""


def cattura_pacchetti(interfaccia, durata_cattura, risultato, indice):
    pacchetto = sniff(iface=interfaccia, timeout=durata_cattura)
    bytes_cattura = sum(len(packet) for packet in pacchetto)
    risultato[indice] = bytes_cattura


def calcola_banda(interfacce, durata_cattura):
    threads = []
    risultati = [0] * len(interfacce)
    print(f"Inizio del calcolo, attendere {durata_cattura} secondi...")
    # Crea e avvia un thread per ciascuna interfaccia di rete
    for indice, interfaccia in enumerate(interfacce):
        thread = Thread(target=cattura_pacchetti, args=(interfaccia, durata_cattura, risultati, indice))
        threads.append(thread)
        thread.start()

    # Attende che tutti i thread terminino
    for thread in threads:
        thread.join()
    for indice, interfaccia in enumerate(interfacce):
        print(f"Banda consumata da {interfaccia}: {(risultati[indice] * 8) / durata_cattura} bps")
    bytes_totali = sum(risultati)
    bandwidth_rete = (bytes_totali * 8) / durata_cattura
    print(f"Larghezza di banda consumata dall'intera rete è: {bandwidth_rete} bps")


"""--------------------- Fine sezione analisi consumo larghezza di banda ---------------------"""

if __name__ == "__main__":
    # salva_metriche_hardware("hw_arp_aead.csv")
    calcola_banda(["s1-eth1", "s1-eth2", "s1-eth3", "s2-eth1", "s2-eth2", "s2-eth3", "s2-eth4"], 80)
