#!/usr/bin/python3
import scapy.all as scapy
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
from random import randint
import gmpy2

"""----------------------- Sezione costanti e variabili di utilità -----------------------"""


controller_ip = "172.17.0.2"
CHIAVE_DECIFRATURA = None
CHIAVE_CIFRATURA = None
parametri_diffie_hellman = []


"""----------------------- Fine sezione costanti e variabili di utilità -----------------------"""


"""----------------------- Sezione metodi di utilità -----------------------"""


# Funzione per decifrare il payload AES-GCM
def decifra(nonce, ciphertext):
    aes = AESGCM(CHIAVE_DECIFRATURA)
    aad = b'probing'
    plaintext = aes.decrypt(nonce, ciphertext, aad)
    return plaintext


# Funzione per cifrare il payload AES-GCM
def cifra(plaintext):
    aes = AESGCM(CHIAVE_CIFRATURA)
    aad = b'probing'
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


# Funzione per gestire i pacchetti ICMP
def handle_packet(packet):
    global CHIAVE_DECIFRATURA
    global CHIAVE_CIFRATURA
    global parametri_diffie_hellman

    # Verifica se è un ICMP Echo Request del controller
    if scapy.ICMP in packet and packet[scapy.ICMP].type == 0 and packet[scapy.IP].src == controller_ip:

        if not (CHIAVE_CIFRATURA is None) and not (CHIAVE_DECIFRATURA is None):
            print(f"Ricevuto Pacchetto di Probing da {controller_ip}.. verifico l'autenticità")
            payload = packet[scapy.Raw].load
            nonce = payload[:12]
            ciphertext = payload[12:]
            try:
                # Decifro il payload
                plaintext = decifra(nonce, ciphertext)
            except Exception:
                print("Errore in fase di decodifica del Payload di probing. Terminazione Programma.")
                exit()

            # Host --> Controller
            print(f"{controller_ip} autenticato. Invio Pacchetto di Probing in risposta...")
            # Inviamo una risposta
            nonce, encrypted_data = cifra(plaintext)
            # Creare il pacchetto ICMP Echo Reply
            livello_datalink = scapy.Ether(dst=packet.src)
            livello_ip = scapy.IP(dst=controller_ip)
            livello_icmp = scapy.ICMP(type=0)
            icmp_payload = b"PROBING" + nonce + encrypted_data
            pacchetto_chiave = livello_datalink / livello_ip / livello_icmp / scapy.Raw(load=icmp_payload)
            scapy.sendp(pacchetto_chiave)

        if CHIAVE_CIFRATURA is None and not (CHIAVE_DECIFRATURA is None):
            try:
                payload = packet[scapy.Raw].load.decode()  # Assuming the payload is in Raw layer
                
                B = int(payload)
                chiave = hex(pow(B, parametri_diffie_hellman[1], parametri_diffie_hellman[0]))[2:]
                while len(chiave) < 64:
                    chiave = f'0{chiave}'
                CHIAVE_CIFRATURA = bytes.fromhex(chiave)
                print(f"Completato lo scambio di chiavi con: {controller_ip}")
            except Exception as e:
                print("Errore nella creazione della CHIAVE_CIFRATURA: ", e)

        # Controller --> Host
        if CHIAVE_DECIFRATURA is None:
            print(f"Ricevuta richiesta di scambio di chiavi crittografiche da: {controller_ip}")

            try:
                payload = packet[scapy.Raw].load.decode()  # Assuming the payload is in Raw layer
                
                p = int(payload.split(',')[0])
                g = int(payload.split(',')[1])
                A = int(payload.split(',')[2])
                b = randint(2, p-2)
                B = pow(g, b, p)
                chiave = hex(pow(A, b, p))[2:]

                while len(chiave) < 64:
                    chiave = f'0{chiave}'
                CHIAVE_DECIFRATURA = bytes.fromhex(chiave)
                p = gmpy2.next_prime(2**255)
                print(p)
                g = randint(2, p-1)
                a = randint(2, p-2)
                A = pow(g, a, p)
                parametri_diffie_hellman.append(p)
                parametri_diffie_hellman.append(a)
                livello_datalink = scapy.Ether(dst=packet.src)
                livello_ip = scapy.IP(dst=controller_ip)
                livello_icmp = scapy.ICMP(type=0)
                icmp_payload = f"RECEIVE_KEY{str(B)},{str(p)},{str(g)},{str(A)}"
                pacchetto_chiave = livello_datalink / livello_ip / livello_icmp / scapy.Raw(load=icmp_payload)
                scapy.sendp(pacchetto_chiave)
            except Exception as e:
                print("Errore nella creazione della CHIAVE_DECIFRATURA: ", e)
                pass
        

def start_sniffing():
    scapy.sniff(filter="icmp", prn=handle_packet)


"""----------------------- Fine sezione metodi di utilità -----------------------"""


if __name__ == "__main__":
    start_sniffing()
    
