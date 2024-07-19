#!/usr/bin/python3
import scapy.all as scapy
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
import argparse
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import binascii



""" Sezione hpke """

ALGORITMO = "AES"
LUNGHEZZA_NONCE = 12
LUNGHEZZA_TAG_GCM = 16
ASSOCIATED_DATA = b"probing"


# Converte chiavi in formato esadecimale in array di bytes
def hex_to_bytes(hex_key):
    return bytes.fromhex(hex_key)

# Converte una chiave privata in una stringa esadecimale
def private_key_to_hex(private_key):
    # Serializza la chiave privata in formato DER
    chiave_pubblica_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Converti i byte della chiave in una stringa esadecimale
    chiave_privata_hex = binascii.hexlify(chiave_pubblica_bytes).decode()
    return chiave_privata_hex

# Converte una chiave pubblica in una stringa esadecimale
def public_key_to_hex(public_key):
    # Serializza la chiave pubblica in formato DER
    chiave_pubblica_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Converti i byte della chiave in una stringa esadecimale
    chiave_pubblica_hex = binascii.hexlify(chiave_pubblica_bytes).decode()
    return chiave_pubblica_hex


# Deriva una chiave pubblica da una stringa in formato esadecimale
def converti_chiave_pubblica(hex_key):
    chiave_in_bytes = hex_to_bytes(hex_key)
    return serialization.load_der_public_key(chiave_in_bytes, backend=default_backend())


# Deriva una chiave privata da una stringa in formato esadecimale
def converti_chiave_privata(hex_key):
    chiave_in_bytes = hex_to_bytes(hex_key)
    return serialization.load_der_private_key(chiave_in_bytes, password=None, backend=default_backend())


# Genera una chiave di sessione usando ECDH
def genera_chiave_di_sessione(private_key, public_key):
    segreto_condiviso = private_key.exchange(ec.ECDH(), public_key)
    # Derive AES key from shared secret using HKDF
    return hashlib.sha256(segreto_condiviso).digest()[:32]


# Cifra il messagio usando AES-GCM
def cifra_messaggio(plaintext, key):
    iv = os.urandom(LUNGHEZZA_NONCE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, ASSOCIATED_DATA)
    return iv + ciphertext


# Decifra il messagio usando AES-GCM
def decifra_messaggio(ciphertext_with_iv, key):
    iv = ciphertext_with_iv[:LUNGHEZZA_NONCE]
    ciphertext = ciphertext_with_iv[LUNGHEZZA_NONCE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, ASSOCIATED_DATA)


""" Fine Sezione hpke """


hex_public_key_controller = "3059301306072a8648ce3d020106082a8648ce3d0301070342000433ae2f4a166047facff332272a48f95f96beb95cea4d47f72bed72125274136369c6c8d354e9d89a4f1143323837a3ce3a5e5a186c226a0ef14ee7437fb2f087"
hex_private_key_h1 = "3041020100301306072a8648ce3d020106082a8648ce3d03010704273025020101042047e1c26472993ae2f90ff88be6a2fc63036f83d34856ad7b53d0722bc0d78afe"
hex_private_key_h2 = "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420800a62931185d4c696f4f9626761969094f8debee8f3210f0f5d3d3e2312e252"
hex_private_key_h3 = "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420abc1c300e2db9096861a23855a60653f0ac2fbbee901cd4a14ec401914d0e086"
hex_private_key_h4 = "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420f5734089e61c5a061e25c1278bc3f7f7fd25655c2f0737a88917eb8162432e90"


"""
Unused

hexPublicKeyH1 = "3059301306072a8648ce3d020106082a8648ce3d0301070342000485ad0eb6edaa7d7d1ce30a38319e9577c8c938519a565a5912037c2a782907fe1acf7fd1d7a80dc5e376817cf94ab2f0f2e9e79b574be956dea50b20a0729ee5"
hexPublicKeyH2 = "3059301306072a8648ce3d020106082a8648ce3d0301070342000498f2c8333abe9d85a1e57516e4459514280e60838f60449825650e4c951ea4cde0a8ba94d155007d90802da259b4a5aaac74cda9c1c7e9b2cfd84d801a908dfb"
hexPublicKeyH3 = "3059301306072a8648ce3d020106082a8648ce3d030107034200041009e90153e15fe741e749b65dd55dcb8d7159680dfe2cea489a5e5497e78bf18c944ec07ddd89eb41031642f38478cb077b7d7dfd5852d2451d95d495c8e0d1"
hexPublicKeyH4 = "3059301306072a8648ce3d020106082a8648ce3d030107034200043bb53d8481c35b9631d301f3c3f37e8310552e43f3ba17d4ea077ea310d19e60ac78298d055cd9dc1dc14192108b70c4ca7bbbe7cce3191bdaeeca1d9ae69d02"
"""


controller_ip = "172.17.0.2"

# Chiave AES (verrà configurata durante l'esecuzione con la chiave effettiva)
PRIVATE_KEY = None
SESSION_KEY = None


def seleziona_chiavi(host):
    global PRIVATE_KEY
    global SESSION_KEY
    if host.strip() == 'h1':
        SESSION_KEY = genera_chiave_di_sessione(converti_chiave_privata(hex_private_key_h1), converti_chiave_pubblica(hex_public_key_controller))
    if host.strip() == 'h2':
        SESSION_KEY = genera_chiave_di_sessione(converti_chiave_privata(hex_private_key_h2), converti_chiave_pubblica(hex_public_key_controller))
    if host.strip() == 'h3':
        SESSION_KEY = genera_chiave_di_sessione(converti_chiave_privata(hex_private_key_h3), converti_chiave_pubblica(hex_public_key_controller))
    if host.strip() == 'h4':
        SESSION_KEY = genera_chiave_di_sessione(converti_chiave_privata(hex_private_key_h4), converti_chiave_pubblica(hex_public_key_controller))


# Funzione per gestire i pacchetti ICMP
def handle_packet(packet):

    # Verifica se è un ICMP Echo Request del controller
    if scapy.ICMP in packet and packet[scapy.ICMP].type == 0 and packet[scapy.IP].src == controller_ip:  
        
        # Controller --> Host
        
        print(f"Ricevuto Pacchetto di Probing da {controller_ip}.. verifico l'autenticità")
        try:

            testo_cifrato = packet[scapy.Raw].load
            testo_in_chiaro = decifra_messaggio(testo_cifrato, SESSION_KEY)
            print(f"Messaggio decifrato con successo: {testo_in_chiaro}")
            if not testo_in_chiaro == b"pr0b1ng":
                print("Errore: il testo_in_chiaro non è quello atteso")
                # errore, la decifratura non coincide, genera un'eccezione (non so come si fa)
                return 
        except Exception as e:
            print(e)
            print("Errore in fase di decodifica del Payload di probing. Terminazione Programma.")
            exit()

        # Host --> Controller

        print(f"{controller_ip} autenticato. Invio Pacchetto di Probing in risposta...")

        # Inviamo una risposta
        encrypted_data = cifra_messaggio(testo_in_chiaro, SESSION_KEY)
        
        eth_layer = scapy.Ether(dst=packet.src)
        ip_layer = scapy.IP(dst=controller_ip)
        icmp_layer = scapy.ICMP(type=0)  # Type 0 indica Echo Reply
        
        icmp_payload = b'PROBING' + encrypted_data
        reply_packet = eth_layer / ip_layer / icmp_layer / scapy.Raw(load=icmp_payload)
        
        # Inviare il pacchetto di Probe in risposta
        scapy.sendp(reply_packet)
        
        
# Filtra i pacchetti ICMP in ingresso
def start_sniffing():
    scapy.sniff(filter="icmp", prn=handle_packet)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, required=True, help="host su cui eseguire il probing")
    args = parser.parse_args()
    # Assegnamo le chiavi giuste all'host corrente
    seleziona_chiavi(args.host)
    # Restiamo in ascolto di pacchetti di probing
    start_sniffing()
