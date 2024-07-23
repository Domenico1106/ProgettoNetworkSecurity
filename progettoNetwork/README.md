# Istruzioni per il corretto utilizzo e funzionamento del progetto di Network Security di Carreri-Cavallo

**+++NOTA BENE**: L'immagine della VM contiene già tutto il necessario per eseguire i file sorgenti del progetto. I file sono già compilati e pronti ad essere eseguiti. Il seguente è un resoconto che comprende: le operazioni da compiere per utilizzare il progetto, le operazioni che sono state effettuate per permettere l'esecuzione del progetto e infine una descrizione dei file contenuti nel repository.

## Come utilizzare il progetto:

1. Avviare da un terminale il container docker con il comando 
```bash
docker start onos
```
2. In un secondo terminale, eseguire il comando 
```bash 
docker logs -f onos
```
3. Il controller necessita di diversi secondi per avviarsi correttamente, è possibile seguire l'operazione attraverso il terminale dei logs avviato nel punto 2.
4. Quando il container si sarà avviato correttamente, sarà possibile visualizzare la pagina web [http://172.17.0.2:8181/onos/ui/#/topo2](http://172.17.0.2:8181/onos/ui/#/topo2)
5. Le credenziali per accedere alla pagina sono >> username: 'onos' e password: 'rocks'.
6. Usando il terminale del punto 1, spostarsi nella cartella 'progettoNetwork' con il comando 
```bash 
cd progettoNetwork
```
7. Avviare la topologia Mininet utilizzando il comando 
```bash 
sudo python3 topologia.py
```
8. Verrà chiesto se si vuole utilizzare la rete includendo le misure di sicurezza o meno. L'opzione *n* permette di eseguire ONOS nella sua versione originale e vulnerabile. L'opzione *'y'* o *'Y'* o ' ' permette di includere le applicazioni custom che implementano le misure di sicurezza.
9. Verrà chiesto se si desidera utilizzare la versione con **AEAD** e *AES_GCM* (scelta **1**), o la versione che usa **HPKE**(scelta **2**). Entrambe le versioni difendono la rete dagli attacchi all'Host Tracking Service, la differenza tra le due sta nel modo in cui effettuano le operazioni di Host Probing.
11. Dopo aver effettuato una scelta, Mininet creerà la topologia e partirà la CLI. Adesso è possibile simulare gli attacchi alla rete.

**+++ NOTA**: Tutti gli attacchi previsti considerano come attaccante di default H2. +++

12. Gli attacchi a disposizione sono 3: `arp_poisoning.py`, `hts_poisoning.py` e `mitm.py`. Esiste infine `mitm_unsafe.py`, che è un'alternativa di `mitm.py`

**+++ NOTA BENE**: Se i meccanismi di difesa *NON* sono attivi (si è scelto **'n'** nel punto **8.**, `mitm.py`non sarà utilizzabile. Al suo posto bisognerà usare `mitm_unsafe.py`

13) Ciascun attacco si esegue in questo modo: tramite la CLI di Mininet, si avvia *xterm* sull'host attaccante (H2 nei nostri esperimenti) usando il comando: 
```bash 
h2 xterm &
```
14) Una volta aperto xterm su H2, lanciare l'attacco con il comando: 
```bash 
python3 attacco/nome_attacco.py
```
**+++NOTA**: per eseguire `mitm.py`sarà necessario usare il comando: 
```bash 
python3 attacco/mitm.py --host h2
```
15) Se le difese sono attive, gli attacchi non andranno a buon fine. Nei log di ONOS compariranno degli avvisi riguardo i tentativi di attacco.
16) Il progetto è configurato su per eseguire attacchi su una topologia statica e nota all'attaccante (**H2**). Se si necessita di modificare gli attacchi attenersi alla topologia modificare il codice sorgente di `mitm.py`e `mitm_unsafe.py`

## Passaggi effettuati per configurare l'ambiente in cui sviluppare ed eseguire il progetto:

### Configurazione ambiente virtuale:

Per realizzare il progetto è stata utilizzata una macchina virtuale che monta il sistema operativo Linux Ubuntu 20.04.6 LTS (Local Fossa) scarcabile al seguente indirizzo: [Ubuntu 20.04.6 LTS](https://releases.ubuntu.com/focal/ubuntu-20.04.6-desktop-amd64.iso)
L'hypervisor utilizzato per la macchina virtuale è VmWare Workstation (quindi la versione per sistemi operativi Windows o Linux)

### Mininet:

Trattandosi di una rete SDN si è deciso di utilizzare l'emulatore di rete Mininet ottenibile facendo la clone del repository utilizzando git: 
```bash 
git clone https://github.com/mininet/mininet.git
```
Scaricato il repository mininet può essere installato seguendo i seguenti passi:
```bash 
cd mininet/util
chmod +x install.sh
sudo PYTHON=python3 ./install.sh -a
``` 
Per avviare mininet si può utilizzare il comando `sudo mn` oppure, come fatto durante il progetto, si può creare un programma Python che utilizza le API di mininet per realizzare topologie di rete più specifiche e complesse.

### Controller ONOS:

Dopo aver installato l'emulatore Mininet si è deciso di utilizzare come controller ONOS nella sua versione 2.7.0, in particolare si è deciso di utilizzare per semplicità e leggerezza un container Docker del controller. Per installare Docker è stata seguita la guida presente al seguente link: [Guida Docker](https://docs.docker.com/engine/install/ubuntu/)
In seguito per poter eseguire docker senza dover per forza usare il comando 'sudo' è stato aggiunto un docker group al sistema come specificato in questa ulteriore guida:
[Post Installazione Docker](https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user)

Per utilizzare il controller nella versione 2.7.0 per prima cosa è stata pullata la sua
immagine:
```bash 
docker pull onosproject/onos:2.7.0
```
A questo punto l'immagine è stata lanciata abilitando le porte di default di onos e la
porta SSH(22) mappata sulla porta locale 2200 in quanto è risultato utile utilizzare SSH per lo sviluppo del progetto.
Il comando usato per lanciare l'immagine è:
```bash
docker run -d --name onos -p 8181:8181 -p 2200:22 <id_immagine>
```
Creato il container può essere semplicemente avviato e stoppato con i comandi:
```bash 
docker start onos
docker stop onos
```

Dopo aver avviato il container, è necessario attivare alcune applicazioni preinstallate in onos ma che di default sono disattivate. 
Al primo avvio, le uniche applicazioni attive saranno:
  - **Default Drivers**
  - **Onos GUI2**
  - **Optical Network Model**

Le applicazioni da attivare in seguito sono:
  - **Reactive Forwarding**
  - **OpenFlow Base Provider**
  - **LLDP Link Provider**
  - **Host Location Provider**
  
Sarà sufficiente attivare queste applicazioni solo una volta, poiché rimarrano attive anche durante le successive esecuzioni del container.

Per poter inoltre compilare ed utilizzare correttamente tutte le dipendenze delle applicazioni custom ONOS è necessario installare il comando `make` e `maven` con i successivi comandi: 
```bash
apt install maven
apt install make
```
### Abilitare il controller all'utilizzo di SSH

La prima volta che il container viene avviato non possiede le informazioni possibili per poter utilizzare SSH per cui sono state aggiunte manualmente.
Per prima cosa è stato necessario aprire una shell all'interno del controller utilizzando il comando: 
```bash 
docker exec -it onos /bin/bash
```
All'interno della shell è stata cambiata la password per l'account di root in modo da conoscerla e poterla utilizzare in caso di successivi accessi futuri: `passwd root` e poi inserire la password desiderata.
Dopo aver settato la password è stato necessario scaricare il server ssh:
```bash
apt update
apt install openssh-server -y
```
Installato il server SSH non è ancora pronto, vanno modificati i parametri di configurazione. Per poterli modificare è stato necessario installare un editor di testo come ad esempio vim:
```bash
apt install vim -y
vim /etc/ssh/sshd_config
```
All'interno del file sshd_config bisogna aggiungere la seguente riga nella sezione di autenticatione: `PermitRootLogin yes`

Per salvare le modifiche ed uscire dall'editor premere `ESC` e successivamente `:wq`

A questo punto il servizio ssh può essere abilitato attraverso il comando
```bash
service ssh start
```
Fatta questa cosa si può uscire dal container con il comando `exit` e per entrare con ssh si può lanciare il comando
```bash 
ssh root@localhost -p 2200
```
Inserire poi la password che era stata scelta nei passi precedenti.
Per semplicità nella modifica del codice dei file sul container è stato sfruttato l'accesso ssh tramite l'estensione *RemoteSSH* di Visual Studio Code.

**I passi del paragrafo precedente vanno fatti solo la prima volta**, da questo momento in poi ogni volta che il container viene avviato per poter utilizzare ssh bastano solo i successivi comandi:
```bash
docker exec -it onos /bin/bash  # dalla shell del utente
service ssh start  # dalla shell del controller
exit  # dalla shell del controller
```

## Descrizione degli script e dei file contenuti nella cartella

### Descrizione Script:
- **Python**:
  - ***arp_poisoning.py***: la classe permette a chi la esegue di effettuare un MITM tra due host avvelenando i dati delle loro tabelle ARP. Una volta finito l'attacco lo script risistema le tabelle in modo che le vittime non si accorgano di nulla.
  - ***hts_poisoning.py***: l'attaccante (ad esempio H2) che esegue questa classe cerca di ingannare l'Host Location Provider del controller inviando pacchetti di ping ad un host (ad esempio H1) impersonificando un altro host (ad esempio H3) inserendo come ip e mac sorgente del pacchetto proprio quelli di H3.
  - ***host_probing_aead.py***: questa applicazione serve agli host della rete per inoltrare un heartbeat di probing verso il controller per notificare quest ultimo della loro presenza all'interno della rete. L'host che usa la classe si mette in ascolto sulla sua interfaccia di rete di pacchetti ICMP di tipo reply. Inizialmente avviene una fase di scambio delle due chiavi di comunicazioni, (una per la comunicazione Host --> Controller, l'altra per la comunicazione Controller --> Host), usando il protocollo di Diffie-Hellman. Scambiate le chiavi vengono messi a disposizione un meccanismo di cifratura del pacchetto di probing da inviare e un meccanismo di decifratura del pacchetto di probing ricevuto.
  - ***host_probing_hpke.py***: l'applicazione è simile alla precedente, tuttavia non comprende uno scambio delle chiavi ma si utilizza una combinazione di crittografia simmetrica ed asimmetrica; Ogni host genera la sua chiave di sessione (simmetrica) con il controller combinando la sua chiave privata (asimmetrica) con la chiave pubblica del controller in modo tale che quando arriva il probing, se riesce a decifrarlo tale chiave di sessione, è sicuro che proviene dal controller in quanto il controller genera la stessa chiave di sessione usando la chiave pubblica dell'host e quella privata del controller stesso che solo lui possiede.
  - ***location_poisoning.py***: è una classe di utilità che implementa i metodi usati dalla classe mitm_unsafe per sfruttare il fatto che il controller da più priorità al Network Config Listener e quindi permettere un MITM tramite richieste HTTP o in generale API REST.
  - ***mitm.py***: riceve come parametro l'host che la sta avviando per assegnare utilizzare la giusta coppia di chiavi. Chiavi asimmetriche che servono ad implementare un meccanismo di firma digitale, in quanto è stato pensato di utilizzare il nat come proxy per inoltrare le richieste dalla rete interna al controller. L'host che esegue la classe effettua il suo tentativo di attacco inviando un payload malevolo cifrato con la sua chiave privata al nat. Sarà poi il nat a verificare l' autenticità della richiesta ed eventuali controlli alla sicurezza del payload.
  - ***mitm_detection.py***: difesa contro gli attacchi della classe mitm.py, deve essere eseguito dal nat che per assunzione è l'host fidato della rete. Questa classe implementa un meccanismo di firma digitale per cui quando riceve il pacchetto da un host va a controllare l'ip del mittente del pacchetto. Sulla base di questo indirizzo sceglie con quale chiave pubblica decifrare il pacchetto: se la decifratura va a buon fine allora è verificata l'integrità, l'autenticazione e il non ripudio del pacchetto, altrimenti il mittente non è chi dice di essere e il pacchetto viene scartato. Nel caso in cui il pacchetto viene decifrato correttamente il nat effettua controlli sul payload della richiesta, se la ritiene malevola non la invia al controller, altrimenti effettua il forward.
  - ***mitm_unsafe.py***: classe usata dagli host per implementare il MITM sfruttando le API REST L'attaccante scambia la location dell'host che vuole spiare con la sua,  legge i suoi messaggi, risistema la location dell'host nella posizione corretta e gli inoltra il pacchetto. A questo punto fa la stessa cosa con l'host mittente in modo da spiare l'intera comunicazione in maniera silenziosa. Quando finisce l'attacco risistema le posizioni.
  - *topologia.py*: classe che si occupa di avviare la topologia. L'utente in questo caso può fare due scelte:
    1. Avviare la topologia in maniera unsafe usando l'Host Location Provider originale di onos;
    2. Avviare la topologia in maniera sicura facendo partire il meccanismo di proxy da parte del nat. In questo caso si possono effettuare ulteriori due scelte:
        - Usare come meccanismo di crittografia del Probing AEAD_GCM con lo scambio delle chiavi realizzato con Diffie Hellman;
        - Usare come meccanismo di crittografia del Probing HPKE utilizzando dunque una combinazione tra crittografia asimmetrica e crittografia simmetrica.


- **Java**:
  - ***mitm-detection-app***: custom app per ONOS che incorpora tutte le funzionalità dell'applicazione *Host Location Provider* già presente di default in ONOS e le estende implementando dei meccanismi di sicurezza per rilevare e scartare pacchetti che potrebbero alterare illegamente lo stato della topologia, espellendo l'attaccante dalla rete. Include un meccanismo di Host Probing per cui ogni 20 secondi il controller verifica lo stato di attività degli hosts. Implementa un doppio scambio di chiavi tra host e controller tramite Diffie-Hellman per evitare i Reflection Attacks, e utilizza lo schema di cifratura AEAD (Authenticated Encryption with Associated Data) per consentire lo scambio dei messaggi di Probe tra Host e Controller.

  - ***mitm-detection-app2***: custom app per ONOS che incorpora tutte le funzionalità dell'applicazione *Host Location Provider* già presente di default in ONOS e le estende implementando dei meccanismi di sicurezza per rilevare e scartare pacchetti che potrebbero alterare illegamente lo stato della topologia, espellendo l'attaccante dalla rete. Include un meccanismo di Host Probing per cui ogni 20 secondi il controller verifica lo stato di attività degli hosts. Si utilizza come schema di cifratura HPKE (Hybrid Public Key Encryption). Ogni Host e il Controller dispongono di una coppia chiave pubblica e privata. Lo schema di cifratura è AEAD (Authenticated Encryption with Associated Data).


- **Bash**:
  - ***compile.sh***: script per compilare mitm-detection-app e mitm-detection-app2 tramite Maven. Richiede un parametro (1 o 2) per stabilire quale progetto compilare.
  - ***install.sh***: script per installare le custom app mitm-detection-app e mitm-detection-app2. Richiede un parametro (1 o 2) per stabilire quale progetto installare. Da utilizzare se l'app NON è stata installata precedentemente.
  - ***reinstall.sh***: script per re-installare le custom app mitm-detection-app e mitm-detection-app2. Richiede un parametro (1 o 2) per stabilire quale progetto installare. Da utilizzare se l'app è stata installata precedentemente.
