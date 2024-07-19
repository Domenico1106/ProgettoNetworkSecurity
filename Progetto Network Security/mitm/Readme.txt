Istruzioni per il corretto utilizzo e funzionamento del Progetto di Network Security di Carreri-Cavallo

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
NOTA BENE: L'immagine della VM contiene già tutto il necessario per eseguire i file
           sorgenti del progetto. I file sono già compilati e pronti ad essere eseguiti.
           Il seguente è un resoconto delle operazioni che sono state effettuate per
           permettere l'esecuzione del progetto.
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

UTILIZZARE IL PROGETTO:

) Avviare da un terminale il container docker con il comando 'docker start onos'.
) In un secondo terminale, eseguire il comando 'docker logs -f onos'.
) Il controller necessita di diversi secondi per avviarsi correttamente, è possibile seguire l'operazione attraverso il terminale dei logs.
) Quando il container si sarà avviato correttamente, sarà possibile visualizzare la pagina web "http://172.17.0.2:8181/onos/ui/#/topo2"
) Le credenziali per accedere alla pagina sono username: 'onos' e password: 'rocks'.
) Usando il terminale del punto 1), spostarsi nella cartella 'mitm' con il comando 'cd mitm'.
) Avviare la topologia Mininet utilizzando il comando 'sudo python3 topologia.py'.
) Verrà chiesto se si vuole utilizzare la rete includendo le misure di sicurezza o meno.
) L'opzione 'n' permette di eseguire ONOS nella sua versione originale e vulnerabile.
) L'opzione 'y' o 'Y' o ' ' permette di includere le applicazioni custom che implementano le misure di sicurezza.
) Verrà chiesto se si desidera utilizzare la versione con AEAD e AES_GCM (1), o la versione che usa HPKE(2).
) Entrambe le versioni difendono la rete dagli attacchi all'Host Tracking Service, la differenza sta nel modo in cui effettuano le operazioni di Host Probing.
) Dopo aver effettuato una scelta, Mininet creerà la topologia e partirà la CLI.
) Adesso è possibile simulare gli attacchi alla rete.
) Gli attacchi a disposizione sono 4: arp_poisoning.py, hts_poisoning.py, mitm.py e mitm_unsafe.py
) Ciascun attacco si esegue in questo modo: utilizzando la CLI di Mininet, si avvia xterm sull'host attaccante (H2 nei nostri esperimenti) usando il comando: 'h2 xterm &'
) Una volta aperto xterm su H2, lanciare l'attacco con 'python3 nome_attacco.py'
) Se le difese sono attive, gli attacchi non andranno a buon fine


CONFIGURAZIONE AMBIENTE VIRTUALE:

    Per realizzare il progetto è stata utilizzata una macchina virtuale che monta il sistema operativo Linux Ubuntu 20.04.6
    LTS (Local Fossa) scarcabile al seguente indirizzo: https://releases.ubuntu.com/focal/ubuntu-20.04.6-desktop-amd64.iso
    L'hypervisor utilizzato per la macchina virtuale è VmWare Workstation (quindi la versione per sistemi operativi Windows)
    il cui client è scaricabile a questo link:

MININET:

    Trattandosi di una rete SDN si è deciso di utilizzare l'emulatore di rete Mininet ottenibile facendo la clone
    del repository utilizzando git:
        git clone https://github.com/mininet/mininet.git
    Scaricato il repository mininet può essere installato seguendo i seguenti passi:
        cd mininet/util
        chmod +x install.sh
        ./install.sh -a

    Per avviare mininet si può utilizzare il comando sudo mn oppure, come fatto durante il progetto, si può creare un
    programma Python che utilizza le API di mininet per realizzare topologie di rete più specifiche e complesse.


CONTROLLER ONOS:

    Dopo aver installato l'emulatore Mininet si è deciso di utilizzare come controller ONOS nella sua versione 2.7.0,
    in particolare si è deciso di utilizzare per semplicità e leggerezza un container Docker del controller.
    Per installare Docker è stata seguita la guida presente al seguente link : https://docs.docker.com/engine/install/ubuntu/
    In seguito per poter eseguire docker senza dover perforza usare il comando 'sudo' è stato aggiunto un docker group
    al sistema come specificato in questa ulteriore guida: https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user.

    Per utilizzare il controller nella versione 2.7.0 per prima cosa è stata pullata la sua immagine:
        docker pull onosproject/onos:2.7.0
    A questo punto l'immagine è stata lanciata abilitando le porte di default di onos e la porta SSH(22) mappata sulla porta
    locale 2200 in quanto è risultato utile utilizzare SSH con lo sviluppo del progetto.
    Il comando usato per lanciare l'immagine è:
        docker run -d --name onos -p 6640:6640, -p 6653:6653 -p 6653:6653 -p 9876:9876 -p 8181:8181 -p 2200:22 onosproject/onos.
    Creato il container può essere semplicemente avviato e stoppato con i comandi:
        docker start onos
        docker stop onos

Abilitare il controller all'utilizzo di SSH:

    La prima volta che il container è stato avviato non possedeva le informazioni possibili per poter utilizzare SSH per cui
    sono state aggiunte manualmente.
    Per prima cosa è stato necessario aprire una shell all'interno del controller utilizzando il comando:
        docker exec -it onos /bin/bash
    All'interno della shell è stata cambiata la password per l'account di root in modo da conoscerla e poterla utilizzare in
    caso di successivi accessi futuri:
        passwd root
    Dopo aver settato la password è stato necessario scaricare il server ssh:
        apt update
        apt install openssh-server -y
    Installato il server SSH non è ancora pronto, vanno modificati i parametri di configurazione. Per poterli modificare è
    stato necessario installare un editor di testo come ad esempio vim:
        apt install vim -y
        vim /etc/ssh/sshd_config  --> all'interno del file sshd_config bisogna aggiungere la seguente riga nella sezione di autenticatione:
                                        PermitRootLogin yes
                                      Per salvare le modifiche ed uscire dall'editor premere ESC e successivamente :wq

    A questo punto il servizio ssh può essere abilitato attraverso il comando
        service ssh start
    Fatta questa cosa si può uscire dal container con il comando 'exit' e per entrare con ssh si può lanciare il comando
        ssh root@localhost
        --> Inserire qui la password che era stata scelta nei passi precedenti
    Per semplicità nella modifica del codice dei file sul container è stato sfruttato l'accesso ssh tramite l'estensione "RemoteSSH" di VSCode

I passi del paragrafo precedente vanno fatti solo la prima volta, da questo momento in poi ogni volta che il container
viene avviato per poter utilizzare ssh bastano solo i successivi comandi:
    docker exec -it onos /bin/bash  # dalla shell del utente
    service ssh start  # dalla shell del controller
    exit  # dalla shell del controller



