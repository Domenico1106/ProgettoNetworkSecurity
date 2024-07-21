# Titolo progetto 
L'obiettivo di questo progetto è quello di illustrare meccanismi di attacco e proporre delle mitigazioni in un ambiente composto da una topologia di rete SDN gestita da un controller remoto ONOS.


## Mininet
Trattandosi di una rete SDN si è deciso di utilizzare l'emulatore di rete Mininet che può essere installato nel seguente modo su un ambiente Linux basato su Debian:
```bash
git clone https://github.com/mininet/mininet.git
cd mininet/util
chmod +x install.sh
./install.sh -a
```
L'emulatore va avviato usando il comando `sudo mn` oppure, come fatto per il progetto, utilizzare la libreria python di mininet per creare una topologie complesse ed eseguire operazioni.
Per valutare gli esperimenti è stata utilizzata una topologia di rete composta da quattro hosts e due switches tuttavia nell'analisi delle prestazioni e delle metriche sono state introdotto anche altre topologie con numero di hosts e swithces differenti. È stato inoltre introdotto un quinto hosts che funge da nat per permettere agli host della rete di comunicare con l'esterno. La topologia usata è mostrata nell'immagine seguente: 
![topologia](./immagini%20e%20grafici/topologia.png/)

## Controller ONOS
Come citato in prececdenza è stato utizzato come controller ONOS, in particolare la sua versione 2.7.0. Piuttosto che creare una VM a parte per il controller è stato utilizzato il suo container Docker per cui per poterlo utitizzare si è dovuto fare la pull dell'immmagine. Per la creazione del container si è ritenuto utile abilitare oltre che alle porte predeinite usate da onos anche la porta SSH (22) mappata sulla porta locale 2200 per facilitare lo sviluppo di applicazioni onos custom per l'implementazione della difesa. 
Per scaricare l'immagine e costruire il container si possono usare i seguenti passi: 
```bash
docker pull onosproject/onos:2.7.0
docker run -d --name onos -p 6640:6640, -p 6653:6653 -p 6653:6653 -p 9876:9876 -p 8181:8181 -p 2200:22 onosproject/onos
```
Mentre per avviare e stoppare il container: 

```bash
docker stop onos
docker start onos
```
Il controller di default non abilita SSH per cui bisogna entrare nel controller con il comando seguente, dalla shell del controller scaricare il server SSH e settare le configurazioni perr accettare richieste in ingresso.
```bash
docker exec -it onos /bin/bash
```
## Descrizione classi
Nel progetto sono state implementate diverse soluzioni di attacco e di difesa. Gli attacchi sono stati fatti tutti utilizzando il linguaggio Python, mentre per quanto riguarda la difesa ne è stata fatta una in Python e due in Java come applicazioni ONOS custom.
In particolare gli attacchi seguono la seguente logica: 
1. Sfruttare 
