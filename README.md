# Analisi di sicurezza per reti SDN e Host Tracking Service con controller ONOS
Questo repository contiene gli strumenti utilizzati durante lo svolgimento di un'analisi di sicurezza sul controller per SDN **ONOS**, comprendendo anche i risultati ottenuti. L'oggetto dell'attacco è l'*Host Tracking Service*, componente comune a tutte le SDN che in ONOS è implementato con il nome di *Host Location Provider*. In particolare l'analisi si concentra su attacchi di tipo *Cross-App Poisoning* ovvero attacchi che tramite un'applicazione malevola esterna sfruttano i privilegi di una o più applicazioni interne del controller per avvelenare il corretto funzionamento della rete.

Per realizzare gli esperimenti è stata usata una topologia di riferimento creata con **Mininet** composta da quattro hosts e due switches come mostrato nella seguente figura. Nella figura compare anche un quinto host che funge da nat per consentire agli host della rete di connettersi a Internet. L'introduzione del nat è stata utile per implementare un ulteriore vettore di attacco che permette di raggiungere lo stesso scopo del Cross-App Poisoning attraverso chiamate http (o in generale API REST) andando a sfruttare la maggiore priorità dell'componente *Network Config Listener* di ONOS rispetto all'*Host Location Provider* oppure *Host Tracker Service* per avvelenare in maniera permanente l'*Host Data Store*:

![topologia](./progettoNetwork/immagini%20e%20grafici/topologia.png)

Quando la topologia viene avviata permette di effettuare una prima scelta per esprimere la volontà di avviare la rete in maniera sicura o meno. Se si sceglie di avere sicurezza viene posta una seconda scelta, entrambe le scelte forniscono una implementazione sicura dell'Host Location Provider tramite un'applicazione ONOS custom, la differenza sta nel tipo di crittografia utilizzata per autenticare gli host: la prima soluzione utilizza un **Authenticated Encryption with Associated Data con AES_GCM** mentre la seconda utilizza **Hybrid Public Key Encryption**. 

Indipendentemente dal tipo di sicurezza scelta viene attivato anche un meccanismo di proxy sull'host nat (che si assume per ipotesi essere un host fidato all'interno della rete) viene attivato un meccanismo di proxy che controlla le richieste che gli host fanno verso l'esterno, se sono richieste benevole vengono fatte passare verso il controller altrimenti vengono bloccate e scartate dal nat stesso.
Se invece si sceglie di avviare la rete in maniera non sicura si avvia la topologia con tutte le sue vulnerabilità utilizzando l'Host Location Provider predefinito di ONOS.

## Attacchi 
Per quanto riguarda la realizzazione degli attacchi, l'idea è stata quella di implementare il Cross App Poisoning come punto di partenza per un Man In The Middle in cui l'attaccante, che negli esperimenti è stato l'host H2, può intercettare e leggere il traffico delle vittime, gli hosts H1 e H3 in questo caso.

L'attacco ***hts_poisoning*** si occupa di avvelenare l'Host Location Provider attraverso l'invio di pacchetti ICMP: l'host H2 (l'attaccante) invia un pacchetto ad H1 fingendo di essere H3. L'Host Location Provider a questo punto vedendo che il pacchetto inviato ha come sorgente H3 e che la location (porta dello switch) da cui parte questo pacchetto non coincide con la vecchia location di H3 pensa che H3 ha cambiato posizione per cui la aggiorna erroneamente con quella di H2 permettendo in questo a quest'ultimo di leggere tutte le conversazioni che dovrebbero arrivare all'host H3.

L'attacco di ***arp_poisoning*** invece sfrutta una vulnerabilità di Address Resolution Protocol che permette all'attaccante di avvelenare le tabelle ARP delle vittime inviando pacchetti di ARP-Reply senza che in precedenza sia stata effettuata una ARP-Request: H2 può inviare ad H1 un pacchetto in cui dice che l'IP di H3 si trova all'indirizzo MAC di H2. Allo stesso modo H2 invia ad H3 un pacchetto in cui dice che l'IP di H1 si trova all'indirrizzo MAC di H2. In questo modo quando H1 vuole comunicare con H3 o viceversa H2 può leggere la comunicazione per poi fare forwarding del pacchetto al destinatario corretto.

L'attacco di ***mitm*** invece implementa la logica del Cross-App Poisoning tramite chiamate HTTP al controller. In pratica H2 effettua una richiesta POST all'Network Config Listener per sfruttare la sua maggiore priorità rispetto all'Host Location Provider in cui chiede di cambiare la location dell'host H3 con la sua. In questo modo anche se H3 dovesse immettere pacchetti nella rete l'Host Location Provider non è in grado di risistemare la sua location. A questo punto se qualcuno, ad esempio H1, cerca di inviare un messaggio ad H3, lo invierà invece ad H2, che dopo averlo letto effettua un'altra richiesta HTTP per risistemare la posizione di H3 e inoltrargli il pacchetto. Allo stesso modo H2 cambierà le posizioni di H1 per spiare e chiudere l'intera comunicazione e in modo silenzioso senza che le due parti se ne accogano.

## Difesa
Per difendere gli attacchi all'Host Location Provider sono state realizzate due applicazioni ONOS custom che differiscono solo per il meccanismo di sicurezza utilizzato mentre per l'attacco tramite chiamate API REST è stato implementato un proxy che verifica l'autenticità e la bontà del pacchetto tramite un meccanismo di firma digitale.

L'***AppMitmDetection*** è un'applicazione ONOS custom modificata dell'Host Location Provider che implementa il meccanismo di Diffie-Hellman per lo scambio delle chiavi tra controller e host. In par ticolare per un host e un controller vengono utilizzate 2 chiavi, una per la comunicazione HOST --> CONTROLLER e l'altra per la comunicazione inversa: CONTROLLER --> HOST in modo da evitare *Reflection Attack*. Tale metodologia crittografica risulta utile per implemetare un meccanismo di probing sugli host per sapere quali di loro sono ancora attivi all'interno della rete in modo da evitare che quando un host si disconnette qualcun altro possa appropriarsi della sua posizione in maniera illegittima. Per fare ciò ogni il controller invia ad ogni host un ICMP Reply cifrata con la chiave di sessione di quell'host, se l'host non risponde il messaggio viene re-inviato dal controller e se si arriva ad una mancata risposta per tre messaggi di fila l'host viene considerato inattivo e viene rimosso dalla rete. Se invece il controller ottiene una risposta identifica l'host tramite il suo mac e prova a decifrare il messaggio usado la chiave condivisa con il mac da cui ha ricevuto la risposta, se riesce a decifrare vuol dire che la risposta è stata cifrata dall'host corretto, altrimenti rileva un tentativo di furto di identità e blocca il pacchetto.
Per quanto riguarda l'attacco con i pacchetti ARP tramite uno snapshot di rete aggiornato si identifica l'IP del mittente e si va a controllare dentro lo snapshot se questo IP è associato alla location che si sta cercando di modificare, se non è così si rileva un tentativo di attacco e il mittente viene buttato fuori dalla rete.
Per quanto riguarda invece l'attacco tramite pacchetto IP si va a cercare nello snapshot una corrispondenza tra la location e l'indirizzo MAC del mittente, se questa corrispondeza non viene trovata allora si rileva un attacco è il mittente del pacchetto viene sbattuto fuori.

L'***AppMitmDetection2*** è un'applicazione analoga alla precedente. Anch'essa è una versione sicura dell'Host Location Provider di ONOS e, come AppMitmDetection, include un meccanismo per lo scambio di pacchetti di probing tra host e controller che segue la stessa logica. La differenza rispetto all'app precedente consiste nel modo in cui viene effettuata l'operazione di probing: AppMitmDetection2 utilizza come schema di cifratura HPKE (Hybrid Public Key Encryption), basato sull'idea che ogni host e il controller posseggano una coppia di chiavi, pubblica e privata. In particolare, non è più presente una fase di scambio delle chiavi; la cifratura vera e propria dei messaggi invece utilizza anche in quest caso AEAD.

***mitm_detection*** è uno script python che viene eseguito sull'host nat0 al momento dell' avvio della rete fino alla terminazione dell'intera topologia. Il suo scopo è proteggere le api Rest da potenziali richieste malevole. Per realizzare ciò, lo script crea un proxy che si mette in ascolto delle richieste HTTP indirizzate al controller. Quando ne riceve una, ne verifica la provenienza tramite firma digitale (anche in questo scenario ciascun host e il controller possegono una coppia di chiavi, pubblica e privata), scartando le richieste di cui non riesce a identificare il mittente. Se la provenienza della richiesta è legittima, viene successivamente analizzato il contenuto del body. Se esso contiene modifiche potenzialmente dannose per la rete, la richiesta HTTP viene scartata e l'attaccante espulso dalla rete. Al contrario, le richieste legittime verranno inoltrate al controller. 

## Guida installazione e utilizzo del progetto
Per tutti i dettagli sull'ambiente utilizzato e sull'installazione e utilizzo del progetto si rimanda al [README](www.readme.com) interno

## Autori
- [Domenico Carreri](https://github.com/Domenico1106)
- [Giuseppe Cavallo](https://github.com/Giugiugit)
