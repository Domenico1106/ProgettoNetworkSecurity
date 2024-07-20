# Titolo progetto 
L'obiettivo di questo progetto è quello di illustrare meccanismi di attacco e proporre delle mitigazioni in un ambiente composto da una topologia di rete SDN gestita da un controller remoto ONOS.
Il principale attacco trattato è il CROSS-APP POISONING il quale permette ad una applicazione malevola con scarsi privilegi all'interno del controlle di sfruttare una seconda applicazione con privilegi più elevati per effetuare operazioni che non dovrebebro essergli permesse. Il Cross-App è stato un punto di accesso fondamentale che ha permesso di implementare diversi modi di effettuare Man In The Middle. 
## Mininet
Trattandosi di una rete SDN si è deciso di utilizzare l'emulatore di rete Mininet che può essere installato nel seguente modo:

```git
git clone https://github.com/mininet/mininet.git
```
