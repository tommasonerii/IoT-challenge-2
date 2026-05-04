# Analisi Completa – IoT Challenge #2

## Verifica Eseguita

Ho fatto tre livelli di controllo:
1. **Code review** – analisi logica di tutti gli 8 script
2. **Esecuzione** – run di tutti gli script con `conda run -n iot-challenge`
3. **Verifica indipendente** – query tshark dirette con logica alternativa per cross-controllare ogni risultato

> [!IMPORTANT]
> **Aggiornamento interpretativo applicato.** CQ1b e CQ3b usano ora la verifica effettiva del risultato nella traccia; gli script e il report sono stati aggiornati.

---

## Riepilogo Risultati Confermati

| Domanda | Risposta | Stato |
|---------|----------|-------|
| CQ1a | MID 30800 | ✅ Confermato |
| CQ1b | 0 | Aggiornato: GET successiva a `/validate` torna `2.05 Content`, non `4.04 Not Found` |
| CQ2 | 1 (`/dining_room`: POST=1, PUT=1) | ✅ Confermato |
| CQ3a | 10 | ✅ Confermato |
| CQ3b | 5 | Aggiornato: notifiche CON con ICMP Port Unreachable |
| CQ4 | 0 | ✅ Confermato |
| CQ5 | 1 | ✅ Confermato |
| CQ6a | 5 | ✅ Confermato |
| CQ6b | 2 | ✅ Confermato |
| CQ7 | 9 | ✅ Confermato |
| CQ8a | 439 | ✅ Confermato |
| CQ8b | 534 | ✅ Confermato |

---

## Dove il Tuo Amico Potrebbe Aver Sbagliato

Ho testato tutte le interpretazioni alternative più comuni. Ecco le "trappole" con i numeri sbagliati che se ne ricavano:

### CQ1b – Fermarsi alla risposta DELETE

La risposta `2.02 Deleted` basta per CQ1a, ma CQ1b richiede il risultato finale del DELETE. La GET successiva allo stesso resource path `/validate` è frame 11363 e riceve `2.05 Content` al frame 11364; quindi il resource è ancora disponibile e CQ1b è **0**.

### CQ2 – Includere coap.me

Se il tuo amico ha contato anche le POST/PUT verso coap.me (non solo il server locale 127.0.0.1), ha **36 request aggiuntive** verso coap.me. La domanda dice chiaramente *"local server"*.

### CQ3 – Contare la risposta iniziale

Se la risposta iniziale dell'Observe (frame 4344, stessa MID della registrazione) viene contata come notifica, la risposta diventa **11 invece di 10**. Ma CQ3a chiede "separate observe notifications", e la prima risposta è la conferma della registrazione, non una notifica separata.

### CQ3b – Usare solo il criterio "valore ripetuto"

Una notifica inviata ma non ricevuta/processata è traffico inutile. Le notifiche CQ3a sono CON: le prime 5 hanno ACK, le ultime 5 generano ICMP Port Unreachable (`9866->9867`, `10573->10574`, `11220->11221`, `11917->11918`, `12782->12783`). Quindi CQ3b è **5**. Il criterio "stesso valore della precedente" darebbe 0, ma qui non identifica il traffico sprecato.

### ⚠️ CQ4 – Contare TUTTI i messaggi MQTT-SN (errore più comune!)

| Interpretazione | Risultato |
|----------------|-----------|
| **Tutti** i messaggi MQTT-SN sulla porta 1885 | **219** (SBAGLIATO) |
| Solo quelli **ricevuti dai client** (srcport=1885) | **0** (CORRETTO) |

La domanda chiede "messages **received by the clients** from the local broker". Il broker *invia* dalla porta 1885 (srcport=1885). Tutti i 219 messaggi vanno nella direzione opposta (client→broker, dstport=1885). Il broker non risponde mai perché non è in esecuzione (tutti i pacchetti ricevono ICMP Destination Unreachable type 3).

> [!WARNING]
> Questo è di gran lunga l'errore più probabile del tuo amico. 219 vs 0.

### CQ7 – Contare wildcards ≥ 1 invece di ≥ 2

| Interpretazione | Risultato |
|----------------|-----------|
| Topic con ≥ 1 wildcard | **34** (SBAGLIATO) |
| Topic con ≥ 2 wildcards | **9** (CORRETTO) |

La domanda dice *"at least two wildcards"*.

### CQ8 – Direzione sbagliata o includere broker pubblico

| Interpretazione | A.pcapng | B.pcapng |
|----------------|----------|----------|
| PUBLISH **TO** local broker (corretto) | **439** | **534** |
| PUBLISH **FROM** local broker (sbagliato) | 267 | 735 |
| Tutti i PUBLISH su porta 1883 (include HiveMQ) | 872 | 1989 |

La domanda dice "publish messages **directed to** the local broker", non "dal broker" e non "a qualsiasi broker".

> [!NOTE]
> Per B.pcapng, se non si filtra per IP locale (127.0.0.1/::1), si prendono anche i PUBLISH verso HiveMQ su porta 1883. Il risultato sarebbe 1989 invece di 534.

Il topic `hello_this_test` va contato perché la domanda non richiede di escludere payload o topic di test. In `B.pcapng` ci sono 21 PUBLISH locali con quel topic, tutti contati come topic a 1 layer.

---

## Conclusione sugli Script

Nessun bug trovato. I tuoi script gestiscono correttamente:
- ✅ Token matching per CoAP (NON e CON)
- ✅ Piggybacked vs Separate response
- ✅ Empty ACK (code 0) skip
- ✅ Deduplicazione retransmission per MID+token+endpoints
- ✅ Loopback duplicate detection
- ✅ MQTT-SN decode-as
- ✅ Direzione broker↔client
- ✅ MQTT wildcard topic matching
- ✅ Retained empty PUBLISH detection per erase
- ✅ HiveMQ IP resolution via DNS
- ✅ Multiple MQTT messages in one TCP frame
- ✅ Topic layer counting (non-empty levels)

---

## Part 2 (Exercise)

`part2/report/Exercise.tex` include già la fase iniziale MQTT: i dispositivi partono disconnessi. In EQ1 non si contano cicli di sleep o DISCONNECT finali; per EQ2 la scelta dei parametri resta parte della risposta.
