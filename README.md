# TestCodex

Applicazione demo costruita con Flask che arricchisce prodotti partendo da una lista di codici PIM. L'applicazione autentica l'utente, recupera i dati di dettaglio da un'API esterna, propone una categoria suggerita via OpenAI e offre un flusso di revisione manuale con invio simulato verso il PIM.

## Funzionalità
- **Autenticazione e gestione account**: login, registrazione, logout e flusso di recupero password tramite token monouso con scadenza a 1 ora.
- **Inserimento codici**: supporto a input manuale (righe o valori separati da virgole) e upload CSV (campo `code_prodotto`).
- **Recupero dati PIM**: per ogni codice viene chiamata un'API REST (XML) esterna; in caso di errore il prodotto viene marcato come mancante.
- **Classificazione AI**: se configurata una chiave OpenAI, l'agente indicato in `OPENAI_AGENT_ID` riceve un payload JSON con dati essenziali e restituisce la categoria consigliata (livelli 1 e 2 più motivazione). La categoria proposta viene aggiunta alle categorie mostrate.
- **Risultati filtrabili**: pagina di elenco con ricerca per codice/nome, filtro per stato e per categoria; conteggio per stato.
- **Dettaglio prodotto**: form precompilato con dati di marketing e prezzo, modificabile e con invio simulato al PIM; lo stato rimane in sessione.

## Architettura tecnica
- **Framework**: [Flask](https://flask.palletsprojects.com/)
- **Persistenza**: [SQLAlchemy](https://www.sqlalchemy.org/) con database SQLite locale (`app.db`) di default; compatibile con altri RDBMS via `DATABASE_URL`.
- **Moduli principali**:
  - `app.py`: entrypoint Flask con modelli `User` e `PasswordResetToken`, routing, logica di autenticazione, parsing dei codici, integrazione API esterna e classificazione OpenAI.
  - `templates/`: viste Jinja2 per login/registrazione, reset password, inserimento codici, risultati e dettaglio prodotto.
  - `static/`: risorse statiche (CSS/JS) utilizzate dalle pagine HTML.
  - `tests/`: suite Pytest con stubs per verificare la chiamata all'agente OpenAI.
- **Sessione**: la sessione Flask (cookie-signed) mantiene l'utente autenticato e i prodotti elaborati durante la navigazione.
- **Password e token**: le password sono salvate come digest SHA-256 (senza salt, ad uso demo); i token di reset sono random URL-safe con scadenza registrata a database.
- **OpenAI**: uso del client `OpenAI` (SDK ufficiale) per creare thread, inviare messaggi all'agente e leggere la risposta testuale.

## Requisiti
- Python 3.11+
- Librerie definite in `requirements.txt`

## Configurazione ambiente
Variabili d'ambiente principali:

- `DATABASE_URL`: stringa di connessione SQLAlchemy (default `sqlite:///app.db`).
- `CONAD_TOKEN_URL`: endpoint OAuth2 per ottenere l'access token (default
  `https://api.cfp5zmx7oc-conadscrl1-s2-public.model-t.cc.commerce.ondemand.com/authorizationserver/oauth/token`).
- `CONAD_CLIENT_ID`: client_id OAuth2 per la chiamata `client_credentials` (default `aem_client`).
- `CONAD_CLIENT_SECRET`: client_secret OAuth2 per la chiamata `client_credentials` (default `secret`).
- `CONAD_GRANT_TYPE`: grant_type OAuth2 (default `client_credentials`).
- `OPENAI_API_KEY`: chiave API OpenAI (se assente la classificazione AI viene ignorata senza errore).
- `OPENAI_MODEL`: modello OpenAI usato (default `gpt-4o-mini`).
- `OPENAI_AGENT_ID`: ID dell'agente OpenAI che riceve il prompt di classificazione.

## Avvio locale
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app app run --debug
```

> **Nota database**
> - Con SQLite viene creato `app.db` nella root del progetto.
> - Per MySQL/PostgreSQL impostare `DATABASE_URL` (esempio: `export DATABASE_URL="mysql+pymysql://user:pass@localhost:3306/nome_db"`).

## Flusso utente
1. Accesso dalla pagina di login (o registrazione nuovo utente).
2. Possibilità di avviare la procedura "password dimenticata" che genera un token e stampa il link di reset a console (simulazione email).
3. Inserimento codici prodotto manualmente o tramite CSV, quindi invio.
4. Per ogni codice l'app chiama l'API PIM esterna; se configurata la chiave OpenAI, invia il payload di contesto all'agente e integra la categoria suggerita.
5. Visualizzazione elenco risultati con filtri; eventuali codici mancanti sono mostrati separatamente.
6. Apertura del dettaglio prodotto per modificare descrizione/marketing/prezzo e invio simulato al PIM.
7. Logout.

## Logica di integrazione PIM
- Endpoint API configurato in `API_URL_TEMPLATE` con header `Authorization: Bearer <token OAuth2>` ottenuto con grant `client_credentials` e conservato in sessione utente (con refresh automatico su 401/expiration).
- La risposta XML viene parsata per estrarre codice, EAN, brand, descrizioni, prezzo e categorie.
- Errori HTTP o di parsing portano a un elemento con `status="error"` e vengono elencati nei "codici mancanti".

## Test
Eseguire la suite automatica:
```bash
pytest
```
Il test `tests/test_classification.py` fornisce stub per `openai`, `flask`, `sqlalchemy` e verifica che il prompt e l'`assistant_id` corretti siano inviati all'agente.

## Struttura del progetto
- `app.py`: logica applicativa e routing Flask.
- `templates/`: template HTML Jinja2.
- `static/`: risorse statiche.
- `tests/`: test Pytest e stubs.
- `requirements.txt`: dipendenze runtime.

## Limitazioni note
- Hashing password senza salt e invio email di reset simulato: adatto solo a scopo demo.
- Il salvataggio del prodotto è simulato: non esiste persistenza lato PIM né scrittura nel database locale.
