# TestCodex

Applicazione Flask di esempio per arricchire prodotti tramite un agente che propone categoria e short description a partire da una lista di codici PIM.

## Requisiti
- Python 3.11+
- [Flask](https://flask.palletsprojects.com/) (vedi `requirements.txt`)
- [SQLAlchemy](https://www.sqlalchemy.org/) per la persistenza utenti

## Avvio
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app app run --debug
```

> Database
> - Di default viene creato un file SQLite locale (`app.db`) per archiviare gli utenti registrati.
> - Per puntare a MySQL è sufficiente impostare `DATABASE_URL`, ad esempio `export DATABASE_URL="mysql+pymysql://user:password@localhost:3306/nome_db"`.
> - Le password sono salvate come digest `sha256`.

Credenziali demo sempre disponibili: `admin/password` oppure `demo/demo`.

## Flusso
1. Accesso dalla pagina di login.
2. Possibilità di registrare un nuovo utente con la stessa UI del login.
3. Inserimento dei codici prodotto (uno per riga).
4. Recupero simulato dal PIM, classificazione categoria e generazione short description.
5. Visualizzazione risultati e apertura dettaglio prodotto con form modificabile e invio simulato al PIM.
