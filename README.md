# TestCodex

Applicazione Flask di esempio per arricchire prodotti tramite un agente che propone categoria e short description a partire da una lista di codici PIM.

## Requisiti
- Python 3.11+
- [Flask](https://flask.palletsprojects.com/) (vedi `requirements.txt`)

## Avvio
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app app run --debug
```

Credenziali demo: `admin/password` oppure `demo/demo`.

## Flusso
1. Accesso dalla pagina di login.
2. Inserimento dei codici prodotto (uno per riga).
3. Recupero simulato dal PIM, classificazione categoria e generazione short description.
4. Visualizzazione risultati e apertura dettaglio prodotto con form modificabile e invio simulato al PIM.
