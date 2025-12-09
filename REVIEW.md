# Revisione tecnica e security compliance

## Architettura e suddivisione dei file
- Applicazione monolitica Flask in `app.py` che combina configurazione, modelli SQLAlchemy, routing, integrazione API esterna e chiamate OpenAI.
- Template Jinja2 in `templates/` per login/registrazione, recupero password, inserimento codici e viste risultati/dettaglio.
- Risorse statiche in `static/` (logo SVG) e dipendenze elencate in `requirements.txt`.
- Test Pytest in `tests/test_classification.py` che stubba Flask/OpenAI/SQLAlchemy per verificare la composizione della chiamata all'agente.

## Modello di sviluppo e design
- Single-file backend: funzioni di dominio (parsing codici, classificazione AI, integrazione API) e presentation logic convivono in `app.py`, riducendo la separazione di responsabilità e la testabilità modulare.
- Sessione server-side basata su cookie firmato; nessuna persistenza dei prodotti modificati oltre la sessione.
- Uso di SQLAlchemy ORM per utenti/token reset; hashing password con `werkzeug.security` o fallback SHA256.
- Rate limiting via `flask-limiter` con fallback no-op in ambienti senza dipendenza installata.

## UX
- UI bootstrap con design coerente (`templates/base.html` definisce header sticky, palette brand e step indicator).
- Flusso chiaro: login/registrazione → inserimento codici (manuale o CSV) → elenco filtrabile → dettaglio modificabile.
- Messaggi flash per errori di validazione (username/password, codici, link reset) e feedback sulle azioni.

## Aderenza alle best practice
- Validazioni input: regex per codici prodotto (`CODE_PATTERN`), policy password forte (`PASSWORD_POLICY`), limitazione quantitativo codici (max 100).
- Sicurezza HTTP: middleware `after_request` applica CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy e HSTS opzionale.
- Mitigazioni CSRF: `flask-wtf` CSRF token registrato nei globals Jinja; fallback custom quando la dipendenza manca.
- gestione token OAuth2 con cache e refresh su 401; timeout di rete espliciti.

## Security e OWASP Top 10
- **A01 Broken Access Control**: protezione con `login_required` e `before_request` su quasi tutti gli endpoint, ma i dati utente/prodotti vivono in sessione client-side; non esiste controllo di autorizzazione per ruolo o per risorsa.
- **A02 Cryptographic Failures**: fallback SHA256 per password senza salt né strette derivation parameters è debole; in produzione imporre `werkzeug`/`bcrypt`, secret key da env e storage sicuro del DB.
- **A03 Injection**: uso di ORM riduce SQL injection; input API ai servizi esterni è validato con regex; attenzione al consumo diretto di XML esterno (usa `defusedxml` se disponibile ma manca hard requirement).
- **A05 Security Misconfiguration**: CSP e header hardening sono presenti; debug disattivato per default. Mancano controlli su dimensione upload CSV e logging/monitoring centralizzato.
- **A07 Identification & Authentication Failures**: policy password robusta e reset token con scadenza; i token vengono invalidati post reset. Tuttavia sessione cookie-signed senza rotazione, nessuna MFA, e rate limit leggero (100/h) su login potrebbe essere insufficiente.
- **A08 Software and Data Integrity Failures**: dipendenza da agent OpenAI/servizi esterni senza firma dell’output; nessun controllo sull’integrità dei file CSV caricati.
- **A09 Security Logging & Monitoring**: log minimi via `print`; assente audit trail per accessi e operazioni critiche.
- **A10 Server-Side Request Forgery**: chiamate outbound a URL configurati con costanti/env; input utente non influenza gli host remoti (riduce rischio SSRF).

## Raccomandazioni sintetiche
- Estrarre in moduli separati autenticazione, integrazione API e classificazione AI per migliorare manutenibilità e test.
- Rendere obbligatorie le dipendenze di sicurezza (`defusedxml`, `flask-wtf`, `flask-limiter`) eliminando i fallback permissivi.
- Migliorare storage credenziali: usare hashing forte (p. es. `pbkdf2`/`bcrypt` obbligatorio), secret key da secret manager, e database non SQLite in produzione.
- Potenziare access control: ruoli, ownership delle risorse, rotazione sessione post-login, lockout progressivo e MFA.
- Aumentare osservabilità: logging strutturato, audit trail, allarmi su eventi anomali.
- Validare e sanificare input file: limitare dimensione CSV, usare librerie sicure e storage temporaneo confinato.
- Definire pipeline CI con test e security linting (Bandit, safety) e scansioni SAST/DAST.

## Implementazione raccomandazioni
- Reso obbligatorio l'uso delle librerie di sicurezza, rimuovendo i fallback permissivi e aggiungendo stub isolati per i test automatizzati.
- Rafforzato l'accesso con rotazione della sessione, blocco progressivo dopo più tentativi falliti e logging strutturato per eventi di sicurezza.
- Migliorata la protezione degli input limitando a 1MB i CSV caricati e mantenendo il tetto a 100 codici per richiesta.
