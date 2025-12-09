from __future__ import annotations

import csv
import datetime as dt
import io
import json
import logging
import os
import re
import secrets
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Dict, List, Optional, Tuple

import requests
from defusedxml import ElementTree
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from openai import OpenAI
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, create_engine, select
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("product-review")

app = Flask(__name__)
if not hasattr(app, "config"):
    app.config = {}


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError(
            "FLASK_SECRET_KEY non impostata. Configura una chiave stabile e segreta prima di avviare l'applicazione."
        )
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.getenv("FLASK_SECURE_COOKIES", "1") == "1"
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = dt.timedelta(minutes=30)
    WTF_CSRF_TIME_LIMIT = 60 * 60
    PREFERRED_URL_SCHEME = "https" if SESSION_COOKIE_SECURE else "http"


if hasattr(getattr(app, "config", None), "from_object"):
    app.config.from_object(Config)
else:  # pragma: no cover - fallback for tests without real Flask
    for key, value in Config.__dict__.items():
        if key.isupper():
            app.config[key] = value

csrf = CSRFProtect(app)
if getattr(app, "jinja_env", None) is not None:
    app.jinja_env.globals["csrf_token"] = generate_csrf
else:  # pragma: no cover - fallback for test stubs without real Flask
    app.jinja_env = SimpleNamespace(globals={"csrf_token": generate_csrf})
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per hour"])

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///app.db")
DEFAULT_TOKEN_URL = (
    "https://api.cfp5zmx7oc-conadscrl1-s2-public.model-t.cc.commerce."
    "ondemand.com/authorizationserver/oauth/token"
)
API_TOKEN_URL = os.getenv("CONAD_TOKEN_URL", DEFAULT_TOKEN_URL)
API_CLIENT_ID = os.getenv("CONAD_CLIENT_ID", "aem_client")
API_CLIENT_SECRET = os.getenv("CONAD_CLIENT_SECRET", "secret")
API_GRANT_TYPE = os.getenv("CONAD_GRANT_TYPE", "client_credentials")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_AGENT_ID = os.getenv("OPENAI_AGENT_ID", "asst_o1LCzpNKALkmUwTGao1x0Mjp")
API_URL_TEMPLATE = (
    "https://api.cfp5zmx7oc-conadscrl1-s2-public.model-t.cc.commerce.ondemand.com/occ/v2/conad/products/"
    "{code}?fields=FULL&storeId=010040"
)
engine = create_engine(
    DATABASE_URL,
    future=True,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()
def _create_openai_client() -> Optional[OpenAI]:
    if not OPENAI_API_KEY:
        logger.warning("OPENAI_API_KEY non configurata: salto la classificazione AI.")
        return None

    try:
        return OpenAI(api_key=OPENAI_API_KEY)
    except TypeError as exc:
        # Alcune versioni del client OpenAI possono rifiutare parametri imprevisti
        # (ad esempio "proxies") quando vengono inizializzate. In tal caso
        # continuiamo senza il supporto AI per evitare il crash dell'app.
        logger.exception("Impossibile inizializzare il client OpenAI")
        return None


openai_client = _create_openai_client()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(64), nullable=False)
    reset_tokens = relationship(
        "PasswordResetToken", cascade="all, delete-orphan", back_populates="user"
    )


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token = Column(String(128), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="reset_tokens")


def hash_password(password: str) -> str:
    return generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)


def verify_password(password: str, password_hash: str) -> bool:
    return check_password_hash(password_hash, password)


def send_reset_email(recipient: str, reset_url: str) -> None:
    """
    Send the password reset email.

    In a production setup this should be integrated with a transactional email
    provider. For this demo we log the link to the console to avoid exposing
    SMTP credentials and to keep the feature easily testable.
    """

    message = (
        "Richiesta di reset password\n\n"
        "Clicca sul link seguente per impostare una nuova password:"
        f"\n{reset_url}\n\n"
        "Il link scade tra un'ora. Se non hai richiesto tu il reset, ignora questa email."
    )
    logger.info("Invio email di reset a %s", recipient)


def persist_reset_token(user_id: int) -> str:
    token = secrets.token_urlsafe(48)
    expires_at = dt.datetime.utcnow() + dt.timedelta(hours=1)

    with SessionLocal.begin() as db_session:
        existing_tokens = db_session.execute(
            select(PasswordResetToken).where(PasswordResetToken.user_id == user_id)
        ).scalars()
        for existing_token in existing_tokens:
            db_session.delete(existing_token)

        db_session.add(
            PasswordResetToken(
                user_id=user_id,
                token=token,
                expires_at=expires_at,
            )
        )

    return token


def init_db() -> None:
    Base.metadata.create_all(engine)
    # Ensure legacy demo credentials are removed so only registered users can access
    with SessionLocal.begin() as db_session:
        for username in ("demo", "admin"):
            existing_user = db_session.execute(
                select(User).where(User.username == username)
            ).scalar_one_or_none()
            if existing_user:
                db_session.delete(existing_user)


init_db()


@dataclass
class Product:
    code: str
    categories: List[Dict[str, str]]
    codice_ean: str
    marchio: str
    nome_marca: str
    denominazione_vendita: str
    descrizione_marketing: str
    description: str
    price: float
    ai_category: Optional[Dict[str, str]] = None
    status: str = "review"


STATUS_CHOICES = {
    "ready": {"label": "Pronto", "badge": "success"},
    "review": {"label": "Richiede revisione", "badge": "warning"},
    "error": {"label": "Errore", "badge": "danger"},
    "exported": {"label": "Esportato", "badge": "secondary"},
}

CODE_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,64}$")
PASSWORD_POLICY = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{12,}$")
MAX_CODES_PER_REQUEST = 100
MAX_CSV_BYTES = 1_000_000
LOGIN_FAILURE_WINDOW = dt.timedelta(minutes=15)
MAX_LOGIN_FAILURES = 5
_login_failures: Dict[str, Tuple[int, dt.datetime]] = {}
PASSWORD_RESET_WINDOW = dt.timedelta(hours=1)
MAX_RESET_REQUESTS = 3
_reset_requests: Dict[str, Tuple[int, dt.datetime]] = {}


def username_is_valid(username: str) -> bool:
    return bool(username) and bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username))


def password_is_valid(password: str) -> bool:
    return bool(PASSWORD_POLICY.match(password))


def parse_categories(product_xml: ElementTree.Element) -> List[Dict[str, str]]:
    categories: List[Dict[str, str]] = []
    for category_node in product_xml.findall("categories"):
        categories.append(
            {
                "code": category_node.findtext("code", default=""),
                "name": category_node.findtext("name", default=""),
            }
        )
    return categories


def classify_product_category(product_data: Dict[str, str]) -> Optional[Dict[str, str]]:
    if not openai_client:
        logger.warning("OPENAI_API_KEY non configurata: salto la classificazione AI.")
        return None

    payload = {
        "code": product_data.get("code", ""),
        "codice_ean": product_data.get("codice_ean", ""),
        "denominazione_vendita": product_data.get("denominazione_vendita", ""),
        "descrizione_marketing": product_data.get("descrizione_marketing", ""),
        "price": product_data.get("price", 0.0),
    }
    logger.info("Richiesta classificazione AI per codice %s", payload.get("code", ""))

    prompt = json.dumps(payload, ensure_ascii=False)

    response = classify_with_agent(prompt)
    if not response:
        return None

    response_text = _extract_response_text(response)
    if response_text:
        logger.info(
            "Risposta classificazione AI ricevuta (lunghezza %d caratteri)",
            len(response_text),
        )
    else:
        logger.warning("Risposta classificazione AI vuota o non leggibile")

    return parse_classification_response(response)


def classify_with_agent(user_prompt: str):
    if not openai_client:
        return None
    if not OPENAI_AGENT_ID:
        logger.warning("OPENAI_AGENT_ID non configurato: salto la classificazione AI.")
        return None

    try:
        logger.info("Invio prompt all'agente %s", OPENAI_AGENT_ID)

        thread = openai_client.beta.threads.create()
        openai_client.beta.threads.messages.create(
            thread_id=thread.id,
            role="user",
            content=user_prompt,
        )

        run = openai_client.beta.threads.runs.create(
            thread_id=thread.id, assistant_id=OPENAI_AGENT_ID
        )

        while run.status in ("queued", "in_progress"):
            run = openai_client.beta.threads.runs.retrieve(
                thread_id=thread.id, run_id=run.id
            )

        if run.status != "completed":
            logger.warning("Run AI non completato: stato %s", run.status)
            return None

        messages = openai_client.beta.threads.messages.list(thread_id=thread.id)
        assistant_msg = messages.data[0] if getattr(messages, "data", None) else None
        text_chunks: List[str] = []
        if assistant_msg:
            for chunk in getattr(assistant_msg, "content", []) or []:
                if getattr(chunk, "type", "") == "text":
                    text_value = getattr(chunk, "text", None)
                    if text_value is not None:
                        text_chunks.append(getattr(text_value, "value", ""))

        full_text = "".join(text_chunks).strip()
        if full_text:
            logger.info(
                "Risposta grezza dall'agente ricevuta (lunghezza %d caratteri)",
                len(full_text),
            )
        else:
            logger.warning("Risposta grezza dall'agente vuota o non leggibile")

        return SimpleNamespace(output_text=full_text)
    except Exception as exc:
        logger.exception("Errore durante la classificazione AI")
        return None


def parse_classification_response(response) -> Optional[Dict[str, str]]:
    try:
        raw_text = _extract_response_text(response)

        parsed = json.loads(raw_text)
        required_keys = {"category_2_id", "category_2_name", "category_1_name", "reason"}
        if not required_keys.issubset(parsed):
            missing = required_keys - set(parsed)
            logger.warning("Risposta AI mancante di campi obbligatori: %s", missing)
            return None

        return {key: str(parsed.get(key, "")).strip() for key in required_keys}
    except (AttributeError, IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        logger.warning("Impossibile leggere la risposta AI come JSON: %s", exc)
        return None


def _extract_response_text(response) -> str:
    try:
        if hasattr(response, "output_text") and response.output_text:
            return str(response.output_text).strip()

        output_blocks = getattr(response, "output", None) or []
        first_block = output_blocks[0]
        content_list = getattr(first_block, "content", None) or []
        return (getattr(content_list[0], "text", "") or "").strip()
    except (AttributeError, IndexError, KeyError, TypeError):
        return ""


_api_token_cache: Dict[str, Optional[dt.datetime]] = {"token": None, "expires_at": None}


def _token_is_expired(expires_at: Optional[dt.datetime]) -> bool:
    if not expires_at:
        return True

    return dt.datetime.utcnow() >= expires_at


def _store_api_token(token: str, expires_in: int) -> str:
    safe_expires_in = max(expires_in - 30, 30) if expires_in else 0
    expiry = dt.datetime.utcnow() + dt.timedelta(seconds=safe_expires_in)
    _api_token_cache["token"] = token
    _api_token_cache["expires_at"] = expiry
    return token


def request_api_token() -> Optional[str]:
    try:
        response = requests.post(
            API_TOKEN_URL,
            data={"grant_type": API_GRANT_TYPE},
            auth=(API_CLIENT_ID, API_CLIENT_SECRET),
            timeout=10,
        )
    except Exception:
        logger.exception("Errore durante la richiesta del token OAuth2")
        return None

    if response.status_code != 200:
        logger.error(
            "Token non ottenuto: status %s, body %s", response.status_code, response.text
        )
        return None

    try:
        payload = response.json()
        token = payload.get("access_token", "")
        expires_in = int(payload.get("expires_in", 0))
    except (ValueError, json.JSONDecodeError, TypeError) as exc:
        logger.warning("Risposta token non valida: %s", exc)
        return None

    if not token:
        logger.error("Token mancante nella risposta OAuth2")
        return None

    return _store_api_token(token, expires_in)


def get_api_token(force_refresh: bool = False) -> Optional[str]:
    cached_token = _api_token_cache.get("token")
    expires_at = _api_token_cache.get("expires_at")

    if not force_refresh and cached_token and not _token_is_expired(expires_at):
        return cached_token

    return request_api_token()


def fetch_product_from_api(code: str) -> Optional[Dict[str, str]]:
    if not CODE_PATTERN.fullmatch(code):
        return None

    url = API_URL_TEMPLATE.format(code=code)
    token = get_api_token()
    if not token:
        return None

    headers = {"accept": "application/xml", "Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=10)

    if response.status_code == 401:
        refreshed_token = get_api_token(force_refresh=True)
        if not refreshed_token:
            return None

        headers["Authorization"] = f"Bearer {refreshed_token}"
        response = requests.get(url, headers=headers, timeout=10)

    if response.status_code != 200:
        return None

    try:
        root = ElementTree.fromstring(response.content)
    except ElementTree.ParseError:
        return None

    price_value = root.findtext("price/value", default="0")
    try:
        price_float = float(price_value)
    except ValueError:
        price_float = 0.0

    product_data = {
        "code": root.findtext("code", default=code),
        "categories": parse_categories(root),
        "codice_ean": root.findtext("codiceEAN", default=""),
        "marchio": root.findtext("marchio", default=""),
        "nome_marca": root.findtext("nomeMarca", default=""),
        "denominazione_vendita": root.findtext("denominazioneDiVendita", default=""),
        "descrizione_marketing": root.findtext("descrizioneMarketing", default=""),
        "description": root.findtext("description", default=""),
        "price": price_float,
    }

    ai_category = classify_product_category(product_data)
    if ai_category:
        product_data["ai_category"] = ai_category
        product_data.setdefault("categories", []).append(
            {
                "code": ai_category.get("category_2_id", "ai"),
                "name": ai_category.get("category_2_name", "Suggerita AI"),
            }
        )

    return product_data


def build_products(codes: List[str]) -> Tuple[List[Product], List[str]]:
    products: List[Product] = []
    missing_codes: List[str] = []

    for code in codes:
        product_data = fetch_product_from_api(code)
        if not product_data:
            missing_codes.append(code)
            products.append(
                Product(
                    code=code,
                    categories=[],
                    codice_ean="",
                    marchio="",
                    nome_marca="",
                    denominazione_vendita="",
                    descrizione_marketing="",
                    description="",
                    price=0.0,
                    status="error",
                )
            )
            continue

        products.append(
            Product(
                code=product_data["code"],
                categories=product_data["categories"],
                codice_ean=product_data["codice_ean"],
                marchio=product_data["marchio"],
                nome_marca=product_data["nome_marca"],
                denominazione_vendita=product_data["denominazione_vendita"],
                descrizione_marketing=product_data["descrizione_marketing"],
                description=product_data["description"],
                price=product_data["price"],
                ai_category=product_data.get("ai_category"),
                status="review",
            )
        )

    return products, missing_codes


def parse_codes(raw_codes: str, csv_file) -> List[str]:
    codes: List[str] = []

    def add_code(value: str) -> None:
        code = value.strip()
        if code and CODE_PATTERN.fullmatch(code) and code not in codes:
            codes.append(code)

    for code in re.split(r"[\n,]+", raw_codes):
        add_code(code)

    if csv_file and csv_file.filename:
        content = csv_file.stream.read()
        if len(content) > MAX_CSV_BYTES:
            logger.warning("CSV troppo grande: %s bytes", len(content))
            flash("Il file CSV supera il limite di 1MB e non verrà elaborato.")
            return codes
        try:
            decoded = content.decode("utf-8")
        except UnicodeDecodeError:
            return codes

        reader = csv.DictReader(io.StringIO(decoded))
        for row in reader:
            add_code(row.get("code_prodotto", ""))

    return codes


def _get_session_products() -> List[Dict[str, str]]:
    return session.get("products") or []


def _persist_products(products: List[Dict[str, str]]) -> None:
    session["products"] = products


def _status_counters(products: List[Dict[str, str]]) -> Dict[str, int]:
    return {key: sum(1 for p in products if p.get("status") == key) for key in STATUS_CHOICES}


def _login_key(username: str, ip_address: str) -> str:
    return f"{username.lower()}:{ip_address}"


def _login_locked(username: str, ip_address: str) -> bool:
    key = _login_key(username, ip_address)
    failures = _login_failures.get(key)
    if not failures:
        return False

    count, first_failure = failures
    if dt.datetime.utcnow() - first_failure > LOGIN_FAILURE_WINDOW:
        _login_failures.pop(key, None)
        return False

    return count >= MAX_LOGIN_FAILURES


def _record_login_failure(username: str, ip_address: str) -> None:
    key = _login_key(username, ip_address)
    count, first_failure = _login_failures.get(
        key, (0, dt.datetime.utcnow())
    )
    _login_failures[key] = (count + 1, first_failure)


def _reset_login_failures(username: str, ip_address: str) -> None:
    _login_failures.pop(_login_key(username, ip_address), None)


def _reset_key(identifier: str) -> str:
    return identifier.lower()


def _reset_requests_exceeded(identifier: str) -> bool:
    key = _reset_key(identifier)
    count, first_request = _reset_requests.get(key, (0, dt.datetime.utcnow()))
    if dt.datetime.utcnow() - first_request > PASSWORD_RESET_WINDOW:
        _reset_requests.pop(key, None)
        return False

    return count >= MAX_RESET_REQUESTS


def _record_reset_request(identifier: str) -> None:
    key = _reset_key(identifier)
    count, first_request = _reset_requests.get(key, (0, dt.datetime.utcnow()))
    if dt.datetime.utcnow() - first_request > PASSWORD_RESET_WINDOW:
        count = 0
        first_request = dt.datetime.utcnow()

    _reset_requests[key] = (count + 1, first_request)


def login_required(view_func):
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    wrapper.__name__ = view_func.__name__
    return wrapper


@app.before_request
def ensure_authenticated():
    """Redirect users to the login page if they are not authenticated."""

    exempt_endpoints = {
        "login",
        "register",
        "forgot_password",
        "reset_password",
        "static",
    }
    if request.endpoint in exempt_endpoints:
        return None

    if not session.get("user"):
        return redirect(url_for("login"))

    return None


@app.route("/", methods=["GET"])
def home():
    if session.get("user"):
        return redirect(url_for("codes"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if session.get("user"):
        return redirect(url_for("codes"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username_is_valid(username):
            flash("Inserisci un username valido (3-64 caratteri alfanumerici e simboli ._-).")
            return render_template("login.html")

        if _login_locked(username, get_remote_address()):
            flash(
                "Account temporaneamente bloccato per troppi tentativi falliti. "
                "Riprovare tra qualche minuto."
            )
            logger.warning("Login bloccato per %s", username)
            return render_template("login.html")

        with SessionLocal() as db_session:
            user = db_session.execute(
                select(User).where(User.username == username)
            ).scalar_one_or_none()
            if user and verify_password(password, user.password_hash):
                session.clear()
                session.permanent = True
                session["user"] = username
                session["session_nonce"] = secrets.token_urlsafe(16)
                session.pop("products", None)
                _reset_login_failures(username, get_remote_address())
                logger.info("Login eseguito per %s da %s", username, get_remote_address())
                return redirect(url_for("codes"))
        _record_login_failure(username, get_remote_address())
        logger.warning("Tentativo di login non riuscito per %s da %s", username, get_remote_address())
        flash("Credenziali non valide. Riprova.")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def register():
    if session.get("user"):
        return redirect(url_for("codes"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username_is_valid(username):
            flash("Username non valido. Usa 3-64 caratteri alfanumerici o simboli ._-.")
            return render_template("register.html")

        if not password_is_valid(password):
            flash("Password non conforme: minimo 12 caratteri con maiuscola, minuscola e numero.")
            return render_template("register.html")

        if password != confirm_password:
            flash("Le password non coincidono.")
            return render_template("register.html")

        with SessionLocal.begin() as db_session:
            existing_user = db_session.execute(
                select(User).where(User.username == username)
            ).scalar_one_or_none()
            if existing_user:
                flash("Username già in uso. Scegline un altro.")
                return render_template("register.html")

            db_session.add(User(username=username, password_hash=hash_password(password)))

        flash("Registrazione completata! Effettua il login.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/password-dimenticata", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def forgot_password():
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        if not username_is_valid(identifier):
            flash("Inserisci un username valido per procedere al reset.")
            return render_template("forgot_password.html")

        if _reset_requests_exceeded(identifier):
            flash(
                "Sono stati effettuati troppi tentativi di reset per questo account. Riprova più tardi."
            )
            logger.warning("Reset password bloccato per %s", identifier)
            return render_template("forgot_password.html")

        _record_reset_request(identifier)

        with SessionLocal() as db_session:
            user = db_session.execute(
                select(User).where(User.username == identifier)
            ).scalar_one_or_none()

        if user:
            token = persist_reset_token(user.id)
            reset_url = url_for("reset_password", token=token, _external=True)
            send_reset_email(identifier, reset_url)
            logger.info("Reset password inviato per utente %s", identifier)

        flash(
            "Se l'account esiste, riceverai un'email con il link per reimpostare la password."
        )
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/reset-password/<token>", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def reset_password(token: str):
    with SessionLocal() as db_session:
        reset_request = db_session.execute(
            select(PasswordResetToken).where(PasswordResetToken.token == token)
        ).scalar_one_or_none()

        if not reset_request or reset_request.expires_at < dt.datetime.utcnow():
            flash("Link di reset non valido o scaduto. Richiedi nuovamente il reset.")
            return redirect(url_for("forgot_password"))

        user = db_session.get(User, reset_request.user_id)

    if request.method == "POST":
        new_password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not password_is_valid(new_password):
            flash("La password deve avere minimo 12 caratteri, maiuscola, minuscola e numero.")
            return render_template("reset_password.html", username=user.username, token=token)

        if new_password != confirm_password:
            flash("Le password non coincidono.")
            return render_template("reset_password.html", username=user.username, token=token)

        with SessionLocal.begin() as db_session:
            reset_request = db_session.execute(
                select(PasswordResetToken).where(PasswordResetToken.token == token)
            ).scalar_one_or_none()

            if not reset_request or reset_request.expires_at < dt.datetime.utcnow():
                flash("Link di reset non valido o scaduto. Richiedi nuovamente il reset.")
                return redirect(url_for("forgot_password"))

            user_db = db_session.get(User, reset_request.user_id)
            user_db.password_hash = hash_password(new_password)

            tokens = db_session.execute(
                select(PasswordResetToken).where(PasswordResetToken.user_id == user_db.id)
            ).scalars()
            for token_instance in tokens:
                db_session.delete(token_instance)

        logger.info("Password aggiornata con successo per utente %s", user.username)
        flash("Password aggiornata con successo. Accedi con le nuove credenziali.")
        return redirect(url_for("login"))

    return render_template("reset_password.html", username=user.username, token=token)


@app.route("/codici", methods=["GET", "POST"])
@login_required
@limiter.limit("30 per hour")
def codes():
    if request.method == "POST":
        raw_codes = request.form.get("codes", "")
        csv_file = request.files.get("csv_file")

        codes = parse_codes(raw_codes, csv_file)
        if len(codes) > MAX_CODES_PER_REQUEST:
            flash("Puoi inviare massimo 100 codici per richiesta; i restanti sono stati ignorati.")
            codes = codes[:MAX_CODES_PER_REQUEST]
        if not codes:
            flash("Inserisci almeno un codice prodotto valido (caratteri alfanumerici, ._-).")
        else:
            products, missing_codes = build_products(codes)
            session["products"] = [product.__dict__ for product in products]
            session["missing_codes"] = missing_codes
            return redirect(url_for("results"))
    return render_template("codes.html")


@app.route("/risultati")
@login_required
def results():
    products: Optional[List[Dict[str, str]]] = session.get("products")
    if not products:
        flash("Nessun prodotto richiesto. Inserisci i codici per continuare.")
        return redirect(url_for("codes"))
    missing_codes = session.get("missing_codes", [])

    for product in products:
        product.setdefault("status", "review")

    search_query = request.args.get("q", "").strip().lower()
    status_filter = request.args.get("status", "").strip()
    category_filter = request.args.get("category", "").strip()

    filtered_products: List[Dict[str, str]] = []
    for product in products:
        code_match = search_query in product.get("code", "").lower()
        name_match = search_query in product.get("denominazione_vendita", "").lower()
        matches_search = not search_query or code_match or name_match
        matches_status = not status_filter or product.get("status") == status_filter
        category_names = {c.get("name", "") for c in product.get("categories", [])}
        matches_category = not category_filter or category_filter in category_names

        if matches_search and matches_status and matches_category:
            filtered_products.append(product)

    categories = sorted(
        {
            c.get("name", "")
            for p in products
            for c in p.get("categories", [])
            if c.get("name")
        }
    )
    status_counts = {
        key: sum(1 for p in filtered_products if p.get("status") == key)
        for key in STATUS_CHOICES
    }

    return render_template(
        "results.html",
        products=filtered_products,
        missing_codes=missing_codes,
        status_choices=STATUS_CHOICES,
        status_filter=status_filter,
        category_filter=category_filter,
        search_query=search_query,
        categories=categories,
        status_counts=status_counts,
    )


@app.post("/api/prodotti/stato")
@login_required
def update_product_status():
    products = _get_session_products()
    if not products:
        return {"message": "Nessun prodotto attivo nella sessione."}, 400

    payload = request.get_json(silent=True) or {}
    requested_codes = payload.get("codes") or []
    target_status = payload.get("status", "")

    if not isinstance(requested_codes, list) or not all(
        isinstance(code, str) for code in requested_codes
    ):
        return {"message": "Formato codici non valido."}, 400

    if target_status not in STATUS_CHOICES:
        return {"message": "Stato richiesto non valido."}, 400

    updated_codes: List[str] = []
    skipped_codes: List[str] = []

    for product in products:
        if product.get("code") not in requested_codes:
            continue

        current_status = product.get("status", "review")
        if target_status == "exported" and current_status != "ready":
            skipped_codes.append(product.get("code", ""))
            continue

        product["status"] = target_status
        updated_codes.append(product.get("code", ""))

    _persist_products(products)

    return {
        "updated_codes": updated_codes,
        "skipped_codes": skipped_codes,
        "status_counts": _status_counters(products),
    }


@app.route("/prodotto/<code>", methods=["GET", "POST"])
@login_required
def product_detail(code: str):
    if not CODE_PATTERN.fullmatch(code):
        flash("Codice prodotto non valido.")
        return redirect(url_for("results"))

    products: Optional[List[Dict[str, str]]] = session.get("products")
    if not products:
        flash("Nessun prodotto richiesto. Inserisci i codici per continuare.")
        return redirect(url_for("codes"))

    product = next((p for p in products if p["code"] == code), None)
    if not product:
        flash("Prodotto non trovato nella richiesta corrente.")
        return redirect(url_for("results"))

    product.setdefault("status", "review")

    if request.method == "POST":
        try:
            price_value = float(request.form.get("price", product.get("price", 0.0)))
            price_value = max(price_value, 0.0)
        except (TypeError, ValueError):
            price_value = product.get("price", 0.0)

        product.update(
            {
                "denominazione_vendita": request.form.get(
                    "denominazione_vendita", product.get("denominazione_vendita", "")
                )[:255],
                "descrizione_marketing": request.form.get(
                    "descrizione_marketing", product.get("descrizione_marketing", "")
                )[:1024],
                "price": price_value,
            }
        )

        session["products"] = products
        flash("Prodotto aggiornato e inviato al PIM (simulato).")
        return redirect(url_for("results"))

    return render_template("product.html", product=product, status_choices=STATUS_CHOICES)


if hasattr(app, "after_request"):

    @app.after_request
    def apply_security_headers(response):
        csp = (
            "default-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com; "
            "img-src 'self' data: https://cdn.jsdelivr.net https://fonts.gstatic.com; "
            "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com; "
            "form-action 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
            )
        return response


else:  # pragma: no cover - fallback for dummy Flask in tests

    def apply_security_headers(response):
        return response


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1")
