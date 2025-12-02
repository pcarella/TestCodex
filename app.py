from __future__ import annotations

import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
import secrets
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from openai import OpenAI
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, create_engine, select
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
import requests

app = Flask(__name__)
app.secret_key = "dev-secret-key"

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///app.db")
API_TOKEN = os.getenv(
    "CONAD_API_TOKEN", "vm8ZQy9FyAir3r4ssRv787mDnJc"
)
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
openai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None


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
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


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
    print(f"[PasswordReset] Invio email a {recipient}:\n{message}")


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
}


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
        print("[OpenAI] OPENAI_API_KEY non configurata: salto la classificazione AI.")
        return None

    payload = {
        "code": product_data.get("code", ""),
        "codice_ean": product_data.get("codice_ean", ""),
        "denominazione_vendita": product_data.get("denominazione_vendita", ""),
        "descrizione_marketing": product_data.get("descrizione_marketing", ""),
        "price": product_data.get("price", 0.0),
    }
    print(f"[OpenAI] Richiesta classificazione: {json.dumps(payload, ensure_ascii=False)}")

    try:
        response = openai_client.responses.create(
            agent_id=OPENAI_AGENT_ID,
            model=OPENAI_MODEL,
            input=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": (
                                "Restituisci SEMPRE e SOLO un JSON con le chiavi "
                                "category_2_id, category_2_name, category_1_name, reason "
                                "basandoti sui dati prodotto seguenti: "
                                f"{json.dumps(payload, ensure_ascii=False)}"
                            ),
                        }
                    ],
                }
            ],
        )
    except Exception as exc:
        print(f"[OpenAI] Errore durante la classificazione: {exc}")
        return None

    print(f"[OpenAI] Risposta classificazione: {response}")

    try:
        if hasattr(response, "output_text") and response.output_text:
            raw_text = response.output_text.strip()
        else:
            output_blocks = getattr(response, "output", None) or []
            first_block = output_blocks[0]
            content_list = getattr(first_block, "content", None) or []
            raw_text = (getattr(content_list[0], "text", "") or "").strip()

        parsed = json.loads(raw_text)
        required_keys = {"category_2_id", "category_2_name", "category_1_name", "reason"}
        if not required_keys.issubset(parsed):
            missing = required_keys - set(parsed)
            print(f"[OpenAI] Risposta JSON mancante di campi obbligatori: {missing}")
            return None

        return {key: str(parsed.get(key, "")).strip() for key in required_keys}
    except (AttributeError, IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"[OpenAI] Impossibile leggere la risposta AI come JSON: {exc}")
        return None


def fetch_product_from_api(code: str) -> Optional[Dict[str, str]]:
    url = API_URL_TEMPLATE.format(code=code)
    headers = {
        "accept": "application/xml",
        "Authorization": f"Bearer {API_TOKEN}",
    }
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
        if code and code not in codes:
            codes.append(code)

    for code in re.split(r"[\n,]+", raw_codes):
        add_code(code)

    if csv_file and csv_file.filename:
        content = csv_file.stream.read()
        try:
            decoded = content.decode("utf-8")
        except UnicodeDecodeError:
            return codes

        reader = csv.DictReader(io.StringIO(decoded))
        for row in reader:
            add_code(row.get("code_prodotto", ""))

    return codes


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
def login():
    if session.get("user"):
        return redirect(url_for("codes"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with SessionLocal() as db_session:
            user = db_session.execute(
                select(User).where(User.username == username)
            ).scalar_one_or_none()
            if user and user.password_hash == hash_password(password):
                session["user"] = username
                session.pop("products", None)
                return redirect(url_for("codes"))
        flash("Credenziali non valide. Riprova.")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user"):
        return redirect(url_for("codes"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not password:
            flash("Inserisci username e password per registrarti.")
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
def forgot_password():
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        if not identifier:
            flash("Inserisci l'email o l'username associato all'account.")
            return render_template("forgot_password.html")

        with SessionLocal() as db_session:
            user = db_session.execute(
                select(User).where(User.username == identifier)
            ).scalar_one_or_none()

        if user:
            token = persist_reset_token(user.id)
            reset_url = url_for("reset_password", token=token, _external=True)
            send_reset_email(identifier, reset_url)

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

        if len(new_password) < 8:
            flash("La password deve contenere almeno 8 caratteri.")
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

        flash("Password aggiornata con successo. Accedi con le nuove credenziali.")
        return redirect(url_for("login"))

    return render_template("reset_password.html", username=user.username, token=token)


@app.route("/codici", methods=["GET", "POST"])
@login_required
def codes():
    if request.method == "POST":
        raw_codes = request.form.get("codes", "")
        csv_file = request.files.get("csv_file")

        codes = parse_codes(raw_codes, csv_file)
        if not codes:
            flash("Inserisci almeno un codice prodotto.")
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


@app.route("/prodotto/<code>", methods=["GET", "POST"])
@login_required
def product_detail(code: str):
    products: Optional[List[Dict[str, str]]] = session.get("products")
    if not products:
        flash("Nessun prodotto richiesto. Inserisci i codici per continuare.")
        return redirect(url_for("codes"))

    product = next((p for p in products if p["code"] == code), None)
    if not product:
        flash("Prodotto non trovato nella richiesta corrente.")
        return redirect(url_for("results"))

    if request.method == "POST":
        try:
            price_value = float(request.form.get("price", product.get("price", 0.0)))
        except (TypeError, ValueError):
            price_value = product.get("price", 0.0)

        product.update(
            {
                "denominazione_vendita": request.form.get(
                    "denominazione_vendita", product.get("denominazione_vendita", "")
                ),
                "descrizione_marketing": request.form.get(
                    "descrizione_marketing", product.get("descrizione_marketing", "")
                ),
                "price": price_value,
            }
        )

        session["products"] = products
        flash("Prodotto aggiornato e inviato al PIM (simulato).")
        return redirect(url_for("results"))

    return render_template("product.html", product=product)


if __name__ == "__main__":
    app.run(debug=True)
