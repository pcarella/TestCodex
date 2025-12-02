from __future__ import annotations

import csv
import hashlib
import io
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import Column, Integer, String, create_engine, select
from sqlalchemy.orm import declarative_base, sessionmaker

app = Flask(__name__)
app.secret_key = "dev-secret-key"

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///app.db")
engine = create_engine(
    DATABASE_URL,
    future=True,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(64), nullable=False)


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def init_db() -> None:
    Base.metadata.create_all(engine)

    default_users: Dict[str, str] = {
        "admin": "password",
        "demo": "demo",
    }
    with SessionLocal.begin() as db_session:
        for username, password in default_users.items():
            existing_user = db_session.execute(
                select(User).where(User.username == username)
            ).scalar_one_or_none()
            if not existing_user:
                db_session.add(User(username=username, password_hash=hash_password(password)))


init_db()


@dataclass
class Product:
    code: str
    name: str
    brand: str
    long_description: str
    category: str
    short_description: str
    price: float
    status: str = "review"


SAMPLE_PIM_DATA: Dict[str, Dict[str, str]] = {
    "P001": {
        "name": "Wireless Mouse",
        "brand": "ClickCo",
        "description": "Ergonomic wireless mouse with adjustable DPI and silent buttons.",
        "price": 24.99,
    },
    "P002": {
        "name": "Mechanical Keyboard",
        "brand": "TypeMaster",
        "description": "Full-size mechanical keyboard with blue switches and RGB lighting.",
        "price": 89.0,
    },
    "P003": {
        "name": "Noise Cancelling Headphones",
        "brand": "SoundSphere",
        "description": "Over-ear headphones with active noise cancellation and 30-hour battery life.",
        "price": 159.0,
    },
}


CATEGORY_KEYWORDS: Dict[str, List[str]] = {
    "Accessories": ["mouse", "keyboard", "cable", "adapter"],
    "Audio": ["headphones", "earbuds", "speaker", "audio"],
    "Computers": ["laptop", "notebook", "desktop"],
}


def classify_category(name: str, description: str) -> str:
    combined = f"{name} {description}".lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        if any(keyword in combined for keyword in keywords):
            return category
    return "Miscellaneous"


def generate_short_description(product: Dict[str, str]) -> str:
    brand = product.get("brand", "")
    name = product.get("name", "")
    description = product.get("description", "")
    snippet = description[:90].rstrip()
    if len(description) > 90:
        snippet += "..."
    return f"{brand} {name} – {snippet}".strip()


STATUS_CHOICES = {
    "ready": {"label": "Pronto", "badge": "success"},
    "review": {"label": "Richiede revisione", "badge": "warning"},
    "error": {"label": "Errore", "badge": "danger"},
}


def infer_status(code: str) -> str:
    """Derive a stable status for a product code to mimic workflow states."""

    score = sum(ord(ch) for ch in code)
    if score % 10 < 6:
        return "ready"
    if score % 10 < 9:
        return "review"
    return "error"


def fetch_from_pim(codes: List[str]) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    for code in codes:
        product = SAMPLE_PIM_DATA.get(
            code,
            {
                "name": f"Product {code}",
                "brand": "GenericCo",
                "description": "Placeholder description awaiting enrichment.",
                "price": 0.0,
            },
        )
        results.append({"code": code, **product})
    return results


def build_products(
    codes: List[str],
    *,
    generate_short_description_enabled: bool = True,
    recognize_category: bool = True,
) -> List[Product]:
    raw_products = fetch_from_pim(codes)
    products: List[Product] = []
    for product in raw_products:
        category = (
            classify_category(product["name"], product["description"])
            if recognize_category
            else ""
        )
        short_description = (
            generate_short_description(product)
            if generate_short_description_enabled
            else ""
        )
        products.append(
            Product(
                code=product["code"],
                name=product["name"],
                brand=product["brand"],
                long_description=product["description"],
                category=category,
                short_description=short_description,
                price=float(product.get("price", 0.0)),
                status=infer_status(product["code"]),
            )
        )
    return products


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

    exempt_endpoints = {"login", "register", "static"}
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


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/codici", methods=["GET", "POST"])
@login_required
def codes():
    if request.method == "POST":
        raw_codes = request.form.get("codes", "")
        csv_file = request.files.get("csv_file")
        generate_short_description = bool(request.form.get("generate_short_description"))
        recognize_category = bool(request.form.get("recognize_category"))

        codes = parse_codes(raw_codes, csv_file)
        if not codes:
            flash("Inserisci almeno un codice prodotto.")
        else:
            products = build_products(
                codes,
                generate_short_description_enabled=generate_short_description,
                recognize_category=recognize_category,
            )
            session["products"] = [product.__dict__ for product in products]
            session["options"] = {
                "generate_short_description": generate_short_description,
                "recognize_category": recognize_category,
            }
            return redirect(url_for("results"))
    return render_template("codes.html")


@app.route("/risultati")
@login_required
def results():
    products: Optional[List[Dict[str, str]]] = session.get("products")
    if not products:
        flash("Nessun prodotto richiesto. Inserisci i codici per continuare.")
        return redirect(url_for("codes"))
    options = session.get(
        "options",
        {"generate_short_description": True, "recognize_category": True},
    )

    # Ensure products carry a status, even for older sessions
    for product in products:
        product.setdefault("status", infer_status(product.get("code", "")))

    search_query = request.args.get("q", "").strip().lower()
    status_filter = request.args.get("status", "").strip()
    category_filter = request.args.get("category", "").strip()

    filtered_products: List[Dict[str, str]] = []
    for product in products:
        code_match = search_query in product.get("code", "").lower()
        name_match = search_query in product.get("name", "").lower()
        matches_search = not search_query or code_match or name_match
        matches_status = not status_filter or product.get("status") == status_filter
        matches_category = not category_filter or product.get("category", "") == category_filter

        if matches_search and matches_status and matches_category:
            filtered_products.append(product)

    categories = sorted({p.get("category", "") for p in products if p.get("category")})
    status_counts = {
        key: sum(1 for p in filtered_products if p.get("status") == key)
        for key in STATUS_CHOICES
    }

    return render_template(
        "results.html",
        products=filtered_products,
        options=options,
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
        product.update(
            {
                "name": request.form.get("name", product["name"]),
                "brand": request.form.get("brand", product["brand"]),
                "long_description": request.form.get(
                    "long_description", product.get("long_description", "")
                ),
                "category": request.form.get("category", product.get("category", "")),
                "short_description": request.form.get(
                    "short_description", product.get("short_description", "")
                ),
                "price": float(request.form.get("price", product.get("price", 0.0))),
            }
        )

        session["products"] = products
        flash("Prodotto aggiornato e inviato al PIM (simulato).")
        return redirect(url_for("results"))

    return render_template("product.html", product=product)


if __name__ == "__main__":
    app.run(debug=True)
