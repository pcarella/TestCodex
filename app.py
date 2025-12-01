from __future__ import annotations

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

app = Flask(__name__)
app.secret_key = "dev-secret-key"

USERS: Dict[str, str] = {
    "admin": "password",
    "demo": "demo",
}


@dataclass
class Product:
    code: str
    name: str
    brand: str
    long_description: str
    category: str
    short_description: str
    price: float


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


def build_products(codes: List[str]) -> List[Product]:
    raw_products = fetch_from_pim(codes)
    products: List[Product] = []
    for product in raw_products:
        category = classify_category(product["name"], product["description"])
        short_description = generate_short_description(product)
        products.append(
            Product(
                code=product["code"],
                name=product["name"],
                brand=product["brand"],
                long_description=product["description"],
                category=category,
                short_description=short_description,
                price=float(product.get("price", 0.0)),
            )
        )
    return products


def login_required(view_func):
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    wrapper.__name__ = view_func.__name__
    return wrapper


@app.route("/", methods=["GET"])
def home():
    if session.get("user"):
        return redirect(url_for("codes"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if USERS.get(username) == password:
            session["user"] = username
            session.pop("products", None)
            return redirect(url_for("codes"))
        flash("Credenziali non valide. Riprova.")
    return render_template("login.html")


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
        codes = [code.strip() for code in raw_codes.splitlines() if code.strip()]
        if not codes:
            flash("Inserisci almeno un codice prodotto.")
        else:
            session["products"] = [product.__dict__ for product in build_products(codes)]
            return redirect(url_for("results"))
    return render_template("codes.html")


@app.route("/risultati")
@login_required
def results():
    products: Optional[List[Dict[str, str]]] = session.get("products")
    if not products:
        flash("Nessun prodotto richiesto. Inserisci i codici per continuare.")
        return redirect(url_for("codes"))
    return render_template("results.html", products=products)


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
