#!/usr/bin/env python3
"""
Kimathi Engineering — Flask Backend
Rebuilt from APK decompile. Covers all API endpoints the Flutter app expects.
"""

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import Flask, jsonify, request, g
from flask_cors import CORS

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app)

SECRET_KEY = "kimathi-engineering-secret-2026!!"  # 32 bytes — change in production
TOKEN_EXPIRY_HOURS = 72

DB_PATH = os.path.join(os.path.dirname(__file__), "kimathi.db")

# In-memory storage (simple, no SQLite dependency needed to get running)
# Persisted to JSON file for reboot survival.
DATA = {
    "users": [],
    "customers": [],
    "quotes": [],
    "payments": [],
    "transactions": [],
    "accounts": [],
    "fiscal_years": [],
    "metal_prices": [],
    "scrap_purchases": [],
    "services": [],
}

# Common transaction categories for dropdown picker
TRANSACTION_CATEGORIES = {
    "income": [
        "Scrap Metal Sale",
        "Equipment Sale",
        "Service Fee",
        "Deposit",
        "Loan Repayment",
        "Other Income",
    ],
    "expense": [
        "Transport",
        "Fuel",
        "Equipment Purchase",
        "Maintenance",
        "Utilities",
        "Rent",
        "Salaries",
        "Licenses & Permits",
        "Office Supplies",
        "Advertising",
        "Insurance",
        "Bank Charges",
        "Other Expense",
    ],
}

# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------
def _save():
    """Write DATA to disk."""
    with open(DB_PATH, "w") as f:
        json.dump(DATA, f, indent=2, default=str)


def _load():
    """Load DATA from disk if available."""
    global DATA
    if os.path.exists(DB_PATH):
        with open(DB_PATH) as f:
            DATA.update(json.load(f))


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def _hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=8)).decode()


def _check_password(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())


def _make_token(user_id: int) -> str:
    payload = {
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def _decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except Exception:
        return None


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid token"}), 401
        token = auth_header[7:]
        payload = _decode_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        user = _find_user_by_id(payload["user_id"])
        if not user:
            return jsonify({"error": "User not found"}), 401
        g.current_user = user
        return f(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Finders
# ---------------------------------------------------------------------------
def _find_user_by_username(username: str) -> dict | None:
    for u in DATA["users"]:
        if u["username"] == username:
            return u
    return None


def _find_user_by_id(uid: int) -> dict | None:
    for u in DATA["users"]:
        if u["id"] == uid:
            return u
    return None


def _next_id(collection: str) -> int:
    items = DATA.get(collection, [])
    return max((i["id"] for i in items), default=0) + 1


def _safe_data(body, fields):
    """Return only known fields from request JSON."""
    return {k: body[k] for k in fields if k in body}


# ===========================================================================
# Auth routes
# ===========================================================================
@app.route("/api/login", methods=["POST"])
def login():
    body = request.get_json(force=True)
    username = body.get("username", "").strip()
    password = body.get("password", "")

    user = _find_user_by_username(username)
    if not user or not _check_password(password, user["password"]):
        return jsonify({"error": "Invalid username or password"}), 401

    token = _make_token(user["id"])
    return jsonify({
        "user": {k: v for k, v in user.items() if k != "password"},
        "token": token,
    })


@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    return jsonify({"message": "Logged out"})


# ===========================================================================
# User routes
# ===========================================================================
@app.route("/api/users", methods=["GET"])
@require_auth
def get_users():
    safe = [{k: v for k, v in u.items() if k != "password"} for u in DATA["users"]]
    return jsonify(safe)


@app.route("/api/users", methods=["POST"])
@require_auth
def create_user():
    body = request.get_json(force=True)
    fields = ["username", "password", "role", "email", "phone", "name"]
    data = _safe_data(body, fields)
    data["id"] = _next_id("users")
    data["password"] = _hash_password(data.get("password", "changeme"))
    data.setdefault("role", "user")
    data.setdefault("name", "")
    data.setdefault("email", "")
    data.setdefault("phone", "")
    DATA["users"].append(data)
    _save()
    return jsonify({k: v for k, v in data.items() if k != "password"}), 201


# ===========================================================================
# Dashboard
# ===========================================================================
@app.route("/api/dashboard", methods=["GET"])
@require_auth
def get_dashboard():
    total_customers = len(DATA["customers"])
    total_quotes = len(DATA["quotes"])
    total_payments = sum(p.get("amount", 0) for p in DATA["payments"])
    total_purchases = sum(s.get("total", 0) for s in DATA["scrap_purchases"])
    return jsonify({
        "total_customers": total_customers,
        "total_quotes": total_quotes,
        "total_payments": total_payments,
        "total_purchases": total_purchases,
        "recent_payments": sorted(DATA["payments"], key=lambda x: x.get("id", 0), reverse=True)[:5],
        "recent_transactions": sorted(DATA["transactions"], key=lambda x: x.get("id", 0), reverse=True)[:5],
    })


# ===========================================================================
# Static image serving (logo + landing page)
# ===========================================================================
@app.route("/api/images/<image_name>", methods=["GET"])
def get_image(image_name):
    """Serve static images by name (logo.png, landing.png)."""
    import os as _os
    safe_names = {"logo", "landing"}
    if image_name not in safe_names:
        return jsonify({"error": "Image not found"}), 404
    file_path = _os.path.join(app.static_folder, f"{image_name}.png")
    if not _os.path.exists(file_path):
        return jsonify({"error": "Image file not uploaded yet"}), 404
    from flask import send_file
    return send_file(file_path, mimetype="image/png")


# ===========================================================================
# Generic CRUD helpers
# ===========================================================================
# ===========================================================================
# CRUD endpoints — registered individually to avoid Flask endpoint name clash
# ===========================================================================
def _register_crud(endpoint, collection, fields, search_field=None):
    """Register GET list, GET detail, POST create with unique endpoint names."""

    list_name = f"list_{endpoint}"
    get_name = f"get_{endpoint}"
    create_name = f"create_{endpoint}"

    @app.route(f"/api/{endpoint}", methods=["GET"], endpoint=list_name)
    @require_auth
    def list_items():
        items = DATA.get(collection, [])
        q = request.args.get("search", "").strip().lower()
        if q and search_field:
            items = [i for i in items if q in str(i.get(search_field, "")).lower()]
        return jsonify(sorted(items, key=lambda x: x.get("id", 0), reverse=True))

    @app.route(f"/api/{endpoint}/<int:item_id>", methods=["GET"], endpoint=get_name)
    @require_auth
    def get_item(item_id):
        for i in DATA.get(collection, []):
            if i["id"] == item_id:
                return jsonify(i)
        return jsonify({"error": "Not found"}), 404

    @app.route(f"/api/{endpoint}", methods=["POST"], endpoint=create_name)
    @require_auth
    def create_item():
        body = request.get_json(force=True)
        data = _safe_data(body, fields)
        data["id"] = _next_id(collection)
        data.setdefault("created_at", datetime.now().isoformat())
        DATA.setdefault(collection, []).append(data)
        _save()
        return jsonify(data), 201


# Register all CRUD endpoints
_register_crud("customers", "customers",
    ["name", "phone", "email", "address", "id_number", "notes"])
_register_crud("quotes", "quotes",
    ["customer_id", "customer_name", "items", "total", "status", "notes"])
_register_crud("payments", "payments",
    ["customer_id", "customer_name", "amount", "method", "reference", "notes", "type"])
# Transactions — custom handler with date + payment_method + category filtering
# ---------------------------------------------------------------------------
@app.route("/api/transactions", methods=["GET"], endpoint="list_transactions")
@require_auth
def list_transactions():
    items = DATA.get("transactions", [])
    # Filter by date (supports partial match: "2026-06" or full "2026-06-15")
    date_q = request.args.get("date", "").strip()
    if date_q:
        items = [i for i in items if date_q in str(i.get("date", ""))]
    # Filter by payment_method (exact, case-insensitive)
    pm_q = request.args.get("payment_method", "").strip()
    if pm_q:
        items = [i for i in items if pm_q.lower() in str(i.get("payment_method", "")).lower()]
    # Filter by category (type of work / item bought-sold)
    cat_q = request.args.get("category", "").strip()
    if cat_q:
        items = [i for i in items if cat_q.lower() in str(i.get("category", "")).lower()]
    # Text search across description + reference
    q = request.args.get("search", "").strip().lower()
    if q:
        items = [i for i in items if
                 q in str(i.get("description", "")).lower() or
                 q in str(i.get("reference", "")).lower()]
    return jsonify(sorted(items, key=lambda x: x.get("id", 0), reverse=True))


@app.route("/api/transactions/<int:item_id>", methods=["GET"], endpoint="get_transaction")
@require_auth
def get_transaction(item_id):
    for i in DATA.get("transactions", []):
        if i["id"] == item_id:
            return jsonify(i)
    return jsonify({"error": "Not found"}), 404


@app.route("/api/transactions", methods=["POST"], endpoint="create_transaction")
@require_auth
def create_transaction():
    body = request.get_json(force=True)
    fields = ["type", "category", "amount", "description", "date", "payment_method", "reference"]
    data = {k: body[k] for k in fields if k in body}
    data["id"] = _next_id("transactions")
    data.setdefault("created_at", datetime.now().isoformat())
    DATA.setdefault("transactions", []).append(data)
    _save()
    return jsonify(data), 201


@app.route("/api/transaction-categories", methods=["GET"], endpoint="transaction_categories")
@require_auth
def transaction_categories():
    """Return common transaction categories for frontend dropdown."""
    return jsonify(TRANSACTION_CATEGORIES)


_register_crud("accounts", "accounts",
    ["name", "type", "balance", "currency", "notes"])
_register_crud("fiscal_years", "fiscal_years",
    ["name", "start_date", "end_date", "is_active"])
_register_crud("metal_prices", "metal_prices",
    ["name", "buy_price_per_kg", "sell_price_per_kg", "unit", "is_active"])
_register_crud("scrap_purchases", "scrap_purchases",
    ["customer_id", "customer_name", "metal_type", "weight_kg", "price_per_kg", "total", "notes"])
_register_crud("services", "services",
    ["name", "description", "price", "category", "is_active"])


# ===========================================================================
# Seed data
# ===========================================================================
def _seed():
    _load()
    if not DATA["users"]:
        DATA["users"].append({
            "id": 1,
            "username": "admin",
            "password": _hash_password("admin123"),
            "role": "admin",
            "name": "Admin",
            "email": "admin@kimathi.co.ke",
            "phone": "+254700000000",
        })
        DATA["transactions"].extend([
            # M-Pesa transactions with work/item descriptions
            {"id": 1, "type": "income", "category": "Scrap Metal Sale", "amount": 45000,
             "description": "Sold 300kg steel scrap to Associated Steel Mill", "date": "2026-06-10",
             "payment_method": "M-Pesa", "reference": "MPESA-REF-A001"},
            {"id": 2, "type": "income", "category": "Scrap Metal Sale", "amount": 78000,
             "description": "Sold 150kg copper scrap to Kenya Metal Refiners", "date": "2026-06-11",
             "payment_method": "M-Pesa", "reference": "MPESA-REF-A002"},
            {"id": 3, "type": "expense", "category": "Transport", "amount": 8500,
             "description": "Haulage fee — pickup & delivery of 2-ton scrap load", "date": "2026-06-12",
             "payment_method": "M-Pesa", "reference": "MPESA-REF-B001"},
            {"id": 4, "type": "expense", "category": "Equipment Purchase", "amount": 32000,
             "description": "Bought hydraulic scrap shear (second-hand, Nakuru)", "date": "2026-06-13",
             "payment_method": "M-Pesa", "reference": "MPESA-REF-B002"},
            {"id": 5, "type": "income", "category": "Scrap Metal Sale", "amount": 22500,
             "description": "Sold 180kg aluminium scrap to East African Foundries", "date": "2026-06-14",
             "payment_method": "Cash", "reference": "CASH-001"},
            {"id": 6, "type": "income", "category": "Scrap Metal Sale", "amount": 12500,
             "description": "Sold 60kg brass scrap — walk-in customer", "date": "2026-06-15",
             "payment_method": "M-Pesa", "reference": "MPESA-REF-A003"},
            {"id": 7, "type": "expense", "category": "Utilities", "amount": 3400,
             "description": "Power bill — Kenya Power (yard operations)", "date": "2026-06-15",
             "payment_method": "M-Pesa", "reference": "MPESA-REF-B003"},
            {"id": 8, "type": "expense", "category": "Fuel", "amount": 6200,
             "description": "Diesel for loader machine (200L)", "date": "2026-06-16",
             "payment_method": "M-Pesa", "reference": "MPESA-REF-B004"},
            {"id": 9, "type": "income", "category": "Scrap Metal Sale", "amount": 95000,
             "description": "Bulk steel scrap order — Devki Steel Mill contract", "date": "2026-06-17",
             "payment_method": "Bank Transfer", "reference": "BANK-TFR-001"},
            {"id": 10, "type": "expense", "category": "Maintenance", "amount": 15000,
             "description": "Hydraulic press repair — replacement of seals & hoses", "date": "2026-06-17",
             "payment_method": "M-Pesa", "reference": "MPESA-REF-B005"},
        ])
        DATA["metal_prices"].extend([
            {"id": 1, "name": "Steel", "buy_price_per_kg": 15, "sell_price_per_kg": 25, "unit": "kg", "is_active": True},
            {"id": 2, "name": "Copper", "buy_price_per_kg": 450, "sell_price_per_kg": 520, "unit": "kg", "is_active": True},
            {"id": 3, "name": "Aluminium", "buy_price_per_kg": 120, "sell_price_per_kg": 160, "unit": "kg", "is_active": True},
            {"id": 4, "name": "Brass", "buy_price_per_kg": 200, "sell_price_per_kg": 260, "unit": "kg", "is_active": True},
            {"id": 5, "name": "Cast Iron", "buy_price_per_kg": 10, "sell_price_per_kg": 18, "unit": "kg", "is_active": True},
            {"id": 6, "name": "Stainless Steel", "buy_price_per_kg": 50, "sell_price_per_kg": 80, "unit": "kg", "is_active": True},
            {"id": 7, "name": "Lead", "buy_price_per_kg": 80, "sell_price_per_kg": 120, "unit": "kg", "is_active": True},
            {"id": 8, "name": "Battery", "buy_price_per_kg": 30, "sell_price_per_kg": 55, "unit": "kg", "is_active": True},
            {"id": 9, "name": "Mixed Metal", "buy_price_per_kg": 5, "sell_price_per_kg": 12, "unit": "kg", "is_active": True},
        ])
        _save()
        print("  → Seeded admin user + 9 metal prices")


# ===========================================================================
# Startup
# ===========================================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("Kimathi Engineering Backend")
    print("=" * 40)
    _seed()
    print(f"  Listening on http://0.0.0.0:{port}")
    print(f"  Login: admin / admin123")
    print()
    app.run(host="0.0.0.0", port=port, debug=False)
