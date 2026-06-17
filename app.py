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
    "suppliers": [],
    "inventory": [],
    "stock_movements": [],
    "scale_readings": [],
    "invoices": [],
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

    # Auto-seed if database is empty (handles gunicorn cold start)
    if not DATA["users"]:
        _seed()

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
# Inventory / Stock Management
# ===========================================================================
@app.route("/api/inventory", methods=["GET"], endpoint="list_inventory")
@require_auth
def list_inventory():
    items = DATA.get("inventory", [])
    # Filter by metal_type
    mt = request.args.get("metal_type", "").strip()
    if mt:
        items = [i for i in items if mt.lower() in i.get("metal_type", "").lower()]
    # Search
    q = request.args.get("search", "").strip().lower()
    if q:
        items = [i for i in items if q in str(i.get("metal_type", "")).lower() or q in str(i.get("notes", "")).lower()]
    return jsonify(sorted(items, key=lambda x: x.get("id", 0), reverse=True))


@app.route("/api/inventory/<int:item_id>", methods=["GET"], endpoint="get_inventory")
@require_auth
def get_inventory(item_id):
    for i in DATA.get("inventory", []):
        if i["id"] == item_id:
            return jsonify(i)
    return jsonify({"error": "Not found"}), 404


@app.route("/api/inventory", methods=["POST"], endpoint="create_inventory")
@require_auth
def create_inventory():
    body = request.get_json(force=True)
    fields = ["metal_type", "weight_kg", "location", "buy_price_per_kg", "notes"]
    data = {k: body[k] for k in fields if k in body}
    data["id"] = _next_id("inventory")
    data.setdefault("weight_kg", 0)
    data.setdefault("location", "Main Yard")
    data["created_at"] = datetime.now().isoformat()
    DATA.setdefault("inventory", []).append(data)
    _save()
    return jsonify(data), 201


@app.route("/api/inventory/summary", methods=["GET"], endpoint="inventory_summary")
@require_auth
def inventory_summary():
    items = DATA.get("inventory", [])
    summary = {}
    for item in items:
        mt = item.get("metal_type", "Unknown")
        if mt not in summary:
            summary[mt] = {"metal_type": mt, "total_weight_kg": 0, "item_count": 0, "avg_buy_price": 0}
        summary[mt]["total_weight_kg"] += item.get("weight_kg", 0)
        summary[mt]["item_count"] += 1
    # Calculate averages and totals
    total_weight = 0
    for s in summary.values():
        total_weight += s["total_weight_kg"]
    return jsonify({
        "by_metal": list(summary.values()),
        "total_weight_kg": total_weight,
        "total_items": len(items),
    })


# ===========================================================================
# Stock Movements (in / out tracking)
# ===========================================================================
@app.route("/api/stock-movements", methods=["GET"], endpoint="list_stock_movements")
@require_auth
def list_stock_movements():
    items = DATA.get("stock_movements", [])
    date_q = request.args.get("date", "").strip()
    if date_q:
        items = [i for i in items if date_q in str(i.get("date", ""))]
    mt = request.args.get("metal_type", "").strip()
    if mt:
        items = [i for i in items if mt.lower() in i.get("metal_type", "").lower()]
    return jsonify(sorted(items, key=lambda x: x.get("id", 0), reverse=True))


@app.route("/api/stock-movements", methods=["POST"], endpoint="create_stock_movement")
@require_auth
def create_stock_movement():
    body = request.get_json(force=True)
    fields = ["type", "metal_type", "weight_kg", "reference", "notes", "date", "supplier", "customer"]
    data = {k: body[k] for k in fields if k in body}
    data["id"] = _next_id("stock_movements")
    data.setdefault("date", datetime.now().strftime("%Y-%m-%d"))
    data["created_at"] = datetime.now().isoformat()
    DATA.setdefault("stock_movements", []).append(data)
    # Also update inventory: if type=in, add to inventory; if type=out, reduce
    if data.get("type") == "in":
        DATA.setdefault("inventory", []).append({
            "id": _next_id("inventory"),
            "metal_type": data.get("metal_type", "Unknown"),
            "weight_kg": data.get("weight_kg", 0),
            "location": data.get("location", "Main Yard"),
            "notes": f"Stock in: {data.get('reference', '')}",
            "created_at": datetime.now().isoformat(),
        })
    _save()
    return jsonify(data), 201


# ===========================================================================
# Supplier Management
# ===========================================================================
_register_crud("suppliers", "suppliers",
    ["name", "phone", "email", "address", "id_number", "notes"])


# ===========================================================================
# Profit & Loss Report
# ===========================================================================
@app.route("/api/reports/profit-loss", methods=["GET"], endpoint="profit_loss")
@require_auth
def profit_loss():
    from_date = request.args.get("from", "1970-01-01")
    to_date = request.args.get("to", "2099-12-31")

    income = 0
    expense = 0

    # From transactions
    for t in DATA.get("transactions", []):
        d = t.get("date", "")
        if from_date <= d <= to_date:
            if t.get("type") == "income":
                income += t.get("amount", 0)
            else:
                expense += t.get("amount", 0)

    # From payments
    for p in DATA.get("payments", []):
        # Assume payments are income
        income += p.get("amount", 0)

    # From scrap purchases (expenses)
    for s in DATA.get("scrap_purchases", []):
        expense += s.get("total", 0)

    net = income - expense

    return jsonify({
        "period": {"from": from_date, "to": to_date},
        "income": {"total": income, "sources": {"transactions": income, "payments": 0}},
        "expense": {"total": expense, "sources": {"transactions": expense, "purchases": 0}},
        "net_profit": net,
        "profit_margin_percent": round((net / income * 100), 1) if income > 0 else 0,
    })


# ===========================================================================
# PDF Invoice Generation
# ===========================================================================
@app.route("/api/invoices/generate", methods=["POST"], endpoint="generate_invoice")
@require_auth
def generate_invoice():
    body = request.get_json(force=True)
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    import io

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20*mm, bottomMargin=20*mm)

    styles = getSampleStyleSheet()
    elements = []

    # Company header
    elements.append(Paragraph("<b>KIMATHI ENGINEERING</b>", styles["Title"]))
    elements.append(Paragraph("Scrap Metal Dealers & General Engineering", styles["Normal"]))
    elements.append(Paragraph(f"Nairobi, Kenya | Tel: +254 700 000 000", styles["Normal"]))
    elements.append(Spacer(1, 20))

    # Invoice title
    invoice_no = body.get("invoice_number", f"INV-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    elements.append(Paragraph(f"<b>INVOICE #{invoice_no}</b>", styles["Heading2"]))
    elements.append(Paragraph(f"Date: {body.get('date', datetime.now().strftime('%Y-%m-%d'))}", styles["Normal"]))
    elements.append(Paragraph(f"Customer: {body.get('customer_name', 'Walk-in Customer')}", styles["Normal"]))
    elements.append(Spacer(1, 10))

    # Items table
    items = body.get("items", [])
    table_data = [["#", "Description", "Qty", "Unit Price", "Total"]]
    for i, item in enumerate(items, 1):
        table_data.append([
            str(i),
            item.get("description", ""),
            str(item.get("qty", 1)),
            f"KES {item.get('unit_price', 0):,.2f}",
            f"KES {item.get('total', 0):,.2f}",
        ])
    # Totals row
    subtotal = body.get("subtotal", sum(item.get("total", 0) for item in items))
    table_data.append(["", "", "", "Subtotal:", f"KES {subtotal:,.2f}"])
    table_data.append(["", "", "", "Total:", f"KES {body.get('total', subtotal):,.2f}"])

    col_widths = [30, 250, 60, 100, 100]
    t = Table(table_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -3), 0.5, colors.grey),
        ("LINEBELOW", (0, -2), (-1, -2), 1, colors.black),
        ("LINEBELOW", (0, -1), (-1, -1), 2, colors.black),
        ("ALIGN", (2, 0), (-1, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 30))

    # Payment info
    elements.append(Paragraph("<b>Payment Details:</b>", styles["Heading3"]))
    elements.append(Paragraph("M-Pesa Paybill: 247247 | Account: KIMATHI-INV", styles["Normal"]))
    elements.append(Paragraph("Bank: Equity Bank | Acc: 1234567890", styles["Normal"]))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("<i>Thank you for your business!</i>", styles["Normal"]))

    doc.build(elements)
    pdf_bytes = buf.getvalue()
    buf.close()

    # Store invoice record
    invoice_record = {
        "id": _next_id("invoices"),
        "invoice_number": invoice_no,
        "customer_name": body.get("customer_name", ""),
        "date": body.get("date", datetime.now().strftime("%Y-%m-%d")),
        "total": body.get("total", subtotal),
        "created_at": datetime.now().isoformat(),
    }
    DATA.setdefault("invoices", []).append(invoice_record)
    _save()

    from flask import send_file
    import io as _io
    return send_file(
        _io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"invoice_{invoice_no}.pdf"
    )


# ===========================================================================
# Weight Scale (mock — accepts readings from digital scale / manual entry)
# ===========================================================================
@app.route("/api/scale/reading", methods=["POST"], endpoint="scale_reading_post")
@require_auth
def scale_reading_post():
    body = request.get_json(force=True)
    reading = {
        "id": _next_id("scale_readings"),
        "weight_kg": body.get("weight_kg", 0),
        "source": body.get("source", "manual"),  # "bluetooth", "manual"
        "reference": body.get("reference", ""),
        "timestamp": datetime.now().isoformat(),
    }
    DATA.setdefault("scale_readings", []).append(reading)
    _save()
    return jsonify(reading), 201


@app.route("/api/scale/reading", methods=["GET"], endpoint="scale_reading_get")
@require_auth
def scale_reading_get():
    readings = DATA.get("scale_readings", [])
    latest = sorted(readings, key=lambda x: x.get("id", 0), reverse=True)
    return jsonify(latest[:10] if latest else [{"weight_kg": 0, "message": "No readings yet"}])


# ===========================================================================
# Reset — force re-seed (useful for Render cold starts)
# ===========================================================================
@app.route("/api/reset", methods=["POST"])
def reset_db():
    """Delete the database and re-seed. Returns new admin credentials."""
    import os as _os
    if _os.path.exists(DB_PATH):
        _os.remove(DB_PATH)
    # Clear in-memory data
    for key in DATA:
        if key != "metal_prices":  # metal_prices has defaults below
            DATA[key] = []
    DATA["metal_prices"] = []
    _seed()
    return jsonify({
        "message": "Database reset and re-seeded",
        "login": {"username": "admin", "password": "admin123"},
        "users_count": len(DATA["users"]),
        "transactions_count": len(DATA["transactions"]),
        "metal_prices_count": len(DATA["metal_prices"]),
    })


# ===========================================================================
# Startup  — seed runs here so gunicorn picks it up (__name__ != "__main__")
# ===========================================================================
_seed()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("Kimathi Engineering Backend")
    print("=" * 40)
    print(f"  Listening on http://0.0.0.0:{port}")
    print(f"  Login: admin / admin123")
    print()
    app.run(host="0.0.0.0", port=port, debug=False)
