import os
import uuid
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
import json

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_file, abort, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, NumberRange
from config import Config
from io import StringIO
import csv
from flask_migrate import Migrate

# ---------------- App Setup ----------------
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = "login"

GOLD_RATE_FILE = "gold_rate.json"

# ---------------- Models ----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shop_name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=True)
    jewelries = db.relationship("Jewelry", backref="owner", lazy=True)
    plain_password = ""  # temporary

    def set_password(self, pwd):
        self.password_hash = generate_password_hash(pwd)
        self.plain_password = pwd

    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)

    def to_dict(self):
        return {
            "id": self.id,
            "shop_name": self.shop_name,
            "username": self.username,
            "password": self.plain_password,
            "is_admin": self.is_admin,
            "active": self.active,
            "num_items": len(self.jewelries)
        }


class Jewelry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    unique_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    weight_g = db.Column(db.Float, nullable=False)
    labor_cost = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    photo_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def to_dict(self):
        return {
            "unique_id": self.unique_id,
            "shop_name": self.owner.shop_name,
            "username": self.owner.username,
            "weight_g": self.weight_g,
            "labor_cost": self.labor_cost,
            "created_at": self.created_at
        }


# ---------------- Login Loader ----------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------- Forms ----------------
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Login")



class JewelryForm(FlaskForm):
    weight_g = FloatField("Weight (grams)", validators=[DataRequired(), NumberRange(min=0.01)])
    labor_cost = FloatField("Labor Cost", validators=[DataRequired(), NumberRange(min=0.0)])
    description = TextAreaField("Description (optional)")
    submit = SubmitField("Save")


class SearchForm(FlaskForm):
    unique_id = StringField("Jewelry ID", validators=[DataRequired(), Length(min=3, max=20)])
    submit = SubmitField("Search")


# ---------------- Helpers ----------------
def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in app.config["ALLOWED_EXTENSIONS"]

def new_unique_id() -> str:
    return f"JW-{uuid.uuid4().hex[:8].upper()}"

def money(n) -> str:
    return str(Decimal(str(n)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))

def get_gold_rate_per_gram():
    try:
        with open(GOLD_RATE_FILE, "r") as f:
            data = json.load(f)
        rate = data.get("manual_rate_per_gram")
        return float(rate) if rate else 7000.0
    except (FileNotFoundError, json.JSONDecodeError):
        return 7000.0


# ---------------- Routes ----------------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    flash("Registration is disabled. Contact admin for login credentials.", "warning")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Make sure to check by username
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user and user.active and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid credentials or inactive account.", "danger")
    return render_template("login.html", form=form)



@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    items = Jewelry.query.filter_by(owner=current_user).order_by(Jewelry.created_at.desc()).all()
    rate = get_gold_rate_per_gram()
    return render_template("dashboard.html", items=items, current_rate=rate)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add_jewelry():
    form = JewelryForm()
    if form.validate_on_submit():
        uid = new_unique_id()
        photo_path = None
        file = request.files.get("photo")
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Invalid image type. Use png/jpg/jpeg/webp.", "warning")
                return render_template("add_jewelry.html", form=form)
            fname = secure_filename(f"{uid}_{file.filename}")
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], fname)
            file.save(save_path)
            photo_path = save_path

        item = Jewelry(
            unique_id=uid,
            weight_g=form.weight_g.data,
            labor_cost=form.labor_cost.data,
            description=form.description.data.strip() if form.description.data else None,
            photo_path=photo_path,
            owner=current_user
        )
        db.session.add(item)
        db.session.commit()
        flash(f"Jewelry added with ID {uid}", "success")
        return redirect(url_for("dashboard"))
    return render_template("add_jewelry.html", form=form)


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    form = SearchForm()
    found = price = rate = None
    if form.validate_on_submit():
        uid = form.unique_id.data.strip().upper()
        found = Jewelry.query.filter_by(unique_id=uid).first()
        if found:
            rate = get_gold_rate_per_gram()
            price = found.weight_g * rate + found.labor_cost
        else:
            flash("No jewelry found for that ID.", "warning")
    return render_template("search.html", form=form, item=found, rate=rate, price=price)


@app.route("/invoice/<uid>")
@login_required
def invoice(uid):
    item = Jewelry.query.filter_by(unique_id=uid.upper()).first_or_404()
    if item.owner.id != current_user.id and not current_user.is_admin:
        abort(403)
    rate = get_gold_rate_per_gram()
    final_price = item.weight_g * rate + item.labor_cost
    return render_template("invoice.html", item=item, rate=rate, final_price=final_price)


@app.route("/update-gold-rate", methods=["POST"])
@login_required
def update_gold_rate():
    data = request.json
    if not data or "rate" not in data:
        return jsonify({"error": "No rate provided"}), 400
    try:
        rate = float(data["rate"])
    except ValueError:
        return jsonify({"error": "Invalid rate"}), 400

    with open(GOLD_RATE_FILE, "w") as f:
        json.dump({"manual_rate_per_gram": rate}, f)
    return jsonify({"message": f"Gold rate updated to {rate} per gram."})


# ---------------- Admin ----------------
def admin_required():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)


@app.route("/admin")
@login_required
def admin_dashboard():
    admin_required()
    shops = User.query.order_by(User.shop_name.asc()).all()
    items = Jewelry.query.order_by(Jewelry.created_at.desc()).all()
    return render_template("admin.html", shops=shops, items=items)


@app.route("/admin/create-shopkeeper", methods=["POST"])
@login_required
def admin_create_shopkeeper():
    admin_required()
    shop_name = request.form.get("shop_name").strip()
    username = request.form.get("username").strip()
    password = request.form.get("password").strip()
    if not shop_name or not username or not password:
        flash("All fields are required.", "warning")
        return redirect(url_for("admin_dashboard"))
    if User.query.filter_by(username=username).first():
        flash("Username already exists.", "danger")
        return redirect(url_for("admin_dashboard"))

    user = User(shop_name=shop_name, username=username, active=True, is_admin=False)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    flash(f"Shopkeeper '{shop_name}' created successfully!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/toggle-shop/<int:user_id>")
@login_required
def admin_toggle_shop(user_id):
    admin_required()
    u = User.query.get_or_404(user_id)
    if u.id == current_user.id:
        flash("You cannot deactivate yourself.", "warning")
        return redirect(url_for("admin_dashboard"))
    u.active = not u.active
    db.session.commit()
    flash(f"Shop '{u.shop_name}' active = {u.active}", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete-shop/<int:user_id>")
@login_required
def admin_delete_shop(user_id):
    admin_required()
    u = User.query.get_or_404(user_id)
    if u.id == current_user.id:
        flash("You cannot delete yourself.", "warning")
        return redirect(url_for("admin_dashboard"))
    for item in u.jewelries:
        db.session.delete(item)
    db.session.delete(u)
    db.session.commit()
    flash(f"Shopkeeper '{u.shop_name}' deleted.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete-item/<int:item_id>")
@login_required
def admin_delete_item(item_id):
    admin_required()
    it = Jewelry.query.get_or_404(item_id)
    db.session.delete(it)
    db.session.commit()
    flash("Item deleted.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/export.csv")
@login_required
def admin_export_csv():
    admin_required()
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(["unique_id", "shop_name", "username", "weight_g", "labor_cost", "created_at"])
    for it in Jewelry.query.order_by(Jewelry.created_at.asc()).all():
        writer.writerow([it.unique_id, it.owner.shop_name, it.owner.username,
                         money(it.weight_g), money(it.labor_cost), it.created_at.isoformat()])
    si.seek(0)
    return send_file(si, mimetype="text/csv", as_attachment=True, download_name="jewelry_export.csv")


# ---------------- CLI ----------------
@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Database initialized.")


@app.cli.command("create-admin")
def create_admin():
    username = os.environ.get("ADMIN_USERNAME", "admin")
    password = os.environ.get("ADMIN_PASSWORD", "admin123")
    shop_name = os.environ.get("ADMIN_SHOP", "Main Admin")
    existing = User.query.filter_by(username=username).first()
    if existing:
        print("Admin already exists.")
        return
    u = User(shop_name=shop_name, username=username, is_admin=True, active=True)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    print(f"Admin created: {username} / {password} (change later!)")


@app.cli.command("create-shop")
def create_shop():
    username = input("Shop username: ").strip()
    shop_name = input("Shop name: ").strip()
    password = input("Password: ").strip()
    if User.query.filter_by(username=username).first():
        print("Username already exists.")
        return
    user = User(shop_name=shop_name, username=username, active=True, is_admin=False)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    print(f"Shopkeeper account created: {shop_name} / {username}")


# ---------------- Run ----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
