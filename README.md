# GoldShop MVP

Multi-tenant Flask app for jewelry shops to store items and compute current selling price using today’s gold rate.

## Setup
```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
export FLASK_APP=app.py         # Windows PowerShell: $env:FLASK_APP="app.py"
flask init-db
flask create-admin              # uses env vars ADMIN_EMAIL/ADMIN_PASSWORD (optional)
python app.py
