from flask import Flask, request

app = Flask(__name__)


@app.route("/invoices/<int:invoice_id>", methods=["GET"])
def get_invoice(invoice_id):
    # No ownership check -- any authenticated user can pull any invoice_id.
    invoice = db.query(Invoice).filter_by(id=invoice_id).first()
    return {"id": invoice.id, "total": invoice.total, "owner": invoice.owner_id}


@app.route("/invoices/<int:invoice_id>", methods=["DELETE"])
def delete_invoice(invoice_id):
    db.query(Invoice).filter_by(id=invoice_id).delete()
    db.commit()
    return {"deleted": invoice_id}


@app.route("/account/profile", methods=["GET"])
@login_required
def get_profile():
    return {"email": current_user.email, "name": current_user.name}


@app.route("/account/profile", methods=["POST"])
@login_required
def update_profile():
    payload = request.get_json()
    current_user.name = payload.get("name")
    db.commit()
    return {"ok": True}


@app.route("/healthz")
def health_check():
    return "ok"
