import os

from flask import Flask, render_template, request

from classifier import classify_alert
from playbooks import get_playbook

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    alert_text = ""

    if request.method == "POST":
        alert_text = request.form.get("alert_text", "").strip()

        if alert_text:
            try:
                classification = classify_alert(alert_text)
                playbook = get_playbook(classification.get("incident_type"))

                result = {
                    "alert_text": alert_text,
                    "classification": classification,
                    "playbook": playbook,
                }
            except Exception as e:
                app.logger.exception("Error processing alert")
                result = {"error": str(e)}

    return render_template("index.html", result=result, alert_text=alert_text)


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
