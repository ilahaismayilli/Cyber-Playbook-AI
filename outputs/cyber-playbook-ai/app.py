import os

from flask import Flask, render_template, request

from classifier import classify_alert
from playbooks import get_playbook

app = Flask(__name__)

# Security: limit request sizes and alert text to avoid large payload abuse
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024))
MAX_ALERT_CHARS = int(os.environ.get("MAX_ALERT_CHARS", 10000))


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    alert_text = ""

    if request.method == "POST":
        alert_text = request.form.get("alert_text", "").strip()

        if alert_text:
            if len(alert_text) > MAX_ALERT_CHARS:
                app.logger.warning("Alert text exceeds max allowed length (%d).", MAX_ALERT_CHARS)
                result = {"error": f"Alert text too long (max {MAX_ALERT_CHARS} characters)."}
            else:
            try:
                classification = classify_alert(alert_text)
                playbook = get_playbook(classification.get("incident_type"))

                result = {
                    "alert_text": alert_text,
                    "classification": classification,
                    "playbook": playbook,
                }
            except Exception:
                # Do not return internal exception details to clients; log server-side instead
                app.logger.exception("Error processing alert")
                result = {"error": "An internal error occurred while processing the alert."}

    return render_template("index.html", result=result, alert_text=alert_text)


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # Enable debug only when FLASK_DEBUG=1 in the environment
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
