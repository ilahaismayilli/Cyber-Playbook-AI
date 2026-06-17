# CyberPlaybook AI

A beginner-friendly incident response assistant built with Python and Flask.

Paste a security alert into the app and it will:

- Estimate the incident type
- Estimate the severity
- Select a matching response playbook
- Generate analyst response steps

This first version uses simple keyword rules so you can understand the flow. Later, you can replace the rule logic with a machine learning model.

## Project Structure

```text
cyber-playbook-ai/
  app.py              Flask web app
  classifier.py       Basic incident classification logic
  playbooks.py        Incident response playbooks
  sample_alerts.json  Example alerts to test with
  requirements.txt    Python packages
  templates/
    index.html        Web page
```

## How To Run

Open this folder in VS Code, then run:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## How To Make It Public

Right now, `http://127.0.0.1:5000` only works on your own computer.
To let other users access it, deploy it to a hosting service.

One beginner-friendly path is Render:

1. Create a GitHub repository for this project.
2. Upload/push this folder to GitHub.
3. In Render, create a new Web Service from that GitHub repo.
4. Use these settings:

```text
Build Command: pip install -r requirements.txt
Start Command: gunicorn app:app
```

After deployment, Render gives you a public website link ending in:

```text
.onrender.com
```

Share that link with other users.

This project already includes:

```text
Procfile
render.yaml
/health
gunicorn
```

Those files help public hosting services run the Flask app correctly.

## Example Alert

```text
Multiple failed login attempts from an unusual country followed by a successful login to an administrator account.
```

Expected result:

```text
Incident Type: Brute Force / Account Compromise
Severity: High
Playbook: Account Compromise Response
```

## Future ML Upgrade Ideas

After the basic app works, you can add machine learning by:

1. Creating a CSV dataset of alerts.
2. Adding labels such as `phishing`, `malware`, `brute_force`, and `data_exfiltration`.
3. Training a text classifier with scikit-learn.
4. Replacing the keyword classifier in `classifier.py`.

Suggested dataset columns:

```text
alert_text,incident_type,severity
```
