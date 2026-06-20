# 🔐 Password Strength Checker

A Flask web app that evaluates password strength in real time using length, character variety, common-password blocklist checks, pattern detection, and entropy-based crack-time estimation.

## Live Demo
*(Add your deployed link here once hosted, e.g. on Render)*

---

## Features
- Real-time strength meter (color-coded bar: red / yellow / green) as you type
- Checks: length, uppercase/lowercase/digits/special chars, common/leaked passwords, repeated/sequential/keyboard patterns
- Entropy calculation (bits of randomness)
- Estimated "time to crack"
- Specific, actionable improvement tips
- Unit tested with `pytest`

---

## Project Structure
```
password-strength-checker/
│
├── app.py                      # Flask routes
├── strength_checker.py         # Core scoring logic
├── common_passwords.txt        # Blocklist
├── requirements.txt
├── Procfile                    # For Render/Heroku deployment
├── .gitignore
├── README.md
│
├── templates/
│   └── index.html
│
├── static/
│   ├── style.css
│   └── script.js
│
└── tests/
    └── test_strength_checker.py
```

---

## How It Works

### Scoring logic (`strength_checker.py`)
| Check | Effect |
|---|---|
| Length ≥ 8 / ≥ 12 | +1 / +2 |
| Has lowercase, uppercase, digit, special char | +1 each |
| Found in common password list | -3 |
| Repeated chars (`aaaa`) | -1 per issue |
| Sequential chars (`1234`, `abcd`) | -1 per issue |
| Keyboard pattern (`qwerty`) | -1 per issue |

Final score → **Weak** (0-2), **Medium** (3-4), **Strong** (5+)

### Entropy & crack time
Entropy (bits) = password length × log2(character pool size). This is converted into a rough "time to crack" assuming 1 billion guesses/second.

---

## Run Locally

```bash
git clone https://github.com/<your-username>/password-strength-checker.git
cd password-strength-checker
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Visit `http://localhost:5000`

## Run Tests
```bash
pytest tests/
```

---

## Deploying to GitHub

```bash
git init
git add .
git commit -m "Initial commit: password strength checker"
git remote add origin https://github.com/<your-username>/password-strength-checker.git
git branch -M main
git push -u origin main
```

## Deploying Live (Render — free & simple)
1. Push code to GitHub (above)
2. Go to [render.com](https://render.com) → New → Web Service → connect your GitHub repo
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Deploy — Render auto-redeploys on every `git push`

*(Railway and PythonAnywhere work similarly if you prefer those instead.)*

---

## Possible Extensions
- Integrate the [zxcvbn](https://github.com/dropbox/zxcvbn) library for more realistic strength estimation
- Check against the Have I Been Pwned API (k-anonymity, password never leaves device in full)
- Add a password generator for weak inputs
- Add GitHub Actions CI to auto-run `pytest` on every push

---

## Tech Stack
Python · Flask · HTML/CSS/JavaScript · pytest
