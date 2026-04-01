# 🛡️ Phishing Email Screenshot Detector

> A beginner-friendly, production-structured cybersecurity web application that
> detects phishing emails from screenshots using **OCR + rule-based analysis**.
> No machine learning. No paid APIs. Built with Python + Streamlit.

---

## 📋 Table of Contents
1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Technical Architecture](#technical-architecture)
4. [Folder Structure](#folder-structure)
5. [Windows Setup Guide](#windows-setup-guide)
6. [macOS / Linux Setup Guide](#macos--linux-setup-guide)
7. [Running the App](#running-the-app)
8. [How to Use](#how-to-use)
9. [Detection Logic Explained](#detection-logic-explained)
10. [Troubleshooting & Common OCR Errors](#troubleshooting--common-ocr-errors)
11. [Customisation](#customisation)
12. [Real-World Comparison](#real-world-comparison)
13. [Interview Preparation](#interview-preparation)
14. [Resume Description](#resume-description)

---

## Project Overview

This project analyses a **screenshot of an email** to determine whether the email
is **Legitimate**, **Suspicious**, or a **Phishing attempt**.

### How it works (high level)
```
User uploads screenshot
        ↓
Tesseract OCR extracts text from the image
        ↓
Rule-based detection engine scans the text
        ↓
Risk score is calculated across 8 categories
        ↓
Email is classified: Legitimate / Suspicious / Phishing
        ↓
Results displayed in Streamlit web UI
```

---

## Features

| Feature | Description |
|---|---|
| OCR Text Extraction | Tesseract + Pillow extracts text from any email screenshot |
| Phishing Keyword Detection | Matches against 100+ keywords loaded from an editable `.txt` file |
| Suspicious URL Detection | 13 regex patterns detect spoofed/malicious links |
| Urgency Language Detection | Identifies 30+ high-pressure phrases |
| Attachment Detection | Flags 15 dangerous file extension types |
| Sender-Domain Mismatch | Checks if From: domain matches the claimed brand |
| Free-Hosting Domain Detection | Flags URLs on known free-hosting platforms |
| IP-in-URL Detection | Detects raw IP address URLs (classic phishing tactic) |
| ALL-CAPS Detection | Identifies panic-inducing all-caps urgency words |
| Adjustable Thresholds | Slider controls for Suspicious/Phishing cutoffs |
| Risk Score + Confidence % | Numeric score out of 51 with percentage confidence |
| Downloadable Report | Full analysis exported as `.txt` file |

---

## Technical Architecture

```
phishing_screenshot_app/
│
├── app.py              ← Streamlit frontend (UI, file upload, result display)
├── detector.py         ← Detection engine (8 rule-based checks + scoring)
├── phishing_keywords.txt ← Editable keyword list (loaded at runtime)
├── requirements.txt    ← Python dependencies
├── README.md           ← This file
└── sample_test_guide.txt ← How to test the app manually
```

**Data flow:**
```
app.py  →  PIL.Image  →  pytesseract  →  extracted_text
                                              ↓
                                      detector.py
                                      ├── _check_keywords()
                                      ├── _check_urls()
                                      ├── _check_urgency()
                                      ├── _check_attachments()
                                      ├── _check_domain_mismatch()
                                      ├── _check_free_hosting()
                                      ├── _check_ip_in_url()
                                      └── _check_all_caps()
                                              ↓
                                      result dict → app.py → Streamlit UI
```

---

## Windows Setup Guide

### Step 1 — Install Python 3.10+

1. Visit https://www.python.org/downloads/
2. Download the latest **Python 3.10.x** or **3.11.x** Windows installer.
3. Run the installer.
   - ✅ **IMPORTANT:** Check **"Add Python to PATH"** before clicking Install Now.
4. Verify installation:
   ```
   python --version
   ```
   Expected output: `Python 3.10.x` or later.

### Step 2 — Install Tesseract OCR (Windows)

Tesseract is an open-source OCR engine maintained by Google. It is a **separate
binary** that `pytesseract` (a Python wrapper) calls behind the scenes.

1. Download the **Windows installer** from:
   ```
   https://github.com/UB-Mannheim/tesseract/wiki
   ```
   Direct link (64-bit): `tesseract-ocr-w64-setup-5.x.x.exe`

2. Run the installer.
   - Note the installation path (default: `C:\Program Files\Tesseract-OCR`)
   - Keep default options selected.

3. Add Tesseract to your System PATH:
   - Search **"Environment Variables"** in the Windows search bar.
   - Click **"Edit the system environment variables"**.
   - Under **System variables**, click **Path → Edit → New**.
   - Add: `C:\Program Files\Tesseract-OCR`
   - Click OK on all dialogs.

4. Verify:
   ```
   tesseract --version
   ```
   Expected output: `tesseract 5.x.x ...`

5. **Alternative: If PATH setup doesn't work**, open `app.py` and add this line
   right after the imports at the top:
   ```python
   pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
   ```

### Step 3 — Install VS Code (Optional but Recommended)

1. Download from: https://code.visualstudio.com/
2. Install with defaults.
3. Open VS Code and install the **Python extension** by Microsoft.

### Step 4 — Clone or Download the Project

Option A — Download ZIP:
- Download and extract the project folder.

Option B — If you have Git:
```bash
git clone https://github.com/your-username/phishing_screenshot_app.git
cd phishing_screenshot_app
```

### Step 5 — Create a Virtual Environment (Recommended)

```bash
cd phishing_screenshot_app
python -m venv venv
venv\Scripts\activate
```

You should see `(venv)` at the start of your terminal prompt.

### Step 6 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

This installs: `streamlit`, `Pillow`, `pytesseract`, `typing-extensions`.

---

## macOS / Linux Setup Guide

### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Tesseract
brew install tesseract

# Install Python dependencies
pip3 install -r requirements.txt
```

### Ubuntu / Debian Linux

```bash
sudo apt-get update
sudo apt-get install tesseract-ocr -y
sudo apt-get install libtesseract-dev -y
pip3 install -r requirements.txt
```

---

## Running the App

```bash
# Make sure you're inside the project folder with venv active
streamlit run app.py
```

The app will open automatically in your browser at:
```
http://localhost:8501
```

To stop the server: Press `Ctrl + C` in the terminal.

---

## How to Use

1. **Open the app** at `http://localhost:8501`.
2. **(Optional)** Adjust the Risk Thresholds in the sidebar.
3. Click **"Browse files"** under Upload Email Screenshot.
4. Upload any **PNG or JPG** screenshot of an email.
5. Click the **"🔎 Analyze Email"** button.
6. View:
   - Image preview
   - Extracted OCR text
   - Risk score + progress bar
   - Classification badge (Legitimate / Suspicious / Phishing)
   - Detected indicators list
   - Score breakdown by category
7. Optionally **download** the full analysis report.

---

## Detection Logic Explained

### Risk Scoring System

| Category | Points/Match | Cap |
|---|---|---|
| Phishing Keywords | 2 per keyword | 10 max |
| Suspicious URLs | 3 per URL | 9 max |
| Urgency Language | 2 per phrase | 6 max |
| Suspicious Attachments | 3 per ext | 9 max |
| Sender-Domain Mismatch | 4 (flat) | 4 max |
| Free-Hosting Domain | 3 per domain | 6 max |
| IP Address in URL | 4 (flat) | 4 max |
| ALL-CAPS Urgency | 1 per word | 3 max |
| **Total Max** | | **51** |

### Classification Thresholds (default)

| Score Range | Classification |
|---|---|
| 0 – 2 | ✅ Legitimate |
| 3 – 6 | ⚠️ Suspicious |
| 7+ | 🚨 Phishing |

Thresholds are adjustable via the sidebar sliders.

---

## Troubleshooting & Common OCR Errors

### ❌ `TesseractNotFoundError`
**Cause:** Tesseract binary is not installed or not in PATH.
**Fix (Windows):** Add `C:\Program Files\Tesseract-OCR` to System PATH
**Fix (code):**
```python
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
```

### ❌ OCR extracts garbled or no text
**Cause:** Low-resolution, blurry, or skewed image.
**Fix:**
- Use a higher-resolution screenshot (at least 800x600 px recommended).
- Ensure the email text is readable and not anti-aliased at a tiny font size.
- Try cropping only the email text area.
- Increase zoom level before taking a screenshot.

### ❌ OCR misreads characters (e.g., 'l' → '1', 'O' → '0')
**Cause:** Tesseract has trouble with similar-looking characters in small fonts.
**Fix:**
- Scale up the image before OCR using Pillow:
  ```python
  image = image.resize((image.width * 2, image.height * 2), Image.LANCZOS)
  ```
- Convert to grayscale + increase contrast:
  ```python
  from PIL import ImageEnhance
  image = image.convert("L")
  image = ImageEnhance.Contrast(image).enhance(2.0)
  ```

### ❌ `ModuleNotFoundError: No module named 'streamlit'`
**Fix:** Make sure virtual environment is active and run:
```bash
pip install -r requirements.txt
```

### ❌ `AttributeError: module 'PIL.Image' has no attribute 'ANTIALIAS'`
**Cause:** Pillow 10+ removed `ANTIALIAS`. Use `LANCZOS` instead.
**Fix:** Update to the latest code (already handled in this project).

### ❌ Port 8501 already in use
**Fix:**
```bash
streamlit run app.py --server.port 8502
```

---

## Customisation

### Adding New Keywords
Open `phishing_keywords.txt` and add one keyword or phrase per line.
No code changes needed — keywords are loaded at runtime.

### Adjusting Scores
Open `detector.py` and modify the `SCORE_WEIGHTS` or `SCORE_CAPS` dictionaries.

### Adding New URL Patterns
Add a new regex string to the `SUSPICIOUS_URL_PATTERNS` list in `detector.py`.

### Adding New Urgency Phrases
Add strings to the `URGENCY_PHRASES` list in `detector.py`.

---

## Real-World Comparison

| Feature | This Project | Enterprise Solutions |
|---|---|---|
| Approach | Rule-based heuristics | ML + threat intelligence feeds |
| Keyword detection | Static .txt file | Continuously updated threat DB |
| URL analysis | Regex patterns | Live reputation lookup (VirusTotal etc.) |
| Attachment analysis | Extension name only | Sandboxed execution + hash lookup |
| Speed | Instant | Varies (ms to seconds for live lookups) |
| Accuracy | Moderate (good for demos) | Very high (>99% with tuning) |
| Cost | Free | Expensive (enterprise licenses) |
| Explainability | Full (rule-based = transparent) | Often a black box (deep learning) |
| Internet required | No (fully offline) | Yes (live feeds) |

**Key insight:** Real-world systems like Google Safe Browsing, Microsoft Defender
for Office 365, and Proofpoint combine rule-based filters (like this project) as
the first layer, then use ML models for edge cases, and finally check against
live threat intelligence databases. Rule-based systems are still heavily used in
production because they are fast, transparent, and explainable.

---

## Interview Preparation

### "Walk me through the architecture of your project."

> The project has two main components. `app.py` handles the Streamlit user
> interface — file upload, OCR via pytesseract + Pillow, and displaying results.
> `detector.py` is the detection engine, which is completely decoupled from the UI.
> It takes raw text as input and runs eight independent rule-based checks: keyword
> matching, URL regex patterns, urgency language, dangerous attachment extensions,
> sender-domain mismatch, free-hosting domain detection, IP-in-URL detection, and
> ALL-CAPS urgency detection. Each check returns a score contribution. The scores
> are summed and mapped to a classification label using adjustable thresholds.

### "Why no machine learning?"

> ML requires labelled training data, compute resources, and a model serving
> infrastructure. For many use cases — especially first-level triage — rule-based
> systems are faster, fully explainable, and don't require retraining. Real
> production systems actually use rule-based filters as the first line of defence
> before escalating to ML models.

### "What are the limitations of your approach?"

> The main limitations are: (1) OCR accuracy depends on image quality — blurry
> screenshots produce poor results; (2) our keyword list can produce false
> positives for legitimate marketing emails; (3) we don't do live URL reputation
> lookups; (4) the sender-domain mismatch check relies on the From: field being
> visible and correctly OCR'd. These are known limitations that would be addressed
> in a production system.

### "How would you improve this?"

> I would (1) add image pre-processing (contrast enhancement, deskewing) to
> improve OCR quality; (2) integrate the VirusTotal free API for URL reputation;
> (3) add a feedback mechanism to let users mark false positives, building a
> dataset for future ML training; (4) containerise with Docker for easy deployment;
> (5) add a REST API layer using FastAPI so other systems could call the detector.

### "What is the risk score based on?"

> Each detection category contributes a weighted score. For example, keywords
> found in the text score 2 points each (capped at 10), while an IP-address-based
> URL scores 4 points flat because it's a very strong indicator. The total is out
> of 51. The confidence percentage is simply `(score / 51) * 100`. This design
> makes the scoring system fully transparent and adjustable.

---

## Resume Description

```
Phishing Email Screenshot Detector | Python, Streamlit, Tesseract OCR
• Built a rule-based cybersecurity web application that analyses email screenshots
  for phishing indicators using OCR text extraction and an 8-category scoring engine.
• Implemented detection heuristics including keyword matching, regex-based URL
  analysis, urgency language detection, sender-domain mismatch, and suspicious
  attachment detection — achieving transparent, explainable results with no ML.
• Designed a modular architecture (UI/detection engine separation) with adjustable
  risk thresholds and downloadable reports, structured to production-code standards.
```
