# =============================================================================
# app.py - Phishing Email Screenshot Detection Web App v1.1
# Main Streamlit UI file
# =============================================================================

import re
import streamlit as st
from PIL import Image
import pytesseract
from detector import PhishingDetector

# =============================================================================
# Page Configuration
# =============================================================================
st.set_page_config(
    page_title="Phishing Email Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =============================================================================
# Custom CSS
# =============================================================================
st.markdown("""
    <style>
        .result-card {
            padding: 18px 24px;
            border-radius: 10px;
            margin: 10px 0;
            font-size: 15px;
        }
        .phishing-card   { background-color: #3d0000; border-left: 6px solid #ff4b4b; }
        .suspicious-card { background-color: #2e2000; border-left: 6px solid #ffa500; }
        .legitimate-card { background-color: #002e00; border-left: 6px solid #00c853; }
        .not-email-card  { background-color: #1a1a2e; border-left: 6px solid #7c7cff; }
        .score-label {
            font-size: 38px;
            font-weight: 700;
            text-align: center;
        }
        .indicator-item {
            padding: 6px 10px;
            border-radius: 6px;
            margin: 4px 0;
            background-color: #1e1e2e;
            border-left: 4px solid #ffa500;
            font-size: 14px;
        }
        .section-header {
            font-size: 18px;
            font-weight: 600;
            color: #90caf9;
            margin-top: 20px;
            margin-bottom: 8px;
            border-bottom: 1px solid #333;
            padding-bottom: 4px;
        }
        .found-header {
            padding: 6px 12px;
            border-radius: 6px;
            background-color: #002e00;
            border-left: 4px solid #00c853;
            margin: 3px 0;
            font-size: 13px;
            color: #aaffaa;
        }
        .missing-header {
            padding: 6px 12px;
            border-radius: 6px;
            background-color: #2a1a00;
            border-left: 4px solid #ffa500;
            margin: 3px 0;
            font-size: 13px;
            color: #ffddaa;
        }
    </style>
""", unsafe_allow_html=True)


# =============================================================================
# Email Validation Logic
# =============================================================================

# Standard email header fields - at least 2 must be present
EMAIL_HEADERS = [
    r"\bfrom\s*:",
    r"\bto\s*:",
    r"\bsubject\s*:",
    r"\bdate\s*:",
    r"\breply.to\s*:",
    r"\bcc\s*:",
    r"\bbcc\s*:",
    r"\bsent\s*:",
    r"\bmessage.id\s*:",
    r"\bmime.version\s*:",
]

# Secondary signals - email body clues
EMAIL_BODY_SIGNALS = [
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",  # any email address
    r"unsubscribe",
    r"dear\s+\w+",
    r"regards",
    r"sincerely",
    r"click here",
    r"inbox",
    r"reply",
    r"forward",
    r"attachment",
    r"sent from",
    r"do not reply",
]


def check_is_email(text: str) -> dict:
    """
    Analyses extracted OCR text to determine whether it looks like an email.

    Returns a dict:
        is_email       : bool   - True if we're confident it's an email
        confidence     : str    - "high" / "medium" / "low"
        headers_found  : list   - which email headers were detected
        signals_found  : int    - count of secondary email body signals
        reason         : str    - human-readable explanation
    """
    lower = text.lower()

    # Check for email headers
    headers_found = []
    for pattern in EMAIL_HEADERS:
        if re.search(pattern, lower):
            # Extract clean label for display
            label = pattern.replace(r"\b", "").replace(r"\s*:", "").replace(".", " ").strip()
            headers_found.append(label.capitalize() + ":")

    # Check for secondary body signals
    signals_found = sum(1 for sig in EMAIL_BODY_SIGNALS if re.search(sig, lower))

    # Check for email address anywhere in text
    has_email_address = bool(re.search(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text
    ))

    # Decision logic
    if len(headers_found) >= 2:
        return {
            "is_email": True,
            "confidence": "high",
            "headers_found": headers_found,
            "signals_found": signals_found,
            "reason": f"Found {len(headers_found)} email headers: {', '.join(headers_found[:4])}"
        }
    elif len(headers_found) == 1 and (signals_found >= 2 or has_email_address):
        return {
            "is_email": True,
            "confidence": "medium",
            "headers_found": headers_found,
            "signals_found": signals_found,
            "reason": f"Found header '{headers_found[0]}' plus {signals_found} email body signals."
        }
    elif has_email_address and signals_found >= 3:
        return {
            "is_email": True,
            "confidence": "medium",
            "headers_found": headers_found,
            "signals_found": signals_found,
            "reason": f"Found an email address and {signals_found} email body signals."
        }
    else:
        return {
            "is_email": False,
            "confidence": "low",
            "headers_found": headers_found,
            "signals_found": signals_found,
            "reason": (
                f"Only {len(headers_found)} email header(s) and {signals_found} body signal(s) detected. "
                "This does not appear to be an email screenshot."
            )
        }


# =============================================================================
# Report Builder
# =============================================================================
def build_report(text: str, result: dict, email_check: dict) -> str:
    sep = "=" * 60
    lines = [
        sep,
        "  PHISHING EMAIL SCREENSHOT DETECTOR - ANALYSIS REPORT",
        sep,
        f"Email Validated  : {'YES (' + email_check['confidence'] + ' confidence)' if email_check['is_email'] else 'NO'}",
        f"Classification   : {result['classification']}",
        f"Risk Score       : {result['risk_score']} / {result['max_possible_score']}",
        f"Confidence       : {result['confidence_pct']}%",
        "",
        "SCORE BREAKDOWN",
        "-" * 40,
    ]
    for cat, pts in result["score_breakdown"].items():
        lines.append(f"  {cat:<35} +{pts} pts")

    lines += ["", "DETECTED INDICATORS", "-" * 40]
    if result["indicators"]:
        for ind in result["indicators"]:
            lines.append(f"  [!] {ind}")
    else:
        lines.append("  None detected.")

    lines += [
        "",
        "EXTRACTED OCR TEXT",
        "-" * 40,
        text.strip(),
        "",
        sep,
        "Generated by Phishing Email Screenshot Detector v1.1",
        sep,
    ]
    return "\n".join(lines)


# =============================================================================
# SIDEBAR
# =============================================================================
with st.sidebar:
    st.title("⚙️ Settings")
    st.markdown("---")

    st.markdown("### 🎚️ Risk Thresholds")
    suspicious_threshold = st.slider(
        "Suspicious Threshold (min score)",
        min_value=1, max_value=9, value=3,
        help="Score out of 10. At or above this = Suspicious."
    )
    phishing_threshold = st.slider(
        "Phishing Threshold (min score)",
        min_value=2, max_value=10, value=6,
        help="Score out of 10. At or above this = Phishing."
    )

    st.markdown("---")
    st.markdown("### 🔍 OCR Language")
    ocr_lang = st.selectbox(
        "Tesseract Language",
        options=["eng", "eng+fra", "eng+deu"],
        index=0,
    )

    st.markdown("---")
    st.markdown("### 🔒 Email Validation")
    strict_mode = st.toggle(
        "Strict Mode",
        value=True,
        help=(
            "ON: Reject images that don't look like emails.\n"
            "OFF: Analyse any image (less accurate)."
        )
    )

    st.markdown("---")
    st.info(
        "**Phishing Email Detector v1.1**\n\n"
        "Rule-based phishing detection from email screenshots "
        "using OCR + keyword analysis.\n\nNo ML. No paid APIs."
    )


# =============================================================================
# MAIN HEADER
# =============================================================================
st.title("🛡️ Phishing Email Screenshot Detector")
st.markdown(
    "Upload a **screenshot of an email** (PNG or JPG). "
    "The app validates it is an email, extracts text via OCR, "
    "and analyses it for phishing indicators."
)
st.markdown("---")


# =============================================================================
# FILE UPLOAD + PREVIEW
# =============================================================================
col_upload, col_preview = st.columns([1, 1])

with col_upload:
    st.markdown('<div class="section-header">📂 Upload Email Screenshot</div>', unsafe_allow_html=True)
    st.caption("Only screenshots of real emails will be analysed. Diagrams, charts, and other images will be rejected.")
    uploaded_file = st.file_uploader(
        label="Choose a PNG or JPG file",
        type=["png", "jpg", "jpeg"],
        help="Upload a screenshot of the suspicious email."
    )
    analyze_btn = st.button("🔎 Analyze Email", use_container_width=True, type="primary")

with col_preview:
    st.markdown('<div class="section-header">🖼️ Image Preview</div>', unsafe_allow_html=True)
    if uploaded_file is not None:
        image = Image.open(uploaded_file)
        st.image(image, caption="Uploaded Screenshot", use_container_width=True)
    else:
        st.info("Upload an image on the left to see a preview here.")


# =============================================================================
# ANALYSIS ENGINE
# =============================================================================
if uploaded_file is not None and analyze_btn:
    st.markdown("---")

    # ── Step 1: OCR ──────────────────────────────────────────────────────────
    with st.spinner("🔍 Extracting text via OCR ..."):
        try:
            image = Image.open(uploaded_file)
            if image.mode not in ("RGB", "L"):
                image = image.convert("RGB")
            custom_config = f"--oem 3 --psm 6 -l {ocr_lang}"
            extracted_text = pytesseract.image_to_string(image, config=custom_config)
            ocr_success = True
        except Exception as exc:
            extracted_text = ""
            ocr_success = False
            st.error(
                f"OCR Error: {exc}\n\n"
                "Make sure Tesseract is installed. See README for instructions."
            )

    # ── Step 2: Email Validation ─────────────────────────────────────────────
    if ocr_success and extracted_text.strip():
        email_check = check_is_email(extracted_text)

        # Show validation result
        st.markdown("## 📧 Email Validation")
        val_col1, val_col2 = st.columns([2, 1])

        with val_col1:
            if email_check["is_email"]:
                conf_color = "#00c853" if email_check["confidence"] == "high" else "#ffa500"
                st.markdown(
                    f'<div class="result-card legitimate-card">'
                    f'<b style="font-size:16px">✅ Valid Email Screenshot Detected</b><br>'
                    f'Confidence: <b style="color:{conf_color}">{email_check["confidence"].upper()}</b><br>'
                    f'<small>{email_check["reason"]}</small>'
                    f'</div>',
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    f'<div class="result-card not-email-card">'
                    f'<b style="font-size:16px">🚫 This does not appear to be an email screenshot</b><br><br>'
                    f'{email_check["reason"]}<br><br>'
                    f'<b>This app only analyses email screenshots.</b> Please upload a screenshot '
                    f'of an actual email (from Gmail, Outlook, Apple Mail, etc.)'
                    f'</div>',
                    unsafe_allow_html=True
                )

        with val_col2:
            st.markdown('<div class="section-header">📋 Header Check</div>', unsafe_allow_html=True)
            all_labels = ["From:", "To:", "Subject:", "Date:", "Reply-to:", "Cc:"]
            for label in all_labels:
                found = any(label.lower() in h.lower() for h in email_check["headers_found"])
                if found:
                    st.markdown(f'<div class="found-header">✅ {label}</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="missing-header">— {label} (not found)</div>', unsafe_allow_html=True)

        # ── Block non-emails in strict mode ───────────────────────────────────
        if not email_check["is_email"] and strict_mode:
            st.warning(
                "**Strict Mode is ON** — analysis blocked.\n\n"
                "To analyse this image anyway, turn OFF **Strict Mode** in the sidebar. "
                "Note that results will be unreliable for non-email images."
            )
            st.stop()

        if not email_check["is_email"] and not strict_mode:
            st.warning(
                "⚠️ Strict Mode is OFF — proceeding with analysis, "
                "but this image may not be an email so results may be inaccurate."
            )

        # ── Step 3: Phishing Detection ────────────────────────────────────────
        st.markdown("---")
        st.markdown("## 📊 Analysis Results")

        with st.spinner("🧠 Running phishing detection engine ..."):
            detector = PhishingDetector(
                suspicious_threshold=suspicious_threshold,
                phishing_threshold=phishing_threshold
            )
            result = detector.analyze(extracted_text)

        # ── Step 4: Results UI ────────────────────────────────────────────────
        col_score, col_class = st.columns([1, 2])

        with col_score:
            st.markdown('<div class="section-header">🎯 Risk Score</div>', unsafe_allow_html=True)
            score     = result["risk_score"]
            max_score = result["max_possible_score"]
            color_map = {"Phishing": "#ff4b4b", "Suspicious": "#ffa500", "Legitimate": "#00c853"}
            sc = color_map[result["classification"]]
            st.markdown(
                f'<div class="score-label" style="color:{sc}">{score} / {max_score}</div>',
                unsafe_allow_html=True
            )
            st.progress(min(score / max_score, 1.0))
            st.markdown(
                f"<p style='text-align:center;color:#aaa;'>"
                f"Confidence: <b style='color:{sc}'>{result['confidence_pct']}%</b></p>",
                unsafe_allow_html=True
            )

        with col_class:
            st.markdown('<div class="section-header">🏷️ Classification</div>', unsafe_allow_html=True)
            cls = result["classification"]
            badge_cfg = {
                "Phishing": (
                    "phishing-card", "🚨", "HIGH RISK",
                    "This email exhibits strong phishing characteristics. "
                    "Do NOT click any links, download attachments, or provide personal information."
                ),
                "Suspicious": (
                    "suspicious-card", "⚠️", "MEDIUM RISK",
                    "This email shows suspicious patterns. Proceed with caution and "
                    "independently verify the sender before taking any action."
                ),
                "Legitimate": (
                    "legitimate-card", "✅", "LOW RISK",
                    "No major phishing indicators detected. "
                    "However, always remain cautious with unexpected emails."
                ),
            }
            card_class, icon, risk_label, msg = badge_cfg[cls]
            st.markdown(
                f'<div class="result-card {card_class}">'
                f'<span style="font-size:28px">{icon}</span>'
                f'<b style="font-size:22px"> {cls} - {risk_label}</b>'
                f'<br><br>{msg}</div>',
                unsafe_allow_html=True
            )

        st.markdown("---")

        col_ind, col_text = st.columns([1, 1])

        with col_ind:
            st.markdown('<div class="section-header">🚩 Detected Indicators</div>', unsafe_allow_html=True)
            if result["indicators"]:
                for ind in result["indicators"]:
                    st.markdown(
                        f'<div class="indicator-item">⚑ {ind}</div>',
                        unsafe_allow_html=True
                    )
            else:
                st.success("✅ No suspicious indicators detected.")

            st.markdown('<div class="section-header">📋 Score Breakdown</div>', unsafe_allow_html=True)
            for category, points in result["score_breakdown"].items():
                color = "#ff4b4b" if points > 0 else "#666"
                st.markdown(
                    f"<p style='margin:3px 0;color:{color};'>"
                    f"<b>{category}:</b> +{points} pts</p>",
                    unsafe_allow_html=True
                )

        with col_text:
            st.markdown('<div class="section-header">📄 Extracted OCR Text</div>', unsafe_allow_html=True)
            st.text_area(
                label="Raw text extracted from the image:",
                value=extracted_text,
                height=360,
                key="ocr_output"
            )

        # Download Report
        st.markdown("---")
        st.markdown('<div class="section-header">📥 Download Analysis Report</div>', unsafe_allow_html=True)
        report_data = build_report(extracted_text, result, email_check)
        st.download_button(
            label="⬇️ Download Full Analysis Report (.txt)",
            data=report_data,
            file_name="phishing_analysis_report.txt",
            mime="text/plain",
            use_container_width=True
        )

    elif ocr_success and not extracted_text.strip():
        st.warning(
            "OCR completed but extracted no text.\n\n"
            "Possible causes:\n"
            "- Image resolution is too low\n"
            "- Image is blurry, skewed, or heavily compressed\n"
            "- Email body is itself a raster image\n\n"
            "Fix: Take a cleaner, higher-resolution screenshot and try again."
        )

elif uploaded_file is None and analyze_btn:
    st.warning("Please upload an image file before clicking Analyze.")
