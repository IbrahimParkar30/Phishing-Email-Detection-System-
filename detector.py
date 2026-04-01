# =============================================================================
# detector.py - Rule-Based Phishing Detection Engine v1.1
# Score displayed out of 10 (normalized from internal raw score).
# No machine learning. Pure rule-based heuristics.
# =============================================================================

import re
from typing import List, Dict, Tuple


class PhishingDetector:
    """
    Analyses text from an email screenshot and returns:
      - A normalized risk score out of 10
      - A classification: Legitimate / Suspicious / Phishing
      - A list of detected indicators
      - A category-level score breakdown

    Scoring design:
      Each category has internal raw points and a cap.
      The raw total is then normalized to a clean 0-10 scale.
      This means a score of 3/51 raw = 1/10 displayed (correct for legit email).
      A heavy phishing email scoring 35/51 raw = 7/10 displayed.

    Default thresholds (adjustable via sidebar):
      0-2  -> Legitimate
      3-5  -> Suspicious
      6-10 -> Phishing
    """

    # ── Internal raw scoring weights (per match) ──────────────────────────
    SCORE_WEIGHTS = {
        "Phishing Keywords":      2,
        "Suspicious URLs":        3,
        "Urgency Language":       2,
        "Suspicious Attachments": 3,
        "Sender-Domain Mismatch": 4,
        "Free-Hosting Domain":    3,
        "IP Address in URL":      4,
        "ALL-CAPS Urgency":       1,
    }

    # ── Per-category caps (prevent one category dominating) ───────────────
    SCORE_CAPS = {
        "Phishing Keywords":      10,
        "Suspicious URLs":        9,
        "Urgency Language":       6,
        "Suspicious Attachments": 9,
        "Sender-Domain Mismatch": 4,
        "Free-Hosting Domain":    6,
        "IP Address in URL":      4,
        "ALL-CAPS Urgency":       3,
    }

    # Internal max (sum of all caps = 51)
    _INTERNAL_MAX = sum(SCORE_CAPS.values())

    # ── Public display max ─────────────────────────────────────────────────
    MAX_DISPLAY_SCORE = 10

    # ── Urgency phrases ────────────────────────────────────────────────────
    # Specific multi-word phrases only - avoids false positives on legit emails
    URGENCY_PHRASES = [
        "act now",
        "immediate action",
        "action required",
        "account suspended",
        "account will be closed",
        "verify your account",
        "confirm your identity",
        "your account has been compromised",
        "limited time offer",
        "expires today",
        "respond immediately",
        "failure to respond",
        "your password has expired",
        "update your payment",
        "billing information required",
        "suspended account",
        "unauthorized access detected",
        "unusual activity detected",
        "click here immediately",
        "your account will be terminated",
        "you have been selected",
        "congratulations you won",
        "claim your prize",
        "winner notification",
        "do not ignore this",
        "last warning",
        "final notice",
        "account will be deleted",
        "verify now to avoid",
        "your access will be blocked",
    ]

    # ── Suspicious attachment extensions (executables / archives only) ─────
    # Note: .pdf, .doc, .docx are intentionally excluded - common legit attachments
    SUSPICIOUS_EXTENSIONS = [
        r"\.exe\b",
        r"\.scr\b",
        r"\.bat\b",
        r"\.cmd\b",
        r"\.vbs\b",
        r"\.jar\b",
        r"\.msi\b",
        r"\.pif\b",
        r"\.hta\b",
        r"\.wsf\b",
        r"\.ps1\b",
    ]

    # ── Suspicious archive extensions (separate, lower weight) ────────────
    ARCHIVE_EXTENSIONS = [
        r"\.zip\b",
        r"\.rar\b",
        r"\.7z\b",
    ]

    # ── Free / suspicious hosting domains ─────────────────────────────────
    FREE_HOSTING_DOMAINS = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "ow.ly",
        "000webhostapp.com",
        "wixsite.com",
        "netlify.app",
        "ngrok.io",
        "firebaseapp.com",
        "pages.dev",
        "glitch.me",
        "repl.co",
    ]

    # ── Suspicious URL patterns ────────────────────────────────────────────
    SUSPICIOUS_URL_PATTERNS = [
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",       # IP-based URL
        r"https?://[^\s]*@[^\s]*",                               # URL with @
        r"https?://[^\s]*-secure[^\s]*",                         # fake 'secure'
        r"https?://[^\s]*login[^\s]*\.[a-z]{2,}(?!/)",          # login phishing
        r"https?://[^\s]*verify[^\s]*\.[a-z]{2,}(?!/)",         # verify phishing
        r"https?://[^\s]*paypal[^\s]*(?<!paypal\.com)",          # fake PayPal
        r"https?://[^\s]*amazon[^\s]*(?<!amazon\.com)",          # fake Amazon
        r"https?://[^\s]*apple[^\s]*(?<!apple\.com)",            # fake Apple
        r"https?://[^\s]*microsoft[^\s]*(?<!microsoft\.com)",    # fake Microsoft
        r"https?://[^\s]*google[^\s]*(?<!google\.com)",          # fake Google
    ]

    # ── Brands commonly spoofed ────────────────────────────────────────────
    BRAND_KEYWORDS = [
        "paypal", "amazon", "apple", "microsoft", "google",
        "facebook", "netflix", "bank of america", "chase",
        "wells fargo", "citibank", "ebay", "instagram",
        "twitter", "linkedin", "dropbox", "docusign",
    ]

    # ── ALL-CAPS panic words ───────────────────────────────────────────────
    CAPS_WORDS = [
        "URGENT", "WARNING", "ALERT", "IMPORTANT",
        "ACT NOW", "VERIFY NOW", "ACTION REQUIRED",
        "ACCOUNT SUSPENDED", "FINAL NOTICE",
    ]

    # ==========================================================================
    def __init__(
        self,
        keywords_file: str = "phishing_keywords.txt",
        suspicious_threshold: int = 3,   # out of 10
        phishing_threshold: int = 6,     # out of 10
    ):
        self.suspicious_threshold = suspicious_threshold
        self.phishing_threshold   = phishing_threshold
        self.phishing_keywords    = self._load_keywords(keywords_file)

    # ==========================================================================
    # Public API
    # ==========================================================================
    def analyze(self, text: str) -> Dict:
        """
        Main entry. Returns:
        {
            classification    : str          Legitimate / Suspicious / Phishing
            risk_score        : int          0-10 (normalized display score)
            max_possible_score: int          always 10
            raw_score         : int          internal raw score (for debug)
            confidence_pct    : int          0-100
            indicators        : List[str]
            score_breakdown   : Dict[str,int] category -> normalized pts (0-10 scale)
        }
        """
        lower_text = text.lower()
        raw_breakdown: Dict[str, int] = {}
        indicators:    List[str]      = []

        # Run all checks
        checks = [
            ("Phishing Keywords",      self._check_keywords(lower_text)),
            ("Suspicious URLs",        self._check_urls(text)),
            ("Urgency Language",       self._check_urgency(lower_text)),
            ("Suspicious Attachments", self._check_attachments(lower_text)),
            ("Sender-Domain Mismatch", self._check_domain_mismatch(text)),
            ("Free-Hosting Domain",    self._check_free_hosting(lower_text)),
            ("IP Address in URL",      self._check_ip_in_url(text)),
            ("ALL-CAPS Urgency",       self._check_all_caps(text)),
        ]

        for name, (score, found_indicators) in checks:
            raw_breakdown[name] = score
            indicators.extend(found_indicators)

        # Total raw score
        raw_total = sum(raw_breakdown.values())

        # Normalize to 0-10
        display_score = round((raw_total / self._INTERNAL_MAX) * self.MAX_DISPLAY_SCORE)
        display_score = min(display_score, self.MAX_DISPLAY_SCORE)

        # Normalize breakdown values to 0-10 scale for display
        display_breakdown = {
            cat: round((pts / self._INTERNAL_MAX) * self.MAX_DISPLAY_SCORE)
            for cat, pts in raw_breakdown.items()
        }

        classification  = self._classify(display_score)
        confidence_pct  = min(int((display_score / self.MAX_DISPLAY_SCORE) * 100), 100)

        return {
            "classification":     classification,
            "risk_score":         display_score,
            "max_possible_score": self.MAX_DISPLAY_SCORE,
            "raw_score":          raw_total,
            "confidence_pct":     confidence_pct,
            "indicators":         indicators,
            "score_breakdown":    display_breakdown,
        }

    # ==========================================================================
    # Detection Methods
    # ==========================================================================

    def _load_keywords(self, filepath: str) -> List[str]:
        """Load phishing keywords from file. Falls back to built-in list."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return [
                    line.strip().lower()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
        except FileNotFoundError:
            return [
                "verify your account", "confirm your information",
                "update your password", "suspended account",
                "your account has been compromised", "dear customer",
                "dear user", "you have won", "claim your reward",
                "credit card number", "wire transfer", "gift card",
            ]

    def _check_keywords(self, lower_text: str) -> Tuple[int, List[str]]:
        """Match phishing keywords from file."""
        matched = [kw for kw in self.phishing_keywords if kw in lower_text]
        if not matched:
            return 0, []
        raw   = min(len(matched) * self.SCORE_WEIGHTS["Phishing Keywords"],
                    self.SCORE_CAPS["Phishing Keywords"])
        inds  = [f'Phishing keyword: "{kw}"' for kw in matched[:5]]
        if len(matched) > 5:
            inds.append(f"...and {len(matched) - 5} more keyword(s)")
        return raw, inds

    def _check_urls(self, text: str) -> Tuple[int, List[str]]:
        """Detect suspicious URL patterns."""
        matches = []
        for pattern in self.SUSPICIOUS_URL_PATTERNS:
            found = re.findall(pattern, text, re.IGNORECASE)
            for url in found:
                if url not in matches:
                    matches.append(url)
        if not matches:
            return 0, []
        raw  = min(len(matches) * self.SCORE_WEIGHTS["Suspicious URLs"],
                   self.SCORE_CAPS["Suspicious URLs"])
        inds = [f"Suspicious URL: {u[:80]}{'...' if len(u)>80 else ''}" for u in matches[:3]]
        if len(matches) > 3:
            inds.append(f"...and {len(matches)-3} more suspicious URL(s)")
        return raw, inds

    def _check_urgency(self, lower_text: str) -> Tuple[int, List[str]]:
        """Detect urgency/pressure language."""
        matched = [p for p in self.URGENCY_PHRASES if p in lower_text]
        if not matched:
            return 0, []
        raw  = min(len(matched) * self.SCORE_WEIGHTS["Urgency Language"],
                   self.SCORE_CAPS["Urgency Language"])
        inds = [f'Urgency phrase: "{p}"' for p in matched[:3]]
        return raw, inds

    def _check_attachments(self, lower_text: str) -> Tuple[int, List[str]]:
        """
        Detect mentions of dangerous attachment types.
        .pdf, .doc, .docx are safe - NOT flagged.
        Executables and scripts are high risk.
        Archives (.zip, .rar) are medium risk.
        """
        indicators = []
        score = 0

        # High-risk executables (full weight)
        for ext_pattern in self.SUSPICIOUS_EXTENSIONS:
            if re.search(ext_pattern, lower_text, re.IGNORECASE):
                ext = ext_pattern.replace(r"\.", ".").replace(r"\b", "")
                indicators.append(f"Dangerous attachment type detected: {ext}")
                score = min(score + self.SCORE_WEIGHTS["Suspicious Attachments"],
                            self.SCORE_CAPS["Suspicious Attachments"])

        # Medium-risk archives (half weight)
        for ext_pattern in self.ARCHIVE_EXTENSIONS:
            if re.search(ext_pattern, lower_text, re.IGNORECASE):
                ext = ext_pattern.replace(r"\.", ".").replace(r"\b", "")
                indicators.append(f"Archive attachment detected (medium risk): {ext}")
                score = min(score + 1, self.SCORE_CAPS["Suspicious Attachments"])

        return score, indicators

    def _check_domain_mismatch(self, text: str) -> Tuple[int, List[str]]:
        """Check if From: domain matches the claimed brand."""
        from_match = re.search(r"[Ff]rom\s*:\s*[^\n]*", text)
        if not from_match:
            return 0, []
        from_line = from_match.group(0).lower()
        email_match = re.search(
            r"[a-z0-9._%+\-]+@([a-z0-9.\-]+\.[a-z]{2,})", from_line
        )
        if not email_match:
            return 0, []
        sender_domain = email_match.group(1).lower()
        lower_text    = text.lower()
        for brand in self.BRAND_KEYWORDS:
            brand_in_body   = brand in lower_text
            brand_in_domain = (
                brand.replace(" ", "") in sender_domain or
                brand.split()[0] in sender_domain
            )
            if brand_in_body and not brand_in_domain:
                return (
                    self.SCORE_CAPS["Sender-Domain Mismatch"],
                    [f"Sender-domain mismatch: claims to be '{brand}' "
                     f"but sent from '{sender_domain}'"]
                )
        return 0, []

    def _check_free_hosting(self, lower_text: str) -> Tuple[int, List[str]]:
        """Flag links hosted on known free/suspicious platforms."""
        matched = [d for d in self.FREE_HOSTING_DOMAINS if d in lower_text]
        if not matched:
            return 0, []
        raw  = min(len(matched) * self.SCORE_WEIGHTS["Free-Hosting Domain"],
                   self.SCORE_CAPS["Free-Hosting Domain"])
        inds = [f"Free/suspicious hosting domain: {d}" for d in matched]
        return raw, inds

    def _check_ip_in_url(self, text: str) -> Tuple[int, List[str]]:
        """Detect raw IP addresses used as URLs."""
        if re.search(r"https?://(\d{1,3}\.){3}\d{1,3}[/\s]?", text, re.IGNORECASE):
            return (
                self.SCORE_CAPS["IP Address in URL"],
                ["IP address used as URL (legitimate services use domain names, not raw IPs)"]
            )
        return 0, []

    def _check_all_caps(self, text: str) -> Tuple[int, List[str]]:
        """Detect ALL-CAPS panic/urgency words."""
        matched = [w for w in self.CAPS_WORDS if w in text]
        if not matched:
            return 0, []
        raw  = min(len(matched) * self.SCORE_WEIGHTS["ALL-CAPS Urgency"],
                   self.SCORE_CAPS["ALL-CAPS Urgency"])
        inds = [f'ALL-CAPS urgency word: "{w}"' for w in matched]
        return raw, inds

    def _classify(self, display_score: int) -> str:
        """Map normalized score (0-10) to classification label."""
        if display_score >= self.phishing_threshold:
            return "Phishing"
        elif display_score >= self.suspicious_threshold:
            return "Suspicious"
        else:
            return "Legitimate"
