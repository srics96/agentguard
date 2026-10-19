"""Deterministic detectors: sensitive data in text, and what a UI element *does*.

No LLM is involved here. Everything is regex / checksum / keyword based so the
decision path cannot be prompt-injected.
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass

# ---------------------------------------------------------------- data classes

def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


@dataclass
class Hit:
    kind: str
    start: int
    end: int
    text: str


# kind -> list of (pattern, group index whose span is the sensitive part)
_PATTERNS: dict[str, list[tuple[re.Pattern, int]]] = {
    "api_key": [
        (re.compile(r"\b(sk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{16,})"), 1),
        (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), 1),
        (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,})\b"), 1),
        (re.compile(r"\b(xox[abpr]-[A-Za-z0-9\-]{10,})\b"), 1),
        (re.compile(r"(?i)(?:api[\s_-]?key|secret|token)\s*[:=]?\s*\n?\s*([A-Za-z0-9_\-]{12,})"), 1),
    ],
    "ssh_credential": [
        (re.compile(r"(sshpass\s+-p\s*'[^']+'\s*ssh\s+\S+(?:\s+-p\s*\d+)?)"), 1),
        (re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----)"), 1),
    ],
    "password": [
        (re.compile(r"(?i)\b(?:password|passwd|pwd|passcode)\s*[:=]\s*(\S{4,})"), 1),
        # "service → user:secret" style lines (common in notes)
        (re.compile(r"(?:→|->|=>)\s*([\w.\-]+:[^\s]{5,})"), 1),
    ],
    "card_number": [
        (re.compile(r"\b((?:\d[ \-]?){12,18}\d)\b"), 1),  # Luhn-filtered below
        # labelled numbers are flagged even when they fail Luhn (test / fake cards)
        (re.compile(r"(?i)\b(?:card|cc|credit card|debit card)\s*(?:number|no\.?|#)?\s*[:=]\s*((?:\d[ \-]?){12,18}\d)\b"), 1),
        (re.compile(r"(?i)\bcvv2?\s*[:=]?\s*(\d{3,4})\b"), 1),
    ],
    "bank_account": [
        (re.compile(r"(?i)\b(?:account|acct|routing|iban|aba)\s*(?:number|no\.?|#)?\s*[:=]?\s*([A-Z]{0,2}\d[\d \-]{5,30}\d)"), 1),
    ],
    "phone": [
        (re.compile(r"(\+\d{1,3}[\s\-]?\(?\d{1,4}\)?(?:[\s\-]?\d{2,4}){2,4})"), 1),
    ],
    "passport": [
        (re.compile(r"(?i)\bpassport\s*(?:number|no\.?|#)?\s*[:=]?\s*([A-Z0-9]{6,9})\b"), 1),
    ],
    "balance": [
        (re.compile(r"(?i)\b(?:balance|available|total value|portfolio value|net worth|account value)\b[^\n$€£]{0,40}([$€£]\s?-?[\d,]+(?:\.\d{2})?)"), 1),
    ],
}

# Kinds that are reliable enough to block on in outgoing network traffic.
HIGH_CONFIDENCE = {"api_key", "ssh_credential", "card_number", "password", "bank_account", "passport"}


def find_sensitive(text: str, kinds: set[str] | None = None) -> list[Hit]:
    hits: list[Hit] = []
    for kind, pats in _PATTERNS.items():
        if kinds is not None and kind not in kinds:
            continue
        for pat, grp in pats:
            for m in pat.finditer(text):
                val = m.group(grp)
                if kind == "card_number" and pat.pattern.startswith(r"\b((?:\d"):
                    digits = re.sub(r"\D", "", val)
                    if not (13 <= len(digits) <= 19 and _luhn_ok(digits)):
                        continue
                if kind == "api_key" and grp == 1 and pat.pattern.startswith("(?i)"):
                    # labelled token: require some digits to avoid redacting prose
                    if not re.search(r"\d", val):
                        continue
                hits.append(Hit(kind, m.start(grp), m.end(grp), val))
    return hits


# --------------------------------------------------------- protected values

_NORM = re.compile(r"[\s\-_.:/'\"]+")


def norm(s: str) -> str:
    return _NORM.sub("", s.lower())


class Vault:
    """The user's real sensitive values (passport no., API keys, ...).

    Exact-value matching is the most reliable detector we have: it works on
    any site with zero site knowledge.
    """

    def __init__(self, values: dict[str, str] | None = None):
        self.values = {k: v for k, v in (values or {}).items() if v and len(norm(v)) >= 6}
        self._normed = {k: norm(v) for k, v in self.values.items()}

    def find_in_text(self, text: str) -> list[Hit]:
        """Literal occurrences (for redaction)."""
        hits = []
        for name, val in self.values.items():
            for m in re.finditer(re.escape(val), text):
                hits.append(Hit(f"protected:{name}", m.start(), m.end(), val))
            # also tolerate whitespace differences, e.g. card numbers with/without spaces
            loose = r"[\s\-]*".join(re.escape(c) for c in re.sub(r"\s+", "", val))
            if loose != re.escape(val):
                for m in re.finditer(loose, text):
                    hits.append(Hit(f"protected:{name}", m.start(), m.end(), m.group(0)))
        return hits

    def leaks_in(self, payload: str) -> list[str]:
        """Names of protected values present in an outgoing payload, after
        normalisation and common encodings (url, base64, reversed)."""
        if not self.values:
            return []
        candidates = expand_encodings(payload)
        found = []
        for name, nv in self._normed.items():
            for c in candidates:
                nc = norm(c)
                if nv in nc or nv[::-1] in nc:
                    found.append(name)
                    break
        return found


_B64_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")


def expand_encodings(payload: str) -> list[str]:
    out = [payload]
    try:
        u = urllib.parse.unquote_plus(payload)
        if u != payload:
            out.append(u)
    except Exception:
        pass
    for s in list(out):
        for tok in _B64_TOKEN.findall(s):
            for decoder in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    dec = decoder(tok + "=" * (-len(tok) % 4)).decode("utf-8")
                    if dec.isprintable() or "\n" in dec:
                        out.append(dec)
                        break
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    continue
    return out


def redact(text: str, kinds: set[str], vault: Vault) -> tuple[str, list[Hit]]:
    hits = find_sensitive(text, kinds) + vault.find_in_text(text)
    if not hits:
        return text, []
    # merge overlapping spans, longest first
    hits.sort(key=lambda h: (h.start, -(h.end - h.start)))
    merged: list[Hit] = []
    for h in hits:
        if merged and h.start < merged[-1].end:
            if h.end > merged[-1].end:
                merged[-1] = Hit(merged[-1].kind, merged[-1].start, h.end, text[merged[-1].start:h.end])
            continue
        merged.append(h)
    out, last = [], 0
    for h in merged:
        out.append(text[last:h.start])
        out.append(f"[REDACTED:{h.kind}]")
        last = h.end
    out.append(text[last:])
    return "".join(out), merged


# ----------------------------------------------------- action classification

# Ordered: first match wins. Keywords are matched against the element's own
# label (text / aria-label / title / value) first, then its form context.
ACTION_KEYWORDS: list[tuple[str, list[str]]] = [
    ("transfer", ["transfer", "send money", "zelle", "wire", "withdraw", "pay someone", "move money"]),
    ("add_payee", ["add payee", "add recipient", "new payee", "link account", "link bank", "add bank"]),
    ("account_change", ["change password", "update password", "change email", "update email",
                        "two-factor", "2fa", "security settings", "close account"]),
    ("purchase", ["buy now", "purchase", "place order", "checkout", "pay now", "complete booking",
                  "book now", "reserve", "confirm and pay", "upgrade"]),
    ("delete", ["delete", "remove", "trash", "discard", "🗑"]),
    ("send_message", ["send", "reply", "forward", "post"]),
    ("edit_file", ["save changes", "save file", "overwrite", "edit"]),
    ("upload_file", ["upload", "attach"]),
]


def classify_element(el: dict) -> str:
    """Map a DOM element description to an action type."""
    if el.get("tag") == "input" and el.get("type") == "file":
        return "upload_file"
    own = " ".join(str(el.get(k) or "") for k in ("text", "aria", "title", "value", "id", "name")).lower()
    for action, kws in ACTION_KEYWORDS:
        if any(k in own for k in kws):
            return action
    ctx = " ".join(str(el.get(k) or "") for k in ("form_id", "form_action", "form_text")).lower()
    is_submit = el.get("tag") == "button" and el.get("type") in (None, "", "submit") and el.get("in_form")
    if is_submit or el.get("type") == "submit":
        for action, kws in ACTION_KEYWORDS:
            if any(k in ctx for k in kws):
                return action
        return "submit_form"
    return "interact"


URL_ACTION_HINTS: list[tuple[str, re.Pattern]] = [
    ("transfer", re.compile(r"(?i)/(transfer|transfers|zelle|wire|withdraw|payments?/send)\b")),
    ("add_payee", re.compile(r"(?i)/(payees?|recipients?|external-accounts?|link-bank)\b")),
    ("account_change", re.compile(r"(?i)/(password|security|2fa|email/change|close-account)\b")),
    ("purchase", re.compile(r"(?i)/(checkout|purchase|orders?|book|bookings|pay)\b")),
    ("delete", re.compile(r"(?i)/(delete|remove|trash)\b")),
    ("send_message", re.compile(r"(?i)/(send|messages?/new|mail/send|reply)\b")),
]


def classify_request(method: str, url: str) -> str | None:
    path = urllib.parse.urlsplit(url).path
    for action, pat in URL_ACTION_HINTS:
        if pat.search(path):
            return action
    if method == "DELETE":
        return "delete"
    if method in ("PUT", "PATCH"):
        return "edit_file"
    return None
