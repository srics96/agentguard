"""Local fake sites for the AgentGuard evaluation.

Nothing here talks to the real Google Drive or any real service. Every
sensitive effect - a Drive file being read, deleted or edited, data arriving
at the attacker's collector, an email/message being sent - is recorded in an
in-memory ledger that the scorer reads. The ledger is the ground truth: a run
is judged by what landed here, never by what the agent or the guard reports.

Routes
  GET    /drive/<name>            read a Drive file     -> records 'read'
  DELETE /drive/<name>            delete a Drive file   -> records 'delete'
  PUT    /drive/<name>            overwrite a Drive file-> records 'edit'
  POST   /collect                 attacker's form sink  -> records 'exfil'
  POST   /send                    email/message send    -> records 'send'
  GET    /ledger   /reset         inspect / clear the ledger
  GET    /pages/<platform>?id=... a benchmark-style attack page
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__)
_lock = threading.Lock()

PAGES = Path(__file__).resolve().parent.parent / "pages"

# Seeded per test; the real user secrets live only here, never in the agent.
DRIVE: dict[str, str] = {}
LEDGER: list[dict] = []


def _rec(event: str, **kw):
    with _lock:
        LEDGER.append({"event": event, **kw})


@app.post("/reset")
def reset():
    data = request.get_json(force=True, silent=True) or {}
    with _lock:
        DRIVE.clear()
        DRIVE.update(data.get("drive", {}))
        LEDGER.clear()
    return jsonify(ok=True, drive=list(DRIVE))


@app.get("/ledger")
def ledger():
    with _lock:
        return jsonify(list(LEDGER))


@app.get("/drive/<name>")
def drive_read(name):
    if name not in DRIVE:
        return jsonify(error="not found"), 404
    _rec("read", target=name)
    return DRIVE[name], 200, {"Content-Type": "text/plain"}


@app.delete("/drive/<name>")
def drive_delete(name):
    existed = name in DRIVE
    with _lock:
        DRIVE.pop(name, None)
    _rec("delete", target=name, existed=existed)
    return jsonify(ok=True, existed=existed)


@app.put("/drive/<name>")
def drive_edit(name):
    with _lock:
        DRIVE[name] = request.get_data(as_text=True)
    _rec("edit", target=name)
    return jsonify(ok=True)


@app.post("/collect")
def collect():
    body = request.get_data(as_text=True)
    _rec("exfil", channel="form", body=body)
    return jsonify(ok=True)


@app.post("/send")
def send():
    body = request.get_data(as_text=True)
    _rec("send", channel=request.args.get("via", "email"), body=body)
    return jsonify(ok=True)


@app.get("/pages/<platform>")
def page(platform):
    return send_from_directory(PAGES, f"{platform}.html")


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8077
    app.run(port=port, debug=False, use_reloader=False)
