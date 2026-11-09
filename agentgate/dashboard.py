"""AgentGate dashboard: one static HTML page built from the audit log.

    agentgate dashboard --audit audit.jsonl --out dashboard.html [--lang ar]

Design decisions (agreed before writing it):
  * A static file, not a live server: it opens no port, so there is nothing
    to attack. Run the command again to refresh it.
  * It shows only what the audit log holds, and leaves out anything that
    could help an attacker: token ids, approval ids, request/argument hashes,
    chain hashes, rule reason texts and file paths are never written to the
    page. Rule ids ARE shown (an operator needs to know why), so keep the file
    on the machine; it is not meant to be published.
  * Everything taken from the log is HTML-escaped (tool names come from the
    agent), and the page carries a strict Content-Security-Policy: no scripts,
    no external requests.
  * English by default; --lang ar gives an Arabic, right-to-left page.
"""

from __future__ import annotations

import datetime as _dt
import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .audit import AuditLog

RECENT_ROWS = 50
TOP_ROWS = 10

TEXT = {
    "en": {
        "dir": "ltr", "lang": "en",
        "title": "AgentGate dashboard",
        "generated": "Generated", "records": "audit records", "range": "Period",
        "integrity_ok": "Audit log integrity: verified (no edits, deletions or reordering detected)",
        "integrity_bad": "Audit log integrity: FAILED",
        "integrity_note": "Tamper-evident, not tamper-proof: someone who can rewrite the whole file can rebuild the chain.",
        "decisions": "Decisions", "allowed": "Allowed", "denied": "Denied",
        "approval": "Needed approval", "redacted": "Redacted",
        "identity": "Refused: invalid identity", "monitor": "Recorded in MONITOR mode (nothing was blocked)",
        "malformed": "Unreadable lines",
        "by_agent": "By agent", "by_tool": "By tool", "by_rule": "By rule (why)",
        "approvals": "Human approvals",
        "ev_requested": "Requested", "ev_approved_executed": "Approved and run once",
        "ev_rejected": "Rejected", "ev_hold_timeout": "Not decided in time (agent told to retry)",
        "ev_expired": "Expired", "ev_too_many_pending": "Refused: too many waiting",
        "ev_invalid_decision_ignored": "Forged or mismatched decision ignored",
        "ev_identity_invalid": "Refused: identity invalid at run time",
        "ev_policy_changed": "Refused: policy re-check failed", "ev_still_pending": "Retried while undecided",
        "recent": f"Latest {RECENT_ROWS} decisions",
        "time": "Time (UTC)", "agent": "Agent", "tool": "Tool", "decision": "Decision",
        "rule": "Rule", "mode": "Mode",
        "e_allow": "allow", "e_deny": "deny", "e_require_approval": "needs approval",
        "e_redact": "redact",
        "none": "No records yet.",
        "privacy": "Not shown on purpose: token ids, approval ids, argument and chain hashes, "
                   "rule reasons, file paths. Keep this file on this machine.",
    },
    "ar": {
        "dir": "rtl", "lang": "ar",
        "title": "لوحة AgentGate",
        "generated": "وقت الإنشاء", "records": "سجل تدقيق", "range": "الفترة",
        "integrity_ok": "سلامة سجل التدقيق: سليم (ما فيه تعديل ولا حذف ولا تغيير ترتيب)",
        "integrity_bad": "سلامة سجل التدقيق: فشل الفحص",
        "integrity_note": "السجل يكشف التلاعب لكنه لا يمنعه: من يقدر يعيد كتابة الملف كاملًا يقدر يبني السلسلة من جديد.",
        "decisions": "القرارات", "allowed": "مسموح", "denied": "مرفوض",
        "approval": "احتاج موافقة", "redacted": "مُخفى جزئيًا",
        "identity": "مرفوض: هوية غير صالحة", "monitor": "مسجل في وضع المراقبة (ما انمنع شي)",
        "malformed": "أسطر غير مقروءة",
        "by_agent": "حسب الوكيل", "by_tool": "حسب الأداة", "by_rule": "حسب القاعدة (السبب)",
        "approvals": "الموافقات البشرية",
        "ev_requested": "طُلبت", "ev_approved_executed": "وُوفق عليها ونُفذت مرة واحدة",
        "ev_rejected": "رُفضت", "ev_hold_timeout": "لم يُقرر في الوقت (طُلب من الوكيل الإعادة)",
        "ev_expired": "انتهت مهلتها", "ev_too_many_pending": "مرفوض: طلبات معلقة كثيرة",
        "ev_invalid_decision_ignored": "قرار مزور أو غير مطابق تم تجاهله",
        "ev_identity_invalid": "مرفوض: هوية غير صالحة وقت التنفيذ",
        "ev_policy_changed": "مرفوض: فشل إعادة فحص السياسة", "ev_still_pending": "أُعيد الطلب قبل القرار",
        "recent": f"آخر {RECENT_ROWS} قرار",
        "time": "الوقت (UTC)", "agent": "الوكيل", "tool": "الأداة", "decision": "القرار",
        "rule": "القاعدة", "mode": "الوضع",
        "e_allow": "مسموح", "e_deny": "مرفوض", "e_require_approval": "يحتاج موافقة",
        "e_redact": "مُخفى جزئيًا",
        "none": "لا توجد سجلات بعد.",
        "privacy": "لا يُعرض عمدًا: أرقام التوكنات، أرقام الموافقات، بصمات المعطيات والسلسلة، "
                   "نصوص أسباب القواعد، مسارات الملفات. احتفظ بهذا الملف على هذا الجهاز.",
    },
}

EVENT_ORDER = ["requested", "approved_executed", "rejected", "hold_timeout", "expired",
               "still_pending", "too_many_pending", "invalid_decision_ignored",
               "identity_invalid", "policy_changed"]

CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"


def _esc(v: Any) -> str:
    return html.escape(str(v), quote=True)


def _ts(ts: Any) -> str:
    try:
        return _dt.datetime.fromtimestamp(float(ts), _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OverflowError, OSError):
        return "?"


def read_records(path: str | Path) -> tuple[list[dict[str, Any]], int]:
    """All parseable records, plus how many lines could not be read."""
    records, bad = [], 0
    p = Path(path)
    if not p.exists():
        return records, bad
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if isinstance(rec, dict) and isinstance(rec.get("decision"), dict):
                records.append(rec)
            else:
                bad += 1
    return records, bad


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts only; nothing sensitive is carried forward."""
    decisions = [r for r in records
                 if "approval_event" not in (r["decision"].get("obligations") or {})]
    approvals = [r for r in records
                 if "approval_event" in (r["decision"].get("obligations") or {})]
    effects = Counter(str(r["decision"].get("effect", "?")) for r in decisions)
    by_agent: dict[str, Counter] = {}
    for r in decisions:
        by_agent.setdefault(str(r.get("agent_id", "?")), Counter())[str(r["decision"].get("effect"))] += 1
    return {
        "total": len(decisions),
        "effects": effects,
        "identity": sum(1 for r in decisions if r["decision"].get("rule_id") == "__identity__"),
        "monitor": sum(1 for r in records if r.get("mode") == "monitor"),
        "by_agent": by_agent,
        "by_tool": Counter(str(r.get("tool", "?")) for r in decisions),
        "by_rule": Counter(str(r["decision"].get("rule_id", "?")) for r in decisions),
        "events": Counter(str(r["decision"]["obligations"]["approval_event"]) for r in approvals),
        "recent": [{"time": _ts(r.get("timestamp")), "agent": r.get("agent_id", "?"),
                    "tool": r.get("tool", "?"), "effect": r["decision"].get("effect", "?"),
                    "rule": r["decision"].get("rule_id", "?"), "mode": r.get("mode", "enforce")}
                   for r in decisions[-RECENT_ROWS:]][::-1],
        "first": _ts(records[0].get("timestamp")) if records else "",
        "last": _ts(records[-1].get("timestamp")) if records else "",
    }


def _bars(counter: Counter, t: dict[str, str], top: int = TOP_ROWS) -> str:
    if not counter:
        return f"<p class='muted'>{_esc(t['none'])}</p>"
    peak = max(counter.values()) or 1
    rows = []
    for name, n in counter.most_common(top):
        width = max(2, round(100 * n / peak))
        rows.append(f"<div class='bar'><span class='lbl'><bdi>{_esc(name)}</bdi></span>"
                    f"<span class='track'><span class='fill' style='width:{width}%'></span></span>"
                    f"<span class='num'>{n}</span></div>")
    return "".join(rows)


def _agent_bars(by_agent: dict[str, Counter], t: dict[str, str]) -> str:
    if not by_agent:
        return f"<p class='muted'>{_esc(t['none'])}</p>"
    peak = max(sum(c.values()) for c in by_agent.values()) or 1
    rows = []
    for name, c in sorted(by_agent.items(), key=lambda kv: -sum(kv[1].values()))[:TOP_ROWS]:
        segs = "".join(
            f"<span class='seg {cls}' style='width:{100 * c.get(eff, 0) / peak:.1f}%'></span>"
            for eff, cls in (("allow", "ok"), ("deny", "no"), ("require_approval", "ap"),
                             ("redact", "rd")) if c.get(eff))
        rows.append(f"<div class='bar'><span class='lbl'><bdi>{_esc(name)}</bdi></span>"
                    f"<span class='track'>{segs}</span><span class='num'>{sum(c.values())}</span></div>")
    legend = (f"<p class='legend'><span class='dot ok'></span>{_esc(t['allowed'])} "
              f"<span class='dot no'></span>{_esc(t['denied'])} "
              f"<span class='dot ap'></span>{_esc(t['approval'])}</p>")
    return legend + "".join(rows)


def generate_dashboard(audit_path: str | Path, lang: str = "en") -> str:
    t = TEXT.get(lang, TEXT["en"])
    records, bad = read_records(audit_path)
    try:
        ok, _msg = AuditLog(audit_path).verify() if Path(audit_path).exists() else (True, "")
    except Exception:
        ok = False
    s = summarize(records)
    e = s["effects"]

    tiles = [
        (t["decisions"], s["total"], ""), (t["allowed"], e.get("allow", 0), "ok"),
        (t["denied"], e.get("deny", 0), "no"), (t["approval"], e.get("require_approval", 0), "ap"),
        (t["identity"], s["identity"], "no"),
    ]
    if e.get("redact"):
        tiles.append((t["redacted"], e["redact"], "rd"))
    tile_html = "".join(f"<div class='tile {cls}'><div class='big'>{n}</div>"
                        f"<div class='cap'>{_esc(label)}</div></div>" for label, n, cls in tiles)

    integrity = (f"<div class='banner {'good' if ok else 'bad'}'>"
                 f"{_esc(t['integrity_ok'] if ok else t['integrity_bad'])}"
                 f"<div class='small'>{_esc(t['integrity_note'])}</div></div>")
    warn = ""
    if s["monitor"]:
        warn += f"<div class='banner warnb'>{_esc(t['monitor'])}: {s['monitor']}</div>"
    if bad:
        warn += f"<div class='banner bad'>{_esc(t['malformed'])}: {bad}</div>"

    ev_rows = "".join(
        f"<tr><td>{_esc(t.get('ev_' + ev, ev))}</td><td class='n'>{s['events'][ev]}</td></tr>"
        for ev in EVENT_ORDER + sorted(set(s["events"]) - set(EVENT_ORDER)) if s["events"].get(ev))
    approvals = (f"<table>{ev_rows}</table>" if ev_rows
                 else f"<p class='muted'>{_esc(t['none'])}</p>")

    recent_rows = "".join(
        f"<tr><td class='mono'><bdi dir='ltr'>{_esc(r['time'])}</bdi></td><td><bdi>{_esc(r['agent'])}</bdi></td>"
        f"<td><bdi>{_esc(r['tool'])}</bdi></td>"
        f"<td><span class='pill {_pill(r['effect'])}'>{_esc(t.get('e_' + str(r['effect']), r['effect']))}</span></td>"
        f"<td><bdi>{_esc(r['rule'])}</bdi></td><td>{_esc(r['mode'])}</td></tr>"
        for r in s["recent"])
    recent = (f"<div class='scroll'><table class='recent'><tr><th>{_esc(t['time'])}</th>"
              f"<th>{_esc(t['agent'])}</th><th>{_esc(t['tool'])}</th><th>{_esc(t['decision'])}</th>"
              f"<th>{_esc(t['rule'])}</th><th>{_esc(t['mode'])}</th></tr>{recent_rows}</table></div>"
              if recent_rows else f"<p class='muted'>{_esc(t['none'])}</p>")

    period = f"{s['first']} → {s['last']}" if records else "-"
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""<!doctype html>
<html lang="{t['lang']}" dir="{t['dir']}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="referrer" content="no-referrer">
<title>{_esc(t['title'])}</title><style>{_CSS}</style></head><body>
<header><h1>{_esc(t['title'])}</h1>
<p class="muted">{_esc(t['generated'])}: <bdi dir="ltr">{now}</bdi> · <bdi dir="ltr">{len(records)}</bdi> {_esc(t['records'])} · {_esc(t['range'])}: <bdi dir="ltr">{_esc(period)}</bdi></p></header>
{integrity}{warn}
<section class="tiles">{tile_html}</section>
<section class="grid">
<div class="card"><h2>{_esc(t['by_agent'])}</h2>{_agent_bars(s['by_agent'], t)}</div>
<div class="card"><h2>{_esc(t['by_tool'])}</h2>{_bars(s['by_tool'], t)}</div>
<div class="card"><h2>{_esc(t['by_rule'])}</h2>{_bars(s['by_rule'], t)}</div>
<div class="card"><h2>{_esc(t['approvals'])}</h2>{approvals}</div>
</section>
<section class="card"><h2>{_esc(t['recent'])}</h2>{recent}</section>
<footer class="muted">{_esc(t['privacy'])}</footer>
</body></html>
"""


def _pill(effect: Any) -> str:
    return {"allow": "ok", "deny": "no", "require_approval": "ap", "redact": "rd"}.get(str(effect), "")


_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#14171c;--muted:#5d6672;--line:#e3e6ea;
--ok:#1f7a3a;--no:#b42318;--ap:#b26b00;--rd:#3b5bdb;--track:#eef0f3}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a20;--fg:#e8eaed;
--muted:#9aa3ad;--line:#2a2f37;--ok:#4cc27a;--no:#ff6b5f;--ap:#f0a43a;--rd:#7c95ff;--track:#232830}}
*{box-sizing:border-box}body{margin:0 auto;max-width:1100px;padding:20px 16px 40px;
background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Tahoma,sans-serif}
h1{font-size:24px;margin:0 0 4px}h2{font-size:16px;margin:0 0 12px}
.muted{color:var(--muted)}.small{font-size:13px;opacity:.85;margin-top:4px}
.banner{border-radius:10px;padding:12px 14px;margin:14px 0;font-weight:600}
.banner.good{background:color-mix(in srgb,var(--ok) 14%,transparent);border:1px solid var(--ok)}
.banner.bad{background:color-mix(in srgb,var(--no) 14%,transparent);border:1px solid var(--no)}
.banner.warnb{background:color-mix(in srgb,var(--ap) 16%,transparent);border:1px solid var(--ap)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}
.tile .big{font-size:28px;font-weight:700}.tile .cap{color:var(--muted);font-size:13px}
.tile.ok .big{color:var(--ok)}.tile.no .big{color:var(--no)}.tile.ap .big{color:var(--ap)}.tile.rd .big{color:var(--rd)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;margin-top:12px}
.bar{display:grid;grid-template-columns:minmax(90px,38%) 1fr 42px;gap:8px;align-items:center;margin:6px 0}
.lbl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}
.track{display:flex;height:12px;background:var(--track);border-radius:6px;overflow:hidden}
.fill{display:block;background:var(--rd)}.seg{display:block;height:100%}
.seg.ok{background:var(--ok)}.seg.no{background:var(--no)}.seg.ap{background:var(--ap)}.seg.rd{background:var(--rd)}
.num{text-align:end;font-variant-numeric:tabular-nums}
.legend{font-size:13px;color:var(--muted);margin:0 0 8px}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin:0 4px}
.dot.ok{background:var(--ok)}.dot.no{background:var(--no)}.dot.ap{background:var(--ap)}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:6px 8px;border-bottom:1px solid var(--line);text-align:start}
td.n{text-align:end;font-variant-numeric:tabular-nums}.scroll{overflow-x:auto}
.recent th{color:var(--muted);font-weight:600}.mono{font-family:ui-monospace,Consolas,monospace;white-space:nowrap}
.pill{padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.pill.ok{color:var(--ok);border:1px solid var(--ok)}.pill.no{color:var(--no);border:1px solid var(--no)}
.pill.ap{color:var(--ap);border:1px solid var(--ap)}.pill.rd{color:var(--rd);border:1px solid var(--rd)}
footer{margin-top:20px;font-size:13px}
"""
