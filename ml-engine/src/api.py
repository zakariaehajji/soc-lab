"""FastAPI scoring service for the AI-Powered SOC ML engine."""

from __future__ import annotations

import html
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .context import LAB_HOSTS, extract_context, lookup_host
from .features import extract_features
from .response import block_ip, is_protected, list_blocked, unblock_ip
from .schema import FEATURE_NAMES, Explanation, ScoreRequest, ScoreResponse

ARTIFACT = Path(os.getenv("SOC_ML_MODEL", "artifacts/model.joblib"))
MULTI = Path(os.getenv("SOC_ML_MODEL_MULTI", "artifacts/model_multiclass.joblib"))
ENRICHMENT = Path(os.getenv("SOC_ML_ENRICHMENT", "logs/enrichment.jsonl"))

app = FastAPI(title="SOC ML Engine", version="0.2.0", description="Modular ML scoring + lab response actions")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_BUNDLE = None
_MULTI = None


class BlockRequest(BaseModel):
    ip: str = Field(..., description="IPv4/IPv6 to DROP on SOC iptables")
    reason: str = ""
    actor: str = "ui"


def load_models():
    global _BUNDLE, _MULTI
    if not ARTIFACT.exists():
        raise FileNotFoundError(f"Model not found: {ARTIFACT}")
    _BUNDLE = joblib.load(ARTIFACT)
    if MULTI.exists():
        _MULTI = joblib.load(MULTI)


@app.on_event("startup")
def _startup():
    load_models()


def _load_enrichment(limit: int = 200) -> List[Dict[str, Any]]:
    if not ENRICHMENT.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with ENRICHMENT.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows[-limit:]


def _esc(v: Any) -> str:
    return html.escape("" if v is None else str(v))


@app.get("/")
def root():
    return {
        "service": "SOC ML Engine",
        "status": "ok",
        "endpoints": {
            "ui": "/ui",
            "health": "/health",
            "results": "/results",
            "inventory": "/inventory",
            "blocked": "/blocked",
            "block": "POST /block",
            "unblock": "POST /unblock",
            "score": "POST /score",
            "docs": "/docs",
        },
    }


@app.get("/inventory")
def inventory():
    return {"lab_hosts": LAB_HOSTS, "protected_from_block": ["127.0.0.0/8", "192.168.221.136", "192.168.221.138"]}


@app.get("/blocked")
def blocked():
    try:
        return {"blocked": list_blocked()}
    except Exception as e:
        raise HTTPException(500, str(e)) from e


@app.post("/block")
def api_block(req: BlockRequest):
    try:
        return block_ip(req.ip.strip(), reason=req.reason, actor=req.actor)
    except PermissionError as e:
        raise HTTPException(403, str(e)) from e
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    except Exception as e:
        raise HTTPException(500, str(e)) from e


@app.post("/unblock")
def api_unblock(req: BlockRequest):
    try:
        return unblock_ip(req.ip.strip(), actor=req.actor)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    except Exception as e:
        raise HTTPException(500, str(e)) from e


@app.get("/results")
def results(limit: int = 100):
    rows = _load_enrichment(limit=limit)
    classes = Counter((r.get("ml") or {}).get("top_class") or "UNKNOWN" for r in rows)
    preds = Counter((r.get("ml") or {}).get("prediction") or "UNKNOWN" for r in rows)
    risks = [(r.get("ml") or {}).get("risk_score") for r in rows if (r.get("ml") or {}).get("risk_score") is not None]
    srcs = Counter(r.get("src_ip") or "unknown" for r in rows)
    avg_risk = round(sum(risks) / len(risks), 4) if risks else None
    try:
        blocked_now = list_blocked()
    except Exception:
        blocked_now = []
    return {
        "count": len(rows),
        "predictions": dict(preds),
        "classes": dict(classes),
        "top_sources": dict(srcs.most_common(10)),
        "avg_risk": avg_risk,
        "blocked": blocked_now,
        "model_version": (_BUNDLE or {}).get("version"),
        "rows": rows[::-1],
    }


@app.get("/ui", response_class=HTMLResponse)
def ui():
    rows = _load_enrichment(limit=200)
    try:
        blocked_now = set(list_blocked())
    except Exception:
        blocked_now = set()

    classes = Counter((r.get("ml") or {}).get("top_class") or "UNKNOWN" for r in rows)
    risks = [(r.get("ml") or {}).get("risk_score") or 0.0 for r in rows]
    avg_risk = round(sum(risks) / len(risks), 3) if risks else 0.0
    attack_n = sum(1 for r in rows if (r.get("ml") or {}).get("prediction") == "ATTACK")
    srcs = Counter(r.get("src_ip") for r in rows if r.get("src_ip"))
    max_cls = max(classes.values()) if classes else 1
    max_src = max(srcs.values()) if srcs else 1

    bars = "".join(
        f'<div class="barrow"><span>{_esc(k)}</span><div class="track"><div class="fill" style="width:{100 * v / max_cls:.1f}%"></div></div><b>{v}</b></div>'
        for k, v in sorted(classes.items(), key=lambda x: -x[1])
    )
    src_bars = "".join(
        f'<div class="barrow"><span>{_esc(k)}</span><div class="track"><div class="fill src" style="width:{100 * v / max_src:.1f}%"></div></div><b>{v}</b></div>'
        for k, v in srcs.most_common(8)
    )

    trs_parts: List[str] = []
    for r in reversed(rows[-50:]):
        src = r.get("src_ip") or ""
        dst = r.get("dst_ip") or ""
        src_h = (r.get("src_host") or lookup_host(src) or {})
        dst_h = (r.get("dst_host") or lookup_host(dst) or {})
        agent = r.get("agent_info") or {}
        mitre = r.get("mitre") or {}
        tactics = ", ".join(mitre.get("tactic") or [])
        techniques = ", ".join(mitre.get("technique") or [])
        ml = r.get("ml") or {}
        can_block = bool(src) and not is_protected(src)
        is_blk = src in blocked_now
        if can_block:
            if is_blk:
                action_btn = (
                    f'<button class="btn ok" onclick="unblockIp(\'{_esc(src)}\')">Unblock</button>'
                    f' <span class="tag danger">BLOCKED</span>'
                )
            else:
                action_btn = f'<button class="btn danger" onclick="blockIp(\'{_esc(src)}\')">Block IP</button>'
        else:
            action_btn = '<span class="tag">protected</span>'

        machine = (
            f"{_esc(src_h.get('name'))} ({_esc(src_h.get('role'))})"
            if src_h
            else "—"
        )
        sensor = _esc(agent.get("name") or r.get("agent") or "")
        trs_parts.append(
            "<tr>"
            f"<td>{_esc(ml.get('prediction'))}</td>"
            f"<td>{_esc(ml.get('top_class'))}</td>"
            f"<td>{round(float(ml.get('risk_score') or 0), 3)}</td>"
            f"<td><code>{_esc(src)}</code><div class='mini'>{machine}</div></td>"
            f"<td><code>{_esc(dst)}</code><div class='mini'>{_esc((dst_h or {}).get('name'))} ({_esc((dst_h or {}).get('role'))})</div></td>"
            f"<td>{_esc(r.get('proto'))} {_esc(r.get('src_port'))}→{_esc(r.get('dst_port'))}</td>"
            f"<td>{sensor}<div class='mini'>{_esc(agent.get('ip'))}</div></td>"
            f"<td>{_esc(r.get('rule_id'))}<div class='mini'>{_esc(r.get('rule_desc'))}</div>"
            f"<div class='mini'>{_esc(tactics)} · {_esc(techniques)}</div></td>"
            f"<td>{action_btn}</td>"
            "</tr>"
        )
    trs = "".join(trs_parts)

    blocked_list = ", ".join(sorted(blocked_now)) or "none"
    version = (_BUNDLE or {}).get("version", "unknown")
    inv_rows = "".join(
        f"<tr><td><code>{_esc(ip)}</code></td><td>{_esc(h['name'])}</td><td>{_esc(h['role'])}</td>"
        f"<td>{_esc(h['os'])}</td><td>{_esc(h['notes'])}</td></tr>"
        for ip, h in LAB_HOSTS.items()
    )

    html_doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>SOC ML Results</title>
<style>
:root {{ --bg:#0f1419; --panel:#1a222c; --text:#e7eef7; --muted:#8b9bb0; --accent:#3d8bfd; --danger:#e35d6a; --ok:#3ecf8e; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:Segoe UI, system-ui, sans-serif; background:var(--bg); color:var(--text); }}
main {{ max-width:1280px; margin:0 auto; padding:28px 20px 48px; }}
h1 {{ margin:0 0 6px; font-size:1.6rem; }}
.sub {{ color:var(--muted); margin-bottom:18px; }}
.grid {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin-bottom:18px; }}
.card {{ background:var(--panel); border:1px solid #2a3542; border-radius:10px; padding:16px; }}
.card .label {{ color:var(--muted); font-size:.85rem; }}
.card .value {{ font-size:1.45rem; font-weight:700; margin-top:4px; }}
.panel {{ background:var(--panel); border:1px solid #2a3542; border-radius:10px; padding:18px; margin-bottom:18px; }}
.two {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
.barrow {{ display:grid; grid-template-columns:110px 1fr 36px; gap:10px; align-items:center; margin:8px 0; }}
.track {{ background:#243040; border-radius:999px; height:10px; overflow:hidden; }}
.fill {{ background:var(--danger); height:100%; }}
.fill.src {{ background:var(--accent); }}
table {{ width:100%; border-collapse:collapse; font-size:.88rem; }}
th, td {{ text-align:left; padding:9px 6px; border-bottom:1px solid #2a3542; vertical-align:top; }}
th {{ color:var(--muted); font-weight:600; }}
.mini {{ color:var(--muted); font-size:.78rem; margin-top:2px; }}
.btn {{ border:0; border-radius:6px; padding:6px 10px; cursor:pointer; font-weight:600; }}
.btn.danger {{ background:var(--danger); color:#fff; }}
.btn.ok {{ background:var(--ok); color:#0b1a12; }}
.tag {{ display:inline-block; padding:2px 8px; border-radius:999px; background:#243040; color:var(--muted); font-size:.75rem; }}
.tag.danger {{ background:#3a1d22; color:var(--danger); }}
#toast {{ position:fixed; right:16px; bottom:16px; background:#243040; border:1px solid #3a4a5c; padding:10px 14px; border-radius:8px; display:none; }}
a {{ color:var(--accent); }}
@media (max-width:900px) {{ .grid,.two {{ grid-template-columns:1fr 1fr; }} }}
</style></head><body><main>
<h1>SOC ML live results</h1>
<p class="sub">Model <code>{_esc(version)}</code> · src/dst + host inventory · lab iptables block on SOC · currently blocked: <b id="blockedNow">{_esc(blocked_list)}</b></p>
<div class="grid">
  <div class="card"><div class="label">Alerts scored</div><div class="value">{len(rows)}</div></div>
  <div class="card"><div class="label">ATTACK</div><div class="value" style="color:var(--danger)">{attack_n}</div></div>
  <div class="card"><div class="label">Avg risk</div><div class="value">{avg_risk}</div></div>
  <div class="card"><div class="label">Unique src IPs</div><div class="value">{len(srcs)}</div></div>
  <div class="card"><div class="label">Blocked now</div><div class="value" style="color:var(--danger)">{len(blocked_now)}</div></div>
</div>
<div class="two">
  <div class="panel"><h2 style="margin:0 0 10px;font-size:1.05rem">Attack family mix</h2>{bars or "<p class='sub'>No enrichment yet</p>"}</div>
  <div class="panel"><h2 style="margin:0 0 10px;font-size:1.05rem">Top source IPs</h2>{src_bars or "<p class='sub'>No source IPs yet — re-run bridge backfill</p>"}</div>
</div>
<div class="panel"><h2 style="margin:0 0 10px;font-size:1.05rem">Recent scores + response</h2>
<table><thead><tr>
<th>Pred</th><th>Class</th><th>Risk</th><th>From (src)</th><th>To (dst)</th><th>Flow</th><th>Sensor</th><th>Rule / MITRE</th><th>Action</th>
</tr></thead>
<tbody>{trs or "<tr><td colspan=9>No rows</td></tr>"}</tbody></table></div>
<div class="panel"><h2 style="margin:0 0 10px;font-size:1.05rem">Lab machine inventory</h2>
<table><thead><tr><th>IP</th><th>Name</th><th>Role</th><th>OS</th><th>Notes</th></tr></thead>
<tbody>{inv_rows}</tbody></table>
<p class="sub" style="margin-top:10px">Block refuses SOC (.138) and IDS (.136). Block uses iptables chain SOC_ML_BLOCK on this host (drops inbound/forward from that IP).</p>
</div>
<p class="sub">Docs: <a href="/docs">/docs</a> · JSON: <a href="/results">/results</a> · Blocked: <a href="/blocked">/blocked</a></p>
</main>
<div id="toast"></div>
<script>
async function blockIp(ip) {{
  if (!confirm('Block ' + ip + ' on SOC iptables?')) return;
  const r = await fetch('/block', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify({{ip, reason:'ui-manual-block', actor:'ui'}})}});
  const j = await r.json();
  toast(r.ok ? ('Blocked ' + ip) : (j.detail || 'block failed'));
  if (r.ok) setTimeout(() => location.reload(), 600);
}}
async function unblockIp(ip) {{
  const r = await fetch('/unblock', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify({{ip, actor:'ui'}})}});
  const j = await r.json();
  toast(r.ok ? ('Unblocked ' + ip) : (j.detail || 'unblock failed'));
  if (r.ok) setTimeout(() => location.reload(), 600);
}}
function toast(msg) {{
  const el = document.getElementById('toast');
  el.textContent = typeof msg === 'string' ? msg : JSON.stringify(msg);
  el.style.display = 'block';
  setTimeout(() => el.style.display = 'none', 2500);
}}
</script>
</body></html>"""
    return HTMLResponse(html_doc)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_loaded": _BUNDLE is not None,
        "model_version": (_BUNDLE or {}).get("version"),
        "feature_count": len(FEATURE_NAMES),
    }


@app.get("/schema")
def schema():
    return {
        "features": FEATURE_NAMES,
        "request": ScoreRequest.model_json_schema(),
        "response": ScoreResponse.model_json_schema(),
    }


def _vector(feats: Dict[str, float]) -> np.ndarray:
    return np.array([[feats[k] for k in FEATURE_NAMES]], dtype=float)


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest):
    if _BUNDLE is None:
        raise HTTPException(503, "Model not loaded")
    try:
        feats = extract_features(event=req.event, features=req.features)
    except Exception as e:
        raise HTTPException(400, f"feature extraction failed: {e}") from e

    model = _BUNDLE["model"]
    version = _BUNDLE.get("version", "unknown")
    X = _vector(feats)
    pred = int(model.predict(X)[0])
    if hasattr(model, "predict_proba"):
        p = model.predict_proba(X)[0]
        classes = list(model.classes_)
        proba = {("ATTACK" if int(c) == 1 else "BENIGN"): float(p[i]) for i, c in enumerate(classes)}
        risk = float(proba.get("ATTACK", 0.0))
    else:
        proba = {"BENIGN": 1.0 - pred, "ATTACK": float(pred)}
        risk = float(pred)

    top_class = None
    if _MULTI is not None and pred == 1:
        m = _MULTI["model"]
        top_class = str(m.predict(X)[0])

    explanations: List[Explanation] = []
    if hasattr(model, "feature_importances_"):
        imp = model.feature_importances_
        scored = sorted(
            [
                (FEATURE_NAMES[i], float(imp[i] * (abs(feats[FEATURE_NAMES[i]]) + 1e-6)))
                for i in range(len(FEATURE_NAMES))
            ],
            key=lambda x: -x[1],
        )[:5]
        explanations = [Explanation(feature=a, contribution=b) for a, b in scored]

    notes = "Lab-native Suricata/Wazuh feature model; not CIC-IDS columns"
    if req.event:
        ctx = extract_context(req.event)
        if ctx.get("src_ip"):
            notes += f" | src={ctx['src_ip']} dst={ctx.get('dst_ip')}"

    return ScoreResponse(
        request_id=req.request_id,
        model_version=version,
        prediction="ATTACK" if pred == 1 else "BENIGN",
        risk_score=risk,
        label_proba=proba,
        top_class=top_class,
        explanations=explanations,
        notes=notes,
        features_used=feats,
    )


@app.post("/score/batch")
def score_batch(reqs: List[ScoreRequest]):
    return [score(r) for r in reqs]
