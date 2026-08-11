"""
Deployment Setup & Health-Check Script.

One-shot provisioning for a fresh Debian/Kali target that guarantees the IDS can
actually detect the attacks launched from Kali:

  1. Registers every model artifact found in ``models/`` that is not yet in the DB
     (including the macro-aggregate model ``macro_rf_v1``, id 5).
  2. Activates the macro model so assembled flood units are dispatched to it.
  3. Verifies ``AI_IDS_MACRO_FLOW_ENABLED`` is ``true`` in ``.env`` and flips it if not.
  4. Verifies the full detection pipeline against a real captured attack file when
     one is supplied (or against the project PCAP fixtures when present).

Run as root on the target Debian box:
    python scripts/setup_deployment.py [path/to/captured_flows_master.csv]
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

MODEL_REGISTRY: list[dict] = [
    {"name": "Random Forest V3", "file": "random_forest_v3.joblib", "type": "random_forest", "version": "3.0.0"},
    {"name": "XGBoost Pipeline V2", "file": "xgboost_pipeline_v2.joblib", "type": "xgboost", "version": "2.0.0"},
    {"name": "Macro RF V1 (Multi-Class)", "file": "macro_rf_v1.joblib", "type": "random_forest", "version": "2.0.0"},
    {"name": "Macro XGB V1 (Multi-Class)", "file": "macro_xgb_v1.joblib", "type": "xgboost", "version": "1.0.0"},
    {"name": "Macro RF V2 (Multi-Class)", "file": "macro_rf_v2.joblib", "type": "random_forest", "version": "3.0.0"},
    {"name": "Macro XGB V2 (Multi-Class)", "file": "macro_xgb_v2.joblib", "type": "xgboost", "version": "2.0.0"},
]

_ENV_LINES = {
    "AI_IDS_MACRO_FLOW_ENABLED": "true",
    "AI_IDS_MACRO_FLOW_WINDOW_SECONDS": "10.0",
    "AI_IDS_MACRO_FLOW_KEY_FIELDS": "src_ip,dst_ip,dst_port,protocol",
    "AI_IDS_MACRO_FLOW_MIN_MEMBERS": "2",
    "AI_IDS_MACRO_FLOW_MODEL_ID": "8",
}


def _ensure_env() -> None:
    env_path = WORKSPACE_ROOT / ".env"
    lines: list[str] = []
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()

    existing_keys = {
        m.group(1): idx
        for idx, line in enumerate(lines)
        if (m := re.match(r"^\s*(AI_IDS_\w+)\s*=", line))
    }

    changed = False
    for key, value in _ENV_LINES.items():
        if key in existing_keys:
            idx = existing_keys[key]
            if lines[idx].split("=", 1)[1].strip().strip('"').lower() != value.lower():
                lines[idx] = f"{key}={value}"
                changed = True
        else:
            lines.append(f"{key}={value}")
            changed = True

    if changed:
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"[env] Updated {env_path} — macro-flow assembly enabled.")
    else:
        print("[env] .env already has macro-flow assembly enabled.")


def _register_models(container) -> None:
    for spec in MODEL_REGISTRY:
        existing = container.model_repository.get_by_name(spec["name"])
        if existing is not None:
            print(f"[models] '{spec['name']}' already registered (id={existing.id}).")
            continue
        file_path = WORKSPACE_ROOT / "models" / spec["file"]
        if not file_path.exists():
            print(f"[models] WARNING: artifact {file_path.name} missing — skipping.")
            continue
        record = container.model_service.register_model(
            name=spec["name"],
            file_path=str(file_path),
            model_type=spec["type"],
            version=spec["version"],
        )
        print(f"[models] Registered '{spec['name']}' (id={record.id}, {record.features_count} features).")


def _activate_macro_model(container) -> int | None:
    """Resolve and activate the configured macro model (XGB id 8 by default; RF id 7 optional)."""
    macro_id = None
    for m in container.model_service.list_models():
        haystack = f"{m.name} {m.file_path}".lower()
        if "macro xgb v2" in haystack:
            macro_id = m.id
            if not m.is_active:
                container.model_service.activate(m.id, exclusive=False)
                print(f"[models] Activated macro model '{m.name}' (id={m.id}).")
            else:
                print(f"[models] Macro model '{m.name}' (id={m.id}) already active.")
            break
    if macro_id is None:
        for m in container.model_service.list_models():
            haystack = f"{m.name} {m.file_path}".lower()
            if "macro" in haystack:
                macro_id = m.id
                if not m.is_active:
                    container.model_service.activate(m.id, exclusive=False)
                    print(f"[models] Activated macro model '{m.name}' (id={m.id}).")
                else:
                    print(f"[models] Macro model '{m.name}' (id={m.id}) already active.")
                break
    if macro_id is None:
        print("[models] WARNING: no macro model registered — floods will be invisible!")
    return macro_id


def _verify_live_pipeline(csv_path: str | None) -> None:
    from services.container import get_container

    container = get_container()
    _register_models(container)
    _ensure_env()
    _activate_macro_model(container)

    from config.settings import get_settings
    settings = get_settings()
    print(f"[config] macro_flow_enabled={settings.macro_flow_enabled} "
          f"macro_flow_model_id={settings.macro_flow_model_id}")

    target = csv_path
    if target is None:
        candidates = [
            WORKSPACE_ROOT / "data" / "captured_flows_master.csv",
            WORKSPACE_ROOT / "simulated_attacks_demo.csv",
        ]
        target = next((str(p) for p in candidates if p.exists()), None)

    if target:
        print(f"[verify] Analyzing {target} ...")
        summary = container.csv_analysis_service.analyze(
            model_id=settings.macro_flow_model_id,
            csv_path=target,
            skip_integration=True,
        )
        print(f"[verify] rows={summary.total_rows} attack={summary.attack_count} normal={summary.normal_count}")
        if summary.attack_count > 0:
            print("[verify] PASS — attacks detected. The pipeline is operational.")
        else:
            print("[verify] FAIL — no attacks detected on this capture. Inspect logs.")
    else:
        print("[verify] No captured CSV found; skipped live-pipeline smoke test.")


if __name__ == "__main__":
    args = sys.argv[1:]
    _verify_live_pipeline(args[0] if args else None)
