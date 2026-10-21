"""
Phase 8 module adapters: AV, Core, BK, AS — Collect → Decision Core → Act.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(PLATFORM / "decision_core" / "src"))
sys.path.insert(0, str(PLATFORM / "shared" / "contracts" / "src"))
sys.path.insert(0, str(PLATFORM / "phase4" / "src"))
sys.path.insert(0, str(PLATFORM / "phase7" / "src"))

from base_adapter import logical_act, make_event  # noqa: E402
from decision_core import build_evidence, process_event  # noqa: E402
from playbooks import run_playbook, select_playbook  # noqa: E402
from pack_signing import load_key, verify_pack  # noqa: E402
from validate import validate_policy_pack  # noqa: E402


def load_pack(path: Path, key_path: Path) -> dict:
    pack = __import__("json").loads(path.read_text(encoding="utf-8"))
    ok, msg = verify_pack(pack, load_key(key_path))
    if not ok:
        raise ValueError(msg)
    return validate_policy_pack(pack)


class ModuleAdapter:
    module: str = "base"

    def collect_scenario(self, name: str) -> List[dict]:
        raise NotImplementedError

    def act(self, actions: List[dict], event: dict) -> List[dict]:
        return logical_act(actions, event, self.module)

    def handle(self, event: dict, pack: dict, run_playbook_on_auto: bool = True) -> dict:
        result = process_event(event, pack)
        actions = list(result.decision.actions or [])
        playbook_run = None
        if run_playbook_on_auto and result.decision.mode == "auto_act":
            pb = select_playbook(pack, result.vectors)
            if pb:
                playbook_run = run_playbook(pb, event, self.act)
                actions = playbook_run["actions"]
            elif actions:
                actions = self.act(actions, event)
        evidence = build_evidence(
            event, result.vectors, result.score, result.impact_class, result.decision, actions
        ) if result.decision.mode == "auto_act" else result.evidence
        return {
            "module": self.module,
            "event_id": event.get("id"),
            "vectors": result.vectors,
            "score": result.score,
            "mode": result.decision.mode,
            "actions": actions,
            "playbook_run": playbook_run,
            "evidence": evidence,
        }

    def run_scenario(self, name: str, pack: dict) -> List[dict]:
        return [self.handle(e, pack) for e in self.collect_scenario(name)]


class AVAdapter(ModuleAdapter):
    module = "AV"

    def collect_scenario(self, name: str) -> List[dict]:
        if name == "malware_hash":
            return [make_event(
                "file", module=self.module,
                object_={"path": "/tmp/suspicious.bin", "sha256": "deadbeef"},
                attrs={"scan": "hash_match", "verdict": "malicious"},
                technique_ids=["T1204.002"],
            )]
        if name == "heuristic":
            return [make_event(
                "process", module=self.module,
                subject={"device": "d1", "user": "u", "process": "unknown.exe"},
                attrs={"scan": "heuristic", "score_hint": 80},
                technique_ids=["T1059"],
            )]
        if name == "clean":
            return [make_event("health", module=self.module, object_={"scan": "clean"})]
        raise ValueError(name)


class CoreAdapter(ModuleAdapter):
    module = "Core"

    def collect_scenario(self, name: str) -> List[dict]:
        if name == "signature_hit":
            return [make_event(
                "file", module=self.module,
                object_={"path": "/tmp/sample", "sig_id": "VS.Sig.Trojan.Generic"},
                attrs={"engine": "core", "sig_match": True},
                technique_ids=["T1204"],
            )]
        if name == "deep_scan":
            return [make_event(
                "process", module=self.module,
                subject={"process": "wscript.exe", "device": "d1", "user": "u"},
                attrs={"engine": "core", "heuristic": "script_host_burst"},
                technique_ids=["T1059.005"],
            )]
        raise ValueError(name)


class BKAdapter(ModuleAdapter):
    module = "BK"

    def collect_scenario(self, name: str) -> List[dict]:
        if name == "integrity_fail":
            return [make_event(
                "file", module=self.module,
                object_={"backup_set": "daily-2026-10-20", "check": "hash_mismatch"},
                attrs={"bk_integrity": "failed", "impact_hint": True},
                technique_ids=["T1490"],
            )]
        if name == "integrity_ok":
            return [make_event(
                "health", module=self.module,
                object_={"backup_set": "daily-2026-10-20", "check": "ok"},
                attrs={"bk_integrity": "ok"},
            )]
        if name == "ransomware_trigger":
            return [make_event(
                "file", module=self.module,
                object_={"path": "/data/share", "op": "mass_encrypt_suspect"},
                attrs={"bk_action": "verify_restore_points"},
                technique_ids=["T1486"],
            )]
        raise ValueError(name)

    def act(self, actions: List[dict], event: dict) -> List[dict]:
        enriched = []
        for a in actions:
            a = dict(a)
            if a.get("kind") in ("alert", "quarantine_file", "isolate_process"):
                a["target"] = {**(a.get("target") or {}), "bk_verify": True}
            enriched.append(a)
        return logical_act(enriched, event, self.module)


class ASAdapter(ModuleAdapter):
    module = "AS"

    def collect_scenario(self, name: str) -> List[dict]:
        if name == "phish":
            return [make_event(
                "mail", module=self.module,
                object_={"from": "ceo@evil.example", "subject": "Urgent wire"},
                attrs={"spf": "fail", "dkim": "fail", "dmarc": "fail", "verdict": "phish"},
                technique_ids=["T1566.002"],
            )]
        if name == "spam":
            return [make_event(
                "mail", module=self.module,
                object_={"from": "deals@spam.example", "subject": "Buy now"},
                attrs={"verdict": "spam", "bayes": 0.92},
            )]
        if name == "clean_mail":
            return [make_event(
                "mail", module=self.module,
                object_={"from": "colleague@company.com"},
                attrs={"verdict": "clean", "spf": "pass"},
            )]
        raise ValueError(name)


ADAPTERS = {"AV": AVAdapter, "Core": CoreAdapter, "BK": BKAdapter, "AS": ASAdapter}


def run_all_modules(pack: dict, scenarios: Optional[Dict[str, str]] = None) -> Dict[str, List[dict]]:
    scenarios = scenarios or {
        "AV": "malware_hash",
        "Core": "signature_hit",
        "BK": "integrity_fail",
        "AS": "phish",
    }
    out = {}
    for name, scen in scenarios.items():
        adapter = ADAPTERS[name]()
        out[name] = adapter.run_scenario(scen, pack)
    return out
