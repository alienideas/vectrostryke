"""ASG staged pipeline: geo → protocol → reputation → content/bayes → behavioral → score."""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from asg.models import FactorResult, Message, Verdict
from asg.geo.cidr import ip_blocked, load_cidrs
from asg.protocol.auth import check_dkim, check_dmarc, check_spf
from asg.reputation.rbl import query_rbl
from asg.content.analyze import analyze_content
from asg.bayes.classifier import BayesModel
from asg.behavioral.rate import RateLimiter
from asg.scoring.engine import decide


class ASGEngine:
    def __init__(self, config: dict, root: Path):
        self.config = config
        self.root = root
        cidr_rel = config.get("cidr_file", "data/cidr/blocklist.txt")
        self.cidrs = load_cidrs(root / cidr_rel)
        model_rel = config.get("model_file", "data/models/bayes_model.json")
        self.model = BayesModel.load(root / model_rel)
        beh = config.get("behavioral") or {}
        self.limiter = RateLimiter(int(beh.get("max_messages_per_minute", 30)))
        self.weights = config.get("weights") or {}
        self.thresholds = config.get("thresholds") or {}
        lists = config.get("lists") or {}
        self.offline = bool(lists.get("offline_demo", True))
        self.rbl_enabled = bool(lists.get("rbl_enabled", True))

    def process(self, msg: Message) -> Verdict:
        factors = []
        w = self.weights

        blocked, detail = ip_blocked(msg.client_ip, self.cidrs)
        if blocked:
            factors.append(FactorResult("geo", float(w.get("geo", 100)), detail, hard_reject=True))
            return decide(factors, self.thresholds)

        spf, spf_d = check_spf(msg.mail_from, msg.client_ip, msg.headers, self.offline)
        dkim, dkim_d = check_dkim(msg.headers, self.offline)
        dmarc, dmarc_d = check_dmarc(msg.mail_from, msg.headers, spf, dkim, self.offline)
        if spf == "fail":
            factors.append(FactorResult("spf", float(w.get("spf_fail", 25)), f"{spf}:{spf_d}"))
        if dkim == "fail":
            factors.append(FactorResult("dkim", float(w.get("dkim_fail", 20)), f"{dkim}:{dkim_d}"))
        if dmarc == "fail":
            factors.append(FactorResult("dmarc", float(w.get("dmarc_fail", 25)), f"{dmarc}:{dmarc_d}"))

        hit, rdetail = query_rbl(msg.client_ip, self.offline, self.rbl_enabled)
        if hit:
            factors.append(FactorResult("rbl", float(w.get("rbl_hit", 40)), rdetail))

        cscore, chits = analyze_content(msg.headers, msg.body)
        if cscore > 0:
            factors.append(FactorResult(
                "content",
                min(cscore, float(w.get("phishing_heuristic", 35))),
                ",".join(chits) or "heuristics",
            ))
        text = msg.body + " " + msg.headers.get("Subject", "")
        bp, tokens = self.model.score(text)
        if bp >= 0.7:
            factors.append(FactorResult(
                "bayes",
                float(w.get("bayes_spam", 30)) * bp,
                f"p={bp:.2f};tokens={','.join(tokens[:3])}",
            ))

        limited, ldetail = self.limiter.check(msg.client_ip)
        if limited:
            factors.append(FactorResult("rate", float(w.get("rate_limit", 20)), ldetail))

        return decide(factors, self.thresholds)


def message_from_dict(d: dict) -> Message:
    return Message(
        message_id=d.get("message_id") or str(uuid.uuid4()),
        mail_from=d.get("mail_from") or d.get("from") or "",
        rcpt_to=list(d.get("rcpt_to") or d.get("to") or []),
        client_ip=d.get("client_ip") or "127.0.0.1",
        headers=dict(d.get("headers") or {}),
        body=d.get("body") or "",
        helo=d.get("helo") or "",
        raw_size=int(d.get("raw_size") or 0),
    )
