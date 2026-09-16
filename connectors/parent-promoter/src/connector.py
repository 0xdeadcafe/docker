#!/usr/bin/env python3
"""
Parent Reputation Aggregator — OpenCTI Internal Enrichment Connector

Triggered on parent observables created by ioc-trust-cluster (CIDR blocks,
NS domain anchors, CA cert anchors).  Reads the score distribution of their
linked children and promotes the parent's score when a threshold fraction of
children carry a consistent verdict.

Promotion rules
───────────────
MALICIOUS promotion
    ≥ PROMOTER_MALICIOUS_CHILD_PCT % of *scored* children are CONFIRMED_MALICIOUS
    (score ≥ MALICIOUS_SCORE_MIN, no malicious-cascade label — directly assessed)
    AND ≥ PROMOTER_MIN_CHILDREN scored children exist
    → set parent score to PROMOTER_MALICIOUS_SCORE (default 80)

BENIGN promotion
    ≥ PROMOTER_BENIGN_CHILD_PCT % of *scored* children carry fp-candidate
    AND none are CONFIRMED_MALICIOUS
    AND ≥ PROMOTER_MIN_CHILDREN scored children exist
    → set parent score to 15, add fp-candidate label

"Scored children" = score ≠ 50 (unknown anchors excluded from denominator).

Idempotency: parent already at the target score → no write, no note.
"""

from __future__ import annotations

import os

from pycti import OpenCTIConnectorHelper


# ── Constants ─────────────────────────────────────────────────────────────────

LABEL_FP_CANDIDATE      = "fp-candidate"
LABEL_MALICIOUS_CASCADE = "malicious-cascade"

COLOR_FP = "#2e7d32"   # green — benign / fp candidate

# Types this connector is triggered on (parent observable types only).
PARENT_TYPES = {"IPv4-Addr", "IPv6-Addr", "Domain-Name", "X509-Certificate"}


# ── Connector ─────────────────────────────────────────────────────────────────

class ParentPromoterConnector:

    def __init__(self) -> None:
        self.confidence: int = int(os.environ.get("CONNECTOR_CONFIDENCE_LEVEL", "75"))
        config = {
            "opencti": {
                "url":   os.environ.get("OPENCTI_URL",   "http://opencti:8080"),
                "token": os.environ.get("OPENCTI_TOKEN"),
            },
            "connector": {
                "id":               os.environ.get("CONNECTOR_ID"),
                "type":             "INTERNAL_ENRICHMENT",
                "name":             os.environ.get("CONNECTOR_NAME", "Parent Reputation Aggregator"),
                "scope":            "IPv4-Addr,IPv6-Addr,Domain-Name,X509-Certificate",
                "auto":             os.environ.get("CONNECTOR_AUTO", "true").lower() == "true",
                "confidence_level": self.confidence,
                "log_level":        os.environ.get("CONNECTOR_LOG_LEVEL", "info"),
            },
        }
        self.helper = OpenCTIConnectorHelper(config)

        self.malicious_score_min:    int   = int(os.environ.get("PROMOTER_MALICIOUS_SCORE_MIN",    "70"))
        self.malicious_child_pct:    float = float(os.environ.get("PROMOTER_MALICIOUS_CHILD_PCT",  "0.60"))
        self.benign_child_pct:       float = float(os.environ.get("PROMOTER_BENIGN_CHILD_PCT",     "0.70"))
        self.min_children:           int   = int(os.environ.get("PROMOTER_MIN_CHILDREN",           "3"))
        self.promoted_malicious_score: int = int(os.environ.get("PROMOTER_MALICIOUS_SCORE",        "80"))

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _entity_score(entity: dict) -> int:
        raw = entity.get("x_opencti_score")
        return int(raw) if raw is not None else 50

    @staticmethod
    def _entity_labels(entity: dict) -> set[str]:
        return {lbl.get("value", "") for lbl in (entity.get("objectLabel") or [])}

    def _get_children(self, entity_id: str) -> list[dict]:
        """
        Return child observables linked to entity_id via related-to relationships.
        ioc-trust-cluster creates these as: fromId=child, toId=parent.
        ponytail: reads each child individually; add bulk fetch when slow on large CIDRs.
        """
        try:
            rels = self.helper.api.stix_core_relationship.list(
                toId=entity_id,
                relationship_type="related-to",
            ) or []
        except Exception as exc:
            self.helper.log_error(f"[parent-promoter] relationship list failed: {exc}")
            return []

        children = []
        for rel in rels:
            child_stub = rel.get("from") or {}
            cid = child_stub.get("id")
            if not cid:
                continue
            # If the stub already has score + labels embedded, use it directly
            # to avoid an extra round-trip.  Fall back to a full read if not.
            if "x_opencti_score" in child_stub and "objectLabel" in child_stub:
                children.append(child_stub)
            else:
                try:
                    child = self.helper.api.stix_cyber_observable.read(id=cid)
                    if child:
                        children.append(child)
                except Exception as exc:
                    self.helper.log_debug(
                        f"[parent-promoter] child read failed {cid}: {exc}"
                    )
        return children

    def _add_label(self, obs_id: str, label: str, color: str) -> bool:
        try:
            result = self.helper.api.label.create(value=label, color=color)
            self.helper.api.stix_cyber_observable.add_label(id=obs_id, label_id=result["id"])
            return True
        except Exception as exc:
            self.helper.log_warning(f"[parent-promoter] add_label failed '{label}': {exc}")
            return False

    def _set_score(self, obs_id: str, score: int) -> bool:
        try:
            self.helper.api.stix_cyber_observable.update_field(
                id=obs_id,
                input=[{"key": "x_opencti_score", "value": str(score)}],
            )
            return True
        except Exception as exc:
            self.helper.log_error(f"[parent-promoter] score update failed: {exc}")
            return False

    def _create_note(self, obs_id: str, entity_type: str, value: str,
                     actions: list[str], stats: dict) -> None:
        try:
            content = (
                f"## Parent Reputation Aggregator\n\n"
                f"**Observable:** `{entity_type}:{value}`\n\n"
                f"**Children analysed:** {stats['total']} total, "
                f"{stats['scored']} scored (score ≠ 50)\n\n"
                f"| Verdict | Count | % of scored |\n|---|---|---|\n"
                f"| Malicious (direct) | {stats['malicious']} | "
                f"{stats['malicious_pct']:.0%} |\n"
                f"| FP candidate | {stats['fp']} | {stats['fp_pct']:.0%} |\n\n"
                f"**Actions taken:**\n"
                + "\n".join(f"- {a}" for a in actions)
                + "\n\n---\n_Generated by `connector-parent-promoter`._"
            )
            self.helper.api.note.create(
                abstract=f"Parent Promoter: {entity_type}:{value}",
                content=content,
                objectRefs=[obs_id],
                confidence=self.confidence,
            )
        except Exception as exc:
            self.helper.log_debug(f"[parent-promoter] note create skipped: {exc}")

    # ── Pipeline ───────────────────────────────────────────────────────────────

    def process_message(self, data: dict) -> str:
        entity_id   = data.get("entity_id")
        entity_type = data.get("entity_type")

        if not entity_id:
            return "skipped: no entity_id"
        if entity_type not in PARENT_TYPES:
            return f"skipped: {entity_type} is not a parent type"

        entity = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if not entity:
            return "skipped: entity not found"

        value         = entity.get("value") or entity.get("observable_value") or entity_id
        parent_score  = self._entity_score(entity)
        parent_labels = self._entity_labels(entity)

        children = self._get_children(entity_id)
        if not children:
            return "no children"

        # Score distribution — exclude unknown anchors (score=50) from denominator
        scored = [
            (self._entity_score(c), self._entity_labels(c))
            for c in children
            if self._entity_score(c) != 50
        ]
        n_scored = len(scored)

        if n_scored < self.min_children:
            self.helper.log_debug(
                f"[parent-promoter] {entity_type}:{value} — "
                f"insufficient scored children: {n_scored} < {self.min_children}"
            )
            return f"insufficient scored children: {n_scored}"

        n_malicious = sum(
            1 for s, lbl in scored
            if s >= self.malicious_score_min and LABEL_MALICIOUS_CASCADE not in lbl
        )
        n_fp = sum(1 for _, lbl in scored if LABEL_FP_CANDIDATE in lbl)

        malicious_pct = n_malicious / n_scored
        fp_pct        = n_fp        / n_scored

        stats = {
            "total": len(children), "scored": n_scored,
            "malicious": n_malicious, "malicious_pct": malicious_pct,
            "fp": n_fp, "fp_pct": fp_pct,
        }
        actions: list[str] = []

        # ── Malicious promotion ────────────────────────────────────────────────
        if malicious_pct >= self.malicious_child_pct:
            if parent_score < self.promoted_malicious_score:
                if self._set_score(entity_id, self.promoted_malicious_score):
                    actions.append(
                        f"score set to {self.promoted_malicious_score} "
                        f"({n_malicious}/{n_scored} = {malicious_pct:.0%} malicious children)"
                    )
            else:
                self.helper.log_debug(
                    f"[parent-promoter] {entity_type}:{value} already at "
                    f"score={parent_score} (idempotent)"
                )

        # ── Benign promotion ───────────────────────────────────────────────────
        elif fp_pct >= self.benign_child_pct and n_malicious == 0:
            if LABEL_FP_CANDIDATE not in parent_labels:
                if self._add_label(entity_id, LABEL_FP_CANDIDATE, COLOR_FP):
                    actions.append(
                        f"fp-candidate applied "
                        f"({n_fp}/{n_scored} = {fp_pct:.0%} fp children)"
                    )
            if parent_score > 15:
                if self._set_score(entity_id, 15):
                    actions.append("score lowered to 15 (benign promotion)")

        if actions:
            self._create_note(entity_id, entity_type, value, actions, stats)

        result = f"{len(actions)} action(s): {'; '.join(actions)}" if actions else "no actions"
        self.helper.log_info(f"[parent-promoter] {entity_type}:{value} → {result}")
        return result

    def run(self) -> None:
        self.helper.listen(self.process_message)


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    connector = ParentPromoterConnector()
    connector.run()
