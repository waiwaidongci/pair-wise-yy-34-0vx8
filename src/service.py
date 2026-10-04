from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import (ConflictError, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES, STATES,
                    TERMINAL_STATES, TITLE, VIEW_ROLES, completion_blockers,
                    escalation_required, priority_score, response_deadline_hours,
                    role_for_transition, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        }, op_id=f"create:item:{item['id']}")
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        try:
            record = self.repository.add_record(item_id, kind, detail, status,
                                                external_ref, actor)
        except ConflictError:
            # 同一措施先到者生效，后到者保留冲突稿
            draft = self.repository.add_record_conflict(item_id, kind, detail, status,
                                                        external_ref, actor)
            self.repository.append_audit("record_conflict", ENTITY, item_id, actor, {
                "draft_id": draft["id"], "kind": kind, "external_ref": external_ref,
                "conflicting_record_id": draft["conflicting_record_id"],
            }, op_id=f"record_conflict:{draft['id']}")
            raise ConflictError(f"记录唯一标识已存在，已保留冲突稿#{draft['id']}")
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        }, op_id=f"record:{record['id']}")
        # 关闭依据一变（归档后补录），当前结论失效，事故回到验证并保留原快照
        invalidated = self.repository.invalidate_closure(item_id, record, actor)
        if invalidated is not None:
            self.repository.append_audit("closure_invalidated", ENTITY, item_id, actor, {
                "snapshot_id": invalidated.get("id"),
                "trigger": {"record_id": record["id"], "kind": kind,
                            "external_ref": external_ref, "actor": actor},
                "reopened_to": STATES[-2],
            }, op_id=f"closure_invalidated:{item_id}:{record['id']}")
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        detail = {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        }
        if target in TERMINAL_STATES:
            # 关闭时冻结事故版本和全部措施状态
            updated, snapshot = self.repository.close_item(item_id, expected_version, actor)
            detail["snapshot_id"] = snapshot["id"]
            detail["frozen_version"] = snapshot["item_version"]
            detail["frozen_records"] = snapshot["record_count"]
        else:
            updated = self.repository.transition_item(item_id, target,
                                                      expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, detail,
                                     op_id=f"transition:{item_id}:{expected_version}")
        return self.enrich(updated, self._closure_info(
            self.repository.latest_snapshot(item_id)))

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id),
                           self._closure_info(self.repository.latest_snapshot(item_id)))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        snapshots = self.repository.latest_snapshot_map()
        return [self.enrich(item, self._closure_info(snapshots.get(item["id"])))
                for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def list_record_conflicts(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_record_conflicts(item_id)

    def list_closures(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_snapshots(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    @staticmethod
    def _closure_info(snapshot: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if snapshot is None:
            return None
        return {
            "snapshot_id": snapshot["id"],
            "state": snapshot["status"],
            "source": snapshot["source"],
            "item_version": snapshot["item_version"],
            "record_count": snapshot["record_count"],
            "created_by": snapshot["created_by"],
            "created_at": snapshot["created_at"],
            "invalidated_at": snapshot["invalidated_at"],
            "invalidated_by": snapshot["invalidated_by"],
        }

    @staticmethod
    def enrich(item: Dict[str, Any],
               closure: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        result["closure"] = closure
        return result
