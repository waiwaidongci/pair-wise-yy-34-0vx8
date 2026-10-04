from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .domain import (ConflictError, ensure_role, normalize_severity, require_number,
                     require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES, TITLE,
                    VIEW_ROLES, basis_hash, completion_blockers,
                    escalation_required, priority_score, response_deadline_hours,
                    role_for_transition, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository
        # 旧事故补齐：启动时为已关闭但无快照的事故按现状补一份冻结快照
        repository.backfill_snapshots()

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    # ---- 操作号幂等：同一操作号只记账一次，重试直接回放 ----
    def _replay(self, operation_no: Optional[str]) -> Optional[Dict[str, Any]]:
        if not operation_no:
            return None
        return self.repository.find_audit_by_operation(operation_no)

    def _replay_item(self, event: Dict[str, Any]) -> Dict[str, Any]:
        item = self.repository.get_item(event["entity_id"])
        result = self.enrich(item)
        result["replayed"] = True
        return result

    def _replay_record(self, event: Dict[str, Any]) -> Dict[str, Any]:
        detail = event["detail"]
        if isinstance(detail, str):
            detail = json.loads(detail)
        record_id = detail.get("record_id")
        if record_id:
            record = self.repository.get_record(int(record_id))
            if record is not None:
                result = dict(record)
                result["replayed"] = True
                return result
        draft_id = detail.get("draft_id")
        if draft_id:
            draft = self.repository.get_conflict_draft(int(draft_id))
            return {"conflict": True, "draft": draft, "replayed": True}
        return self._replay_item(event)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str,
                    operation_no: Optional[str] = None) -> Dict[str, Any]:
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
        replay = self._replay(operation_no)
        if replay is not None:
            return self._replay_item(replay)

        def fn(conn):
            item = self.repository.create_item(title, description, severity, quantity,
                                               threshold, external_ref, actor)
            self.repository.append_audit("create", ENTITY, item["id"], actor, {
                "title": title, "severity": severity, "quantity": quantity,
                "priority": priority_score(severity, quantity, threshold),
            }, operation_no=operation_no)
            return item

        item = self.repository.atomic(fn)
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str, operation_no: Optional[str] = None) -> Dict[str, Any]:
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
        replay = self._replay(operation_no)
        if replay is not None:
            return self._replay_record(replay)

        def fn(conn):
            # 两名调查员提交同一措施：先到者生效，后到者留冲突稿
            record = self.repository.add_record(item_id, kind, detail, status,
                                                external_ref, actor)
            if record is None:
                draft = self.repository.insert_conflict_draft(
                    item_id, kind, detail, status, external_ref, actor,
                    reason="duplicate_external_ref")
                self.repository.append_audit("record_conflict", ENTITY, item_id, actor, {
                    "draft_id": draft["id"], "kind": kind,
                    "external_ref": external_ref,
                }, operation_no=operation_no)
                return {"conflict": True, "draft": draft}

            # 关闭复核：关闭依据一变，当前结论失效，事故回到验证并保留原快照
            invalidation = None
            snapshot = self.repository.get_valid_snapshot(item_id)
            if snapshot is not None:
                item = self.repository.get_item(item_id)
                records = self.repository.list_records(item_id)
                if basis_hash(item, records) != snapshot["basis_hash"]:
                    source = f"record:{record['id']}:{kind}"
                    self.repository.invalidate_snapshot(
                        snapshot["id"], "record_added", source)
                    self.repository.revert_item_to_verification(item_id, actor)
                    invalidation = {
                        "snapshot_id": snapshot["id"],
                        "reason": "record_added",
                        "source": source,
                        "reverted_to": "verification",
                    }
                    self.repository.append_audit("invalidate", ENTITY, item_id, actor, {
                        "snapshot_id": snapshot["id"],
                        "reason": "record_added",
                        "source": source,
                        "record_id": record["id"],
                        "reverted_to": "verification",
                    }, operation_no=None)

            self.repository.append_audit("record", ENTITY, item_id, actor, {
                "record_id": record["id"], "kind": kind, "status": status,
                "invalidation": invalidation,
            }, operation_no=operation_no)
            return {"conflict": False, "record": record, "invalidation": invalidation}

        return self.repository.atomic(fn)

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str,
                   operation_no: Optional[str] = None) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        # 幂等回放优先：同一操作号已记账则直接返回，避免对已变更状态重复校验/转换
        replay = self._replay(operation_no)
        if replay is not None:
            return self._replay_item(replay)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))

        def fn(conn):
            updated = self.repository.transition_item(item_id, target,
                                                      expected_version, actor)
            snapshot = None
            if target == "closed":
                # 关闭时冻结事故版本与全部措施状态
                snapshot = self.repository.create_snapshot(item_id, actor)
            self.repository.append_audit("transition", ENTITY, item_id, actor, {
                "from": item["status"], "to": target,
                "snapshot_id": snapshot["id"] if snapshot else None,
                "item_version": updated["version"],
                "escalation_required": escalation_required(
                    item["severity"], item["quantity"], item["threshold"]),
            }, operation_no=operation_no)
            return updated

        updated = self.repository.atomic(fn)
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def list_conflict_drafts(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_conflict_drafts(item_id)

    def list_snapshots(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_snapshots(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    def enrich(self, item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        # 关闭复核：列表与详情展示当前结论是否失效及失效来源
        result["close_review"] = self._close_review(item["id"])
        return result

    def _close_review(self, item_id: int) -> Optional[Dict[str, Any]]:
        snapshot = self.repository.get_latest_snapshot(item_id)
        if snapshot is None:
            return None
        return {
            "snapshot_id": snapshot["id"],
            "item_version": snapshot["item_version"],
            "status": snapshot["status"],
            "basis_hash": snapshot["basis_hash"],
            "invalidation_reason": snapshot.get("invalidation_reason"),
            "invalidation_source": snapshot.get("invalidation_source"),
            "invalidated_at": snapshot.get("invalidated_at"),
            "created_at": snapshot["created_at"],
        }
