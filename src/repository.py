from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import (CONFLICT_REASONS, ID_PREFIX, REVERT_TARGET, SNAPSHOT_STATUSES,
                     STATES, basis_hash)


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        # 关闭隐式事务，改用 _tx 显式管理 BEGIN/COMMIT/SAVEPOINT，
        # 从而支持多层嵌套事务（原子化的“操作+审计”）。
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False,
                                    isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._tx_depth = 0
        self._create_schema()

    @contextmanager
    def _tx(self):
        """嵌套事务：最外层 BEGIN，内层用 SAVEPOINT，异常时整体回滚。"""
        with self._lock:
            depth = self._tx_depth
            if depth == 0:
                self.conn.execute("BEGIN")
                self._tx_depth = 1
            else:
                self.conn.execute(f"SAVEPOINT sp_{depth}")
                self._tx_depth = depth + 1
            try:
                yield self.conn
            except BaseException:
                self._tx_depth = depth
                if depth == 0:
                    self.conn.execute("ROLLBACK")
                else:
                    self.conn.execute(f"ROLLBACK TO SAVEPOINT sp_{depth}")
                raise
            else:
                self._tx_depth = depth
                if depth == 0:
                    self.conn.execute("COMMIT")
                else:
                    self.conn.execute(f"RELEASE SAVEPOINT sp_{depth}")

    def atomic(self, fn: Callable[[sqlite3.Connection], Any]) -> Any:
        """在单一事务内执行 fn，用于把主操作与审计写入绑定为原子操作。"""
        with self._tx():
            return fn(self.conn)

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        snapshot_statuses = ",".join("'" + s.replace("'", "''") + "'"
                                     for s in SNAPSHOT_STATUSES)
        with self._lock:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS close_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    item_version INTEGER NOT NULL,
                    basis_hash TEXT NOT NULL,
                    snapshot TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'valid'
                        CHECK(status IN ({snapshot_statuses})),
                    invalidation_reason TEXT,
                    invalidation_source TEXT,
                    created_at TEXT NOT NULL,
                    invalidated_at TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_close_snapshots_item
                    ON close_snapshots(item_id, status);
                CREATE TABLE IF NOT EXISTS conflict_drafts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    reason TEXT NOT NULL DEFAULT 'duplicate_external_ref',
                    resolved INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS ix_conflict_drafts_item
                    ON conflict_drafts(item_id);
            """)
            # 迁移：为旧库的 audit_events 补 operation_no 列
            cols = [r["name"] for r in
                    self.conn.execute("PRAGMA table_info(audit_events)").fetchall()]
            if "operation_no" not in cols:
                self.conn.execute("ALTER TABLE audit_events ADD COLUMN operation_no TEXT")
            self.conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_operation_no "
                "ON audit_events(operation_no) WHERE operation_no IS NOT NULL")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._tx():
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._tx():
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def revert_item_to_verification(self, item_id: int, actor: str) -> None:
        """关闭依据失效后，把事故退回验证态（仅当仍处于 closed 时）。"""
        now = utc_now()
        with self._tx():
            self.conn.execute(
                f"UPDATE items SET status='{REVERT_TARGET}', version=version+1, updated_at=? "
                "WHERE id=? AND status='closed'",
                (now, item_id),
            )

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Optional[Dict[str, Any]]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._tx():
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError:
            # 同一 (item_id, external_ref) 已存在：返回 None，由调用方落冲突稿
            return None
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def get_record(self, record_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row) if row else None

    def record_exists(self, item_id: int, external_ref: Optional[str]) -> bool:
        if not external_ref:
            return False
        with self._lock:
            row = self.conn.execute(
                "SELECT 1 FROM records WHERE item_id=? AND external_ref=? LIMIT 1",
                (item_id, external_ref),
            ).fetchone()
        return row is not None

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    # ---- 冲突稿 ----
    def insert_conflict_draft(self, item_id: int, kind: str, detail: str, status: str,
                              external_ref: Optional[str], actor: str,
                              reason: str = "duplicate_external_ref") -> Dict[str, Any]:
        if reason not in CONFLICT_REASONS:
            reason = CONFLICT_REASONS[0]
        now = utc_now()
        with self._tx():
            cur = self.conn.execute(
                """INSERT INTO conflict_drafts(item_id, kind, detail, status, external_ref,
                   created_by, created_at, reason) VALUES(?,?,?,?,?,?,?,?)""",
                (item_id, kind, detail, status, external_ref, actor, now, reason),
            )
            draft_id = int(cur.lastrowid)
        return self.get_conflict_draft(draft_id)

    def get_conflict_draft(self, draft_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM conflict_drafts WHERE id=?", (draft_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("冲突稿不存在")
        return dict(row)

    def list_conflict_drafts(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM conflict_drafts WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    # ---- 关闭快照 ----
    def create_snapshot(self, item_id: int, actor: str) -> Dict[str, Any]:
        with self._tx():
            item = self.get_item(item_id)
            records = self.list_records(item_id)
            basis = basis_hash(item, records)
            snapshot_data = json.dumps(
                {"item": item, "records": records},
                ensure_ascii=False, sort_keys=True, default=str,
            )
            now = utc_now()
            # 同一事故只保留一份有效快照：旧的有效快照标记为已取代
            self.conn.execute(
                "UPDATE close_snapshots SET status='superseded' "
                "WHERE item_id=? AND status='valid'",
                (item_id,),
            )
            cur = self.conn.execute(
                """INSERT INTO close_snapshots(item_id, item_version, basis_hash, snapshot,
                   status, created_at) VALUES(?,?,?,?, 'valid', ?)""",
                (item_id, item["version"], basis, snapshot_data, now),
            )
            snapshot_id = int(cur.lastrowid)
        return self.get_snapshot(snapshot_id)

    def get_snapshot(self, snapshot_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM close_snapshots WHERE id=?", (snapshot_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("快照不存在")
        return dict(row)

    def get_valid_snapshot(self, item_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM close_snapshots WHERE item_id=? AND status='valid' "
                "ORDER BY id DESC LIMIT 1",
                (item_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_latest_snapshot(self, item_id: int) -> Optional[Dict[str, Any]]:
        """最近一次关闭快照（含已失效/已取代），用于展示当前结论状态与失效来源。"""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM close_snapshots WHERE item_id=? "
                "ORDER BY id DESC LIMIT 1",
                (item_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_snapshots(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM close_snapshots WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def invalidate_snapshot(self, snapshot_id: int, reason: str, source: str) -> None:
        now = utc_now()
        with self._tx():
            self.conn.execute(
                """UPDATE close_snapshots SET status='invalid', invalidation_reason=?,
                   invalidation_source=?, invalidated_at=?
                   WHERE id=? AND status='valid'""",
                (reason, source, now, snapshot_id),
            )

    def backfill_snapshots(self) -> List[Dict[str, Any]]:
        """旧事故补齐：对已关闭但无快照的事故，按现状冻结一份有效快照。"""
        with self._lock:
            rows = self.conn.execute(
                """SELECT i.id FROM items i
                   WHERE i.status='closed'
                     AND NOT EXISTS (SELECT 1 FROM close_snapshots s WHERE s.item_id=i.id)"""
            ).fetchall()
        created: List[Dict[str, Any]] = []
        for row in rows:
            try:
                created.append(self.create_snapshot(int(row["id"]), "system"))
            except Exception:
                # 补齐失败不应阻断启动；记录缺失快照仍可在下次补齐
                continue
        return created

    # ---- 审计（按操作号幂等） ----
    def find_audit_by_operation(self, operation_no: Optional[str]) -> Optional[Dict[str, Any]]:
        if not operation_no:
            return None
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM audit_events WHERE operation_no=? ORDER BY id DESC LIMIT 1",
                (operation_no,),
            ).fetchone()
        return dict(row) if row else None

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict,
                     operation_no: Optional[str] = None) -> Dict[str, Any]:
        with self._tx():
            if operation_no:
                existing = self.conn.execute(
                    "SELECT * FROM audit_events WHERE operation_no=? LIMIT 1",
                    (operation_no,),
                ).fetchone()
                if existing is not None:
                    return dict(existing)
            row = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            cur = self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at, operation_no)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"],
                 operation_no),
            )
            event_id = int(cur.lastrowid)
        event["id"] = event_id
        return event

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
            previous = "GENESIS"
            for row in rows:
                if row["previous_hash"] != previous:
                    return False
                payload = {
                    "action": row["action"], "entity_type": row["entity_type"],
                    "entity_id": row["entity_id"], "actor": row["actor"],
                    "detail": json.loads(row["detail"]), "created_at": row["created_at"],
                }
                if calculate_hash(previous, payload) != row["entry_hash"]:
                    return False
                previous = row["entry_hash"]
            return True

    def close(self) -> None:
        with self._lock:
            self.conn.close()
