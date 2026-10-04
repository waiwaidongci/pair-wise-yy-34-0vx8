from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ENTITY, ID_PREFIX, STATES


class Repository:
    _SNAPSHOT_COLS = ("id, item_id, item_version, record_count, status, source, "
                      "invalidated_by, invalidated_at, created_by, created_at")

    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()
        self._migrate()
        self.backfill_closure_snapshots()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.conn:
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
                    op_id TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS closure_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    item_version INTEGER NOT NULL,
                    record_count INTEGER NOT NULL,
                    data TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active'
                        CHECK(status IN ('active','invalidated')),
                    source TEXT NOT NULL DEFAULT 'closure'
                        CHECK(source IN ('closure','backfill')),
                    invalidated_by TEXT,
                    invalidated_at TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_closure_snapshots_item
                    ON closure_snapshots(item_id, status);
                CREATE TABLE IF NOT EXISTS record_conflicts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL,
                    external_ref TEXT,
                    conflicting_record_id INTEGER,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)

    def _migrate(self) -> None:
        columns = {row["name"] for row in
                   self.conn.execute("PRAGMA table_info(audit_events)").fetchall()}
        with self.conn:
            if "op_id" not in columns:
                self.conn.execute("ALTER TABLE audit_events ADD COLUMN op_id TEXT")
            self.conn.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_events_op_id
                   ON audit_events(op_id) WHERE op_id IS NOT NULL""")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _snapshot_meta(row: sqlite3.Row) -> Dict[str, Any]:
        snap = dict(row)
        snap.pop("data", None)
        snap["invalidated_by"] = (json.loads(snap["invalidated_by"])
                                  if snap["invalidated_by"] else None)
        return snap

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
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
        with self._lock, self.conn:
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

    def close_item(self, item_id: int, expected_version: int,
                   actor: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """关闭事故并在同一事务内冻结事故版本与全部措施状态。"""
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (STATES[-1], now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
            item = dict(self.conn.execute(
                "SELECT * FROM items WHERE id=?", (item_id,)).fetchone())
            records = [dict(r) for r in self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)).fetchall()]
            data = {"item": item, "records": records}
            cur = self.conn.execute(
                """INSERT INTO closure_snapshots(item_id, item_version, record_count, data,
                   status, source, created_by, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (item_id, item["version"], len(records),
                 json.dumps(data, ensure_ascii=False, sort_keys=True),
                 "active", "closure", actor, now),
            )
            snapshot_id = int(cur.lastrowid)
            row = self.conn.execute(
                f"SELECT {self._SNAPSHOT_COLS} FROM closure_snapshots WHERE id=?",
                (snapshot_id,)).fetchone()
            snapshot = self._snapshot_meta(row)
        return item, snapshot

    def invalidate_closure(self, item_id: int, record: Dict[str, Any],
                           actor: str) -> Optional[Dict[str, Any]]:
        """关闭依据变化：事故退回验证，当前快照标记失效并记录来源。

        事故不在closed状态时返回None（幂等，无需处理）。
        """
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND status=?""",
                (STATES[-2], now, item_id, STATES[-1]),
            )
            if cur.rowcount == 0:
                return None
            row = self.conn.execute(
                """SELECT * FROM closure_snapshots
                   WHERE item_id=? AND status='active' ORDER BY id DESC LIMIT 1""",
                (item_id,)).fetchone()
            if row is None:
                return {"id": None}
            source = {"record_id": record["id"], "kind": record["kind"],
                      "external_ref": record["external_ref"], "actor": actor, "at": now}
            self.conn.execute(
                """UPDATE closure_snapshots
                   SET status='invalidated', invalidated_by=?, invalidated_at=?
                   WHERE id=?""",
                (json.dumps(source, ensure_ascii=False, sort_keys=True), now, row["id"]),
            )
            snapshot = self._snapshot_meta(row)
            snapshot["status"] = "invalidated"
            snapshot["invalidated_by"] = source
            snapshot["invalidated_at"] = now
            return snapshot

    def backfill_closure_snapshots(self, actor: str = "system") -> List[Dict[str, Any]]:
        """旧事故没有快照的按现状补齐（启动时执行，幂等）。"""
        with self._lock:
            rows = self.conn.execute(
                """SELECT i.* FROM items i
                   WHERE i.status=? AND NOT EXISTS(
                       SELECT 1 FROM closure_snapshots s WHERE s.item_id=i.id)
                   ORDER BY i.id""",
                (STATES[-1],)).fetchall()
        created = []
        for row in rows:
            item = dict(row)
            records = self.list_records(item["id"])
            now = utc_now()
            data = {"item": item, "records": records}
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO closure_snapshots(item_id, item_version, record_count, data,
                       status, source, created_by, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                    (item["id"], item["version"], len(records),
                     json.dumps(data, ensure_ascii=False, sort_keys=True),
                     "active", "backfill", actor, now),
                )
                snapshot_id = int(cur.lastrowid)
            self.append_audit("snapshot_backfill", ENTITY, item["id"], actor, {
                "snapshot_id": snapshot_id, "item_version": item["version"],
                "record_count": len(records),
            }, op_id=f"backfill:{item['id']}")
            created.append({"item_id": item["id"], "snapshot_id": snapshot_id})
        return created

    def latest_snapshot(self, item_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                f"""SELECT {self._SNAPSHOT_COLS} FROM closure_snapshots
                    WHERE item_id=? ORDER BY id DESC LIMIT 1""",
                (item_id,)).fetchone()
        return self._snapshot_meta(row) if row else None

    def latest_snapshot_map(self) -> Dict[int, Dict[str, Any]]:
        cols = ", ".join("s." + c for c in self._SNAPSHOT_COLS.split(", "))
        with self._lock:
            rows = self.conn.execute(
                f"""SELECT {cols} FROM closure_snapshots s
                    INNER JOIN (SELECT item_id, MAX(id) AS mid
                                FROM closure_snapshots GROUP BY item_id) t
                    ON s.id = t.mid""").fetchall()
        return {row["item_id"]: self._snapshot_meta(row) for row in rows}

    def list_snapshots(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM closure_snapshots WHERE item_id=? ORDER BY id",
                (item_id,)).fetchall()
        result = []
        for row in rows:
            snap = self._snapshot_meta(row)
            snap["data"] = json.loads(row["data"])
            result.append(snap)
        return result

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def add_record_conflict(self, item_id: int, kind: str, detail: str, status: str,
                            external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        """后到者留冲突稿：保留被唯一约束拒绝的措施提交。"""
        now = utc_now()
        self.get_item(item_id)
        with self._lock, self.conn:
            winner = self.conn.execute(
                """SELECT id FROM records WHERE item_id=? AND external_ref=?
                   ORDER BY id LIMIT 1""",
                (item_id, external_ref)).fetchone()
            cur = self.conn.execute(
                """INSERT INTO record_conflicts(item_id, kind, detail, status, external_ref,
                   conflicting_record_id, created_by, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (item_id, kind, detail, status, external_ref,
                 winner["id"] if winner else None, actor, now),
            )
            draft_id = int(cur.lastrowid)
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM record_conflicts WHERE id=?", (draft_id,)).fetchone()
        return dict(row)

    def list_record_conflicts(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM record_conflicts WHERE item_id=? ORDER BY id",
                (item_id,)).fetchall()
        return [dict(row) for row in rows]

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

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict,
                     op_id: Optional[str] = None) -> Dict[str, Any]:
        """追加审计事件；携带op_id时按操作号幂等，重试不重复记账。"""
        with self._lock:
            if op_id is not None:
                existing = self.audit_by_op(op_id)
                if existing is not None:
                    return existing
            try:
                with self.conn:
                    row = self.conn.execute(
                        "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
                    ).fetchone()
                    previous = row["entry_hash"] if row else "GENESIS"
                    event = make_entry(action, entity_type, entity_id, actor, detail, previous)
                    cur = self.conn.execute(
                        """INSERT INTO audit_events(action, entity_type, entity_id, actor,
                           detail, previous_hash, entry_hash, op_id, created_at)
                           VALUES(?,?,?,?,?,?,?,?,?)""",
                        (event["action"], event["entity_type"], event["entity_id"],
                         event["actor"],
                         json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                         event["previous_hash"], event["entry_hash"], op_id,
                         event["created_at"]),
                    )
                    event_id = int(cur.lastrowid)
            except sqlite3.IntegrityError:
                if op_id is None:
                    raise
                existing = self.audit_by_op(op_id)
                if existing is None:
                    raise
                return existing
        event["id"] = event_id
        event["op_id"] = op_id
        return event

    def audit_by_op(self, op_id: str) -> Optional[Dict[str, Any]]:
        """按操作号恢复审计事件，用于写入失败后的对账与重试。"""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM audit_events WHERE op_id=?", (op_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["detail"] = json.loads(item["detail"])
        return item

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
