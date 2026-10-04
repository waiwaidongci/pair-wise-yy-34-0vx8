import tempfile, threading, unittest
from pathlib import Path
from src.domain import ConflictError
from src.repository import Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES


class ClosureReviewTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "test.db")
        self.repo = Repository(self.db_path)
        self.service = Service(self.repo)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _open_item(self, ref="CL-1"):
        return self.service.create_item(
            {"title": "closure item", "description": "closure review flow",
             "severity": "serious", "quantity": 4, "threshold": 2,
             "external_ref": ref}, "creator", "reporter")

    def _close(self, item):
        current = item
        for target in STATES[1:]:
            current = self.service.transition(
                current["id"], target, current["version"],
                "reviewer", TRANSITION_ROLES[target][0])
        return current

    def test_close_freezes_item_version_and_records(self):
        item = self._open_item()
        self.service.add_record(item["id"], {
            "kind": "action", "detail": "加装防护罩", "status": "closed",
            "external_ref": "CL-A1"}, "inv_a", "investigator")
        closed = self._close(item)
        self.assertEqual(closed["status"], "closed")
        self.assertEqual(closed["closure"]["state"], "active")
        self.assertEqual(closed["closure"]["item_version"], closed["version"])
        closures = self.service.list_closures(item["id"], "viewer")
        self.assertEqual(len(closures), 1)
        snap = closures[0]
        self.assertEqual(snap["source"], "closure")
        self.assertEqual(snap["item_version"], closed["version"])
        self.assertEqual(snap["record_count"], 1)
        self.assertEqual(snap["data"]["item"]["version"], closed["version"])
        self.assertEqual(snap["data"]["records"][0]["external_ref"], "CL-A1")
        self.assertEqual(snap["data"]["records"][0]["status"], "closed")
        events = [e for e in self.service.audit("viewer", item["id"])
                  if e["action"] == "transition"]
        self.assertEqual(events[-1]["detail"]["snapshot_id"], snap["id"])
        self.assertTrue(self.repo.verify_audit_chain())

    def test_post_closure_record_invalidates_conclusion(self):
        item = self._open_item()
        closed = self._close(item)
        record = self.service.add_record(item["id"], {
            "kind": "recurrence", "detail": "现场复诊：伤情复发，需复岗评估",
            "status": "closed", "external_ref": "CL-REC-1"}, "inv_b", "investigator")
        updated = self.service.get_item(item["id"], "viewer")
        self.assertEqual(updated["status"], "verification")
        closure = updated["closure"]
        self.assertEqual(closure["state"], "invalidated")
        self.assertEqual(closure["invalidated_by"]["record_id"], record["id"])
        self.assertEqual(closure["invalidated_by"]["actor"], "inv_b")
        # 原快照保留，内容仍是关闭时的冻结状态
        closures = self.service.list_closures(item["id"], "viewer")
        self.assertEqual(len(closures), 1)
        self.assertEqual(closures[0]["status"], "invalidated")
        self.assertEqual(closures[0]["data"]["item"]["status"], "closed")
        self.assertEqual(closures[0]["data"]["records"], [])
        # 安全经理拿旧结论（旧版本）放行会被拒绝
        with self.assertRaises(ConflictError):
            self.service.transition(item["id"], "closed", closed["version"],
                                    "manager", "safety_manager")
        # 列表显示失效来源
        listed = [i for i in self.service.list_items("viewer")
                  if i["id"] == item["id"]][0]
        self.assertEqual(listed["closure"]["state"], "invalidated")
        self.assertEqual(listed["closure"]["invalidated_by"]["record_id"], record["id"])
        # 审计显示失效来源
        events = self.service.audit("viewer", item["id"])
        invalidated = [e for e in events if e["action"] == "closure_invalidated"]
        self.assertEqual(len(invalidated), 1)
        self.assertEqual(invalidated[0]["detail"]["trigger"]["record_id"], record["id"])
        self.assertEqual(invalidated[0]["detail"]["snapshot_id"], closures[0]["id"])
        self.assertTrue(self.repo.verify_audit_chain())
        # 重新关闭生成新快照，原快照保留
        reclosed = self.service.transition(item["id"], "closed", updated["version"],
                                           "manager", "safety_manager")
        self.assertEqual(reclosed["closure"]["state"], "active")
        closures = self.service.list_closures(item["id"], "viewer")
        self.assertEqual(len(closures), 2)
        self.assertEqual(closures[0]["status"], "invalidated")
        self.assertEqual(closures[1]["status"], "active")
        self.assertEqual(closures[1]["record_count"], 1)

    def test_reclose_blocked_until_supplementary_measure_closed(self):
        item = self._open_item()
        self._close(item)
        self.service.add_record(item["id"], {
            "kind": "recurrence", "detail": "复发措施待验证", "status": "open",
            "external_ref": "CL-OPEN"}, "inv_b", "investigator")
        updated = self.service.get_item(item["id"], "viewer")
        self.assertEqual(updated["status"], "verification")
        with self.assertRaises(ConflictError):
            self.service.transition(item["id"], "closed", updated["version"],
                                    "manager", "safety_manager")

    def test_concurrent_same_measure_keeps_conflict_draft(self):
        item = self._open_item()
        payload = {"kind": "action", "detail": "同一项纠正措施", "status": "open",
                   "external_ref": "CL-DUP"}
        barrier = threading.Barrier(2)
        outcome = {"ok": [], "conflict": []}

        def submit(actor):
            barrier.wait()
            try:
                self.service.add_record(item["id"], payload, actor, "investigator")
                outcome["ok"].append(actor)
            except ConflictError:
                outcome["conflict"].append(actor)

        threads = [threading.Thread(target=submit, args=(name,))
                   for name in ("inv_a", "inv_b")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 先到者生效，后到者留冲突稿
        self.assertEqual(len(outcome["ok"]), 1)
        self.assertEqual(len(outcome["conflict"]), 1)
        records = self.service.list_records(item["id"], "viewer")
        self.assertEqual(len(records), 1)
        drafts = self.service.list_record_conflicts(item["id"], "viewer")
        self.assertEqual(len(drafts), 1)
        self.assertEqual(drafts[0]["external_ref"], "CL-DUP")
        self.assertEqual(drafts[0]["conflicting_record_id"], records[0]["id"])
        self.assertEqual(drafts[0]["created_by"], outcome["conflict"][0])
        events = [e for e in self.service.audit("viewer", item["id"])
                  if e["action"] == "record_conflict"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["detail"]["conflicting_record_id"], records[0]["id"])
        self.assertTrue(self.repo.verify_audit_chain())

    def test_audit_retry_by_op_id_is_idempotent(self):
        item = self._open_item()
        first = self.repo.append_audit("record", "事故", item["id"], "inv",
                                       {"record_id": 1}, op_id="op-x")
        # 审计写入失败后按操作号恢复重试，不重复记账
        retry = self.repo.append_audit("record", "事故", item["id"], "inv",
                                       {"record_id": 1}, op_id="op-x")
        self.assertEqual(first["id"], retry["id"])
        self.assertEqual(first["entry_hash"], retry["entry_hash"])
        recovered = self.repo.audit_by_op("op-x")
        self.assertEqual(recovered["entry_hash"], first["entry_hash"])
        ops = [e for e in self.repo.list_audit() if e.get("op_id") == "op-x"]
        self.assertEqual(len(ops), 1)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_service_operation_op_id_recovery(self):
        item = self._open_item()
        self.service.transition(item["id"], "investigating", item["version"],
                                "reviewer", "investigator")
        before = self.repo.list_audit()
        # 按业务操作号重放审计写入，不产生重复事件
        replay = self.repo.append_audit(
            "transition", "事故", item["id"], "reviewer",
            {"from": "reported", "to": "investigating"},
            op_id=f"transition:{item['id']}:{item['version']}")
        after = self.repo.list_audit()
        self.assertEqual(len(before), len(after))
        self.assertEqual(replay["entry_hash"], before[-1]["entry_hash"])
        self.assertTrue(self.repo.verify_audit_chain())

    def test_backfill_legacy_closed_item(self):
        # 模拟旧事故：直接写入closed状态，没有任何快照
        with self.repo.conn:
            cur = self.repo.conn.execute(
                """INSERT INTO items(title, description, severity, quantity, threshold,
                   status, version, external_ref, created_by, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                ("legacy item", "closed before snapshots", "minor", 1, 1, "closed", 7,
                 "LEG-1", "oldsystem", "2020-01-01T00:00:00+00:00",
                 "2020-01-01T00:00:00+00:00"))
            legacy_id = int(cur.lastrowid)
            self.repo.conn.execute(
                """INSERT INTO records(item_id, kind, detail, status, external_ref,
                   created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                (legacy_id, "action", "legacy measure", "closed", "LEG-R1",
                 "oldsystem", "2020-01-01T00:00:00+00:00"))
        # 重启时按现状补齐快照
        self.repo.close()
        self.repo = Repository(self.db_path)
        self.service = Service(self.repo)
        closures = self.service.list_closures(legacy_id, "viewer")
        self.assertEqual(len(closures), 1)
        snap = closures[0]
        self.assertEqual(snap["source"], "backfill")
        self.assertEqual(snap["status"], "active")
        self.assertEqual(snap["item_version"], 7)
        self.assertEqual(snap["record_count"], 1)
        self.assertEqual(snap["data"]["records"][0]["external_ref"], "LEG-R1")
        # 再次重启不重复补齐、不重复记账
        self.repo.close()
        self.repo = Repository(self.db_path)
        self.service = Service(self.repo)
        self.assertEqual(len(self.service.list_closures(legacy_id, "viewer")), 1)
        backfills = [e for e in self.repo.list_audit()
                     if e["action"] == "snapshot_backfill"]
        self.assertEqual(len(backfills), 1)
        self.assertTrue(self.repo.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
