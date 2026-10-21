import base64
import io
import json
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

from app import TrustVault, connect, password_hash, seed_users


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.db_path = str(root / "app.sqlite3")
        seed_users(self.db_path)
        db = connect(self.db_path)
        try:
            db.execute("INSERT INTO users(id,email,name,role,password_hash) VALUES(?,?,?,?,?)",
                       (str(uuid.uuid4()), "owner2@trustvault.test", "Other Owner", "owner",
                        password_hash("OtherOwner!42")))
            db.commit()
        finally:
            db.close()
        self.app = TrustVault(self.db_path, str(root / "files"), "T" * 48)
        self.owner = self.login("owner@trustvault.test", "OwnerDemo!42")
        self.viewer = self.login("viewer@trustvault.test", "ViewerDemo!42")
        self.admin = self.login("admin@trustvault.test", "AdminDemo!42")

    def tearDown(self):
        self.temp.cleanup()

    def request(self, method, path, session=None, body=None):
        from urllib.parse import urlsplit
        parsed_path = urlsplit(path)
        raw = json.dumps(body).encode() if body is not None else b""
        environ = {
            "REQUEST_METHOD": method, "PATH_INFO": parsed_path.path, "QUERY_STRING": parsed_path.query,
            "CONTENT_LENGTH": str(len(raw)), "CONTENT_TYPE": "application/json",
            "wsgi.input": io.BytesIO(raw),
        }
        if session:
            environ["HTTP_COOKIE"] = f"tv_session={session['cookie']}"
            if method in ("POST", "PATCH", "DELETE"):
                environ["HTTP_X_CSRF_TOKEN"] = session["csrf"]
        captured = {}

        def start_response(status, headers):
            captured["status"] = int(status.split()[0])
            captured["headers"] = dict(headers)

        output = b"".join(self.app(environ, start_response))
        content_type = captured["headers"].get("Content-Type", "")
        parsed = json.loads(output) if output and "application/json" in content_type else output
        return captured["status"], parsed, captured["headers"]

    def login(self, email, password):
        status, body, headers = self.request("POST", "/api/login", body={"email": email, "password": password})
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"].split(";", 1)[0].split("=", 1)[1]
        return {"cookie": cookie, "csrf": body["csrf"]}

    def upload(self, session=None, name="report.txt"):
        status, body, _ = self.request("POST", "/api/documents", session or self.owner, {
            "name": name, "category": "Finance",
            "content_base64": base64.b64encode(b"confidential payroll").decode(),
        })
        self.assertEqual(status, 201, body)
        return body["document"]["id"]

    def test_ungranted_user_cannot_list_read_download_edit_or_delete_document(self):
        doc_id = self.upload()
        self.assertEqual(self.request("GET", "/api/documents", self.viewer)[1]["documents"], [])
        self.assertEqual(self.request("GET", f"/api/documents/{doc_id}", self.viewer)[0], 404)
        self.assertEqual(self.request("GET", f"/api/documents/{doc_id}/download", self.viewer)[0], 404)
        self.assertEqual(self.request("PATCH", f"/api/documents/{doc_id}", self.viewer,
                                      {"name": "stolen.txt"})[0], 404)
        self.assertEqual(self.request("DELETE", f"/api/documents/{doc_id}", self.viewer)[0], 404)
        self.assertEqual(self.request("GET", f"/api/documents/{doc_id}", self.admin)[0], 404)
        self.assertEqual(self.request("GET", f"/api/documents/{doc_id}/download", self.admin)[0], 404)

    def test_grant_and_immediate_revocation_apply_on_next_read_and_download(self):
        doc_id = self.upload()
        self.assertEqual(self.request("POST", f"/api/documents/{doc_id}/grants", self.owner,
                                      {"email": "viewer@trustvault.test", "permission": "read"})[0], 200)
        self.assertEqual(self.request("GET", f"/api/documents/{doc_id}/download", self.viewer)[0], 200)
        self.assertEqual(self.request("DELETE", f"/api/documents/{doc_id}/grants", self.owner,
                                      {"email": "viewer@trustvault.test"})[0], 200)
        self.assertEqual(self.request("GET", f"/api/documents/{doc_id}", self.viewer)[0], 404)
        self.assertEqual(self.request("GET", f"/api/documents/{doc_id}/download", self.viewer)[0], 404)

    def test_edit_grant_can_change_metadata_but_not_delete_or_manage_grants(self):
        doc_id = self.upload()
        self.request("POST", f"/api/documents/{doc_id}/grants", self.owner,
                     {"email": "viewer@trustvault.test", "permission": "edit"})
        self.assertEqual(self.request("PATCH", f"/api/documents/{doc_id}", self.viewer,
                                      {"name": "changed.txt"})[0], 200)
        self.assertEqual(self.request("DELETE", f"/api/documents/{doc_id}", self.viewer)[0], 404)
        self.assertEqual(self.request("POST", f"/api/documents/{doc_id}/grants", self.viewer,
                                      {"email": "admin@trustvault.test"})[0], 404)

    def test_owner_isolation_and_viewer_cannot_upload(self):
        doc_id = self.upload()
        self.assertEqual(self.request("POST", "/api/documents", self.viewer, {
            "name": "bad.txt", "category": "General", "content_base64": base64.b64encode(b"no").decode()
        })[0], 403)
        second_owner = self.login("owner2@trustvault.test", "OtherOwner!42")
        self.assertEqual(self.request("DELETE", f"/api/documents/{doc_id}", second_owner)[0], 404)

    def test_invalid_file_types_and_mismatched_signatures_are_rejected(self):
        status, _, _ = self.request("POST", "/api/documents", self.owner, {
            "name": "payload.exe", "category": "General",
            "content_base64": base64.b64encode(b"binary").decode(),
        })
        self.assertEqual(status, 415)
        status, _, _ = self.request("POST", "/api/documents", self.owner, {
            "name": "fake.pdf", "category": "General",
            "content_base64": base64.b64encode(b"not a PDF").decode(),
        })
        self.assertEqual(status, 415)

    def test_denied_attempts_are_in_admin_audit_and_chain_verifies(self):
        doc_id = self.upload()
        self.request("GET", f"/api/documents/{doc_id}/download", self.viewer)
        status, body, _ = self.request("GET", "/api/audit", self.admin)
        self.assertEqual(status, 200)
        self.assertTrue(body["chain_valid"])
        self.assertTrue(any(event["action"] == "download_denied" and event["actor_email"] == "viewer@trustvault.test"
                            for event in body["entries"]))
        self.assertEqual(self.request("GET", "/api/audit", self.viewer)[0], 403)
        _, updated, _ = self.request("GET", "/api/audit", self.admin)
        self.assertTrue(any(event["action"] == "audit_access_denied" and event["actor_email"] == "viewer@trustvault.test"
                            for event in updated["entries"]))

    def test_csrf_is_required_for_state_changes(self):
        doc_id = self.upload()
        session = {"cookie": self.owner["cookie"], "csrf": "incorrect"}
        self.assertEqual(self.request("DELETE", f"/api/documents/{doc_id}", session)[0], 403)

    def test_document_search_filters_are_applied_server_side(self):
        self.upload(name="Quarterly-report.txt")
        self.assertEqual(len(self.request("GET", "/api/documents?name=Quarterly", self.owner)[1]["documents"]), 1)
        self.assertEqual(len(self.request("GET", "/api/documents?name=absent", self.owner)[1]["documents"]), 0)
        self.assertEqual(len(self.request("GET", "/api/documents?owner=owner%40trustvault.test", self.owner)[1]["documents"]), 1)
        self.assertEqual(len(self.request("GET", "/api/documents?category=Finance", self.owner)[1]["documents"]), 1)
        self.assertEqual(len(self.request("GET", "/api/documents?after=2099-01-01", self.owner)[1]["documents"]), 0)

    def test_audit_chain_detects_tampering_and_ordinary_updates_are_blocked(self):
        self.upload()
        db = connect(self.db_path)
        entry_id = db.execute("SELECT id FROM audit ORDER BY id LIMIT 1").fetchone()["id"]
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE audit SET details='{\"tampered\":true}' WHERE id=?", (entry_id,))
        db.rollback()
        db.execute("DROP TRIGGER audit_no_update")
        db.execute("UPDATE audit SET details='{\"tampered\":true}' WHERE id=?", (entry_id,))
        db.commit()
        db.close()
        status, result, _ = self.request("GET", "/api/audit/verify", self.admin)
        self.assertEqual(status, 200)
        self.assertFalse(result["valid"])


if __name__ == "__main__":
    unittest.main()
