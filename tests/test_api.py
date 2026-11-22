import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main
from app.catalog import CAPTURES, MAX_BYTES
from app.services import pcap_parser


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)
        main.recent_jobs.clear()
        self.addCleanup(self.client.close)

    def test_dashboard_assets_and_schema(self):
        for path in ["/", "/style.css", "/app.js", "/demo-data.js", "/mark.svg", "/healthz", "/openapi.json"]:
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)
        schema = self.client.get("/openapi.json").json()
        self.assertIn("Analysis", schema["components"]["schemas"])
        self.assertIn("/api/v1/upload", schema["paths"])
        self.assertEqual(self.client.get("/api/v1/config").json()["max_upload_bytes"], MAX_BYTES)
        for path in ["/docs", "/api.html", "/requirements.txt"]:
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)

    def test_headers_and_origin(self):
        headers = self.client.get("/").headers
        self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertEqual(self.client.post("/api/v1/analyze-pcap/ssh", headers={"Origin": "https://elsewhere.invalid"}).status_code, 403)

    def test_sample_and_unknown(self):
        self.assertEqual(self.client.post("/api/v1/analyze-pcap/unknown").status_code, 404)
        payload = self.client.post("/api/v1/analyze-pcap/ssh").json()
        self.assertEqual(payload["findings"][-1]["count"], 8)

    def test_public_upload_default(self):
        with patch.dict(os.environ, ENABLE_UPLOADS="0"):
            self.assertFalse(self.client.get("/api/v1/config").json()["uploads"])
            self.assertEqual(self.client.post("/api/v1/upload", content=b"test").status_code, 403)

    def test_input_limits_and_type(self):
        limit = 1024**2
        with patch.object(main, "uploads_enabled", return_value=True), patch.object(main, "MAX_BYTES", limit):
            for data, kind, expected in [(b"x", "text/plain", 415), (b"no magic", "application/octet-stream", 415),
                    (b"x" * limit, "application/octet-stream", 415),
                    (b"x" * (limit + 1), "application/octet-stream", 413)]:
                with self.subTest(expected=expected):
                    response = self.client.post("/api/v1/upload", content=data, headers={"Content-Type": kind})
                    self.assertEqual(response.status_code, expected)
            def chunks():
                for _ in range(3):
                    yield b"x" * (limit // 2)
            response = self.client.post("/api/v1/upload", content=chunks(), headers={"Content-Type": "application/octet-stream"})
            self.assertEqual(response.status_code, 413)

    def test_parser_failures_clean_up_private_files(self):
        seen = []
        def fail(path, name):
            seen.append(path)
            self.assertTrue(path.exists())
            raise pcap_parser.InvalidCapture("Damaged capture.")
        with patch.object(main, "uploads_enabled", return_value=True), patch.object(pcap_parser, "analyze", side_effect=fail):
            res = self.client.post("/api/v1/upload", content=bytes.fromhex("d4c3b2a1"),
                                   headers={"content-type": "application/octet-stream"})
        self.assertEqual(res.status_code, 422)
        self.assertFalse(seen[0].parent.exists())

    def test_throttle_and_missing_required_parser(self):
        with patch.object(main, "active_jobs", 2):
            res = self.client.post("/api/v1/analyze-pcap/sqli")
            self.assertEqual(res.status_code, 429)
            self.assertIn("retry-after", res.headers)
        with patch.dict(os.environ, REQUIRE_TSHARK="1"), patch.object(pcap_parser, "tshark_binary", return_value=None):
            self.assertEqual(self.client.get("/healthz").status_code, 503)
            self.assertEqual(self.client.post("/api/v1/analyze-pcap/sqli").status_code, 503)

    @unittest.skipUnless(pcap_parser.tshark_binary(), "requires installed TShark")
    def test_rule_changes_drive_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "rules.json")
            with (patch.dict(os.environ, RULES_FILE=str(path)),
                  TestClient(main.app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as client):
                url = "/api/v1/rules"
                initial = client.get(url).json()
                self.assertTrue(initial["editable"])
                custom_url = url + "/CUSTOM-TEST"
                rule = {"id": "CUSTOM-TEST", "name": "SSH port traffic", "filter": "tcp.dstport == 22"}
                self.assertFalse(self.client.get(url).json()["editable"])
                self.assertEqual(self.client.put(custom_url, json=rule).status_code, 403)
                self.assertEqual(client.delete(url + "/NET-SOC-101", headers={"Origin": "https://elsewhere.invalid"}).status_code, 403)
                invalid = client.put(custom_url, json={**rule, "filter": "("})
                self.assertEqual(invalid.status_code, 422)
                self.assertFalse(path.exists())
                self.assertEqual(client.put(custom_url, json=rule).status_code, 200)
                analysis_url = "/api/v1/analyze-pcap/ssh"
                report = client.post(analysis_url).json()
                self.assertEqual(report["findings"][-1]["id"], rule["id"])
                self.assertEqual(report["findings"][-1]["count"], 8)
                self.assertEqual(client.put(custom_url, json={**rule, "filter": "tcp.dstport == 1"}).status_code, 200)
                self.assertEqual(client.post(analysis_url).json()["findings"][-1]["count"], 0)
                for row in client.get(url).json()["rules"]:
                    self.assertEqual(client.delete(url + "/" + row["id"]).status_code, 200)
                self.assertEqual(client.post(analysis_url).json()["findings"], [])

    @unittest.skipUnless(pcap_parser.tshark_binary(), "requires installed TShark")
    def test_local_capture_library_persists_and_reanalyzes_uploads(self):
        source = (CAPTURES / "03_ssh_burst.pcap").read_bytes()
        headers = {"Content-Type": "application/octet-stream"}
        with tempfile.TemporaryDirectory() as directory:
            library = Path(directory, "captures")
            with (patch.dict(os.environ, ENABLE_UPLOADS="1", CAPTURE_LIBRARY_DIR=os.path.relpath(library),
                             RULES_FILE=str(Path(directory, "rules.json"))),
                  TestClient(main.app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as client):
                self.assertEqual(self.client.get("/api/v1/captures").json(), {"enabled": False, "captures": []})
                url = "/api/v1/upload"
                response = client.post(url, params={"name": "broken.pcap"}, headers=headers, content=b"bad capture")
                self.assertEqual(response.status_code, 415)
                self.assertFalse(library.exists())

                response = client.post(url, params={"name": "../My capture.pcap"}, headers=headers, content=source)
                self.assertEqual(response.status_code, 200)
                saved = response.json()["saved_capture"]
                self.assertEqual(saved["name"], "My capture.pcap")
                self.assertEqual(saved["size"], len(source))
                self.assertEqual(client.get("/api/v1/captures").json()["captures"], [saved])
                response = client.post(url, params={"name": "Retry.pcap"}, headers=headers, content=source)
                self.assertEqual(response.json()["saved_capture"], saved)
                self.assertEqual(client.get("/api/v1/captures").json()["captures"], [saved])

                rule = {"id": "QA-TRAFFIC", "name": "SSH port traffic", "filter": "tcp.dstport == 22"}
                self.assertEqual(client.put("/api/v1/rules/QA-TRAFFIC", json=rule).status_code, 200)
                analysis_url = f"/api/v1/captures/{saved['id']}/analyze"
                self.assertEqual(self.client.post(analysis_url).status_code, 403)
                report = client.post(analysis_url).json()
                self.assertEqual(report["saved_capture"], saved)
                self.assertEqual(report["findings"][-1]["id"], "QA-TRAFFIC")
                self.assertEqual(report["findings"][-1]["count"], 8)

    @unittest.skipUnless(pcap_parser.tshark_binary(), "requires installed TShark")
    def test_live_upload(self):
        data = (CAPTURES / "02_sql_indicators.pcap").read_bytes()
        with patch.dict(os.environ, ENABLE_UPLOADS="1"):
            response = self.client.post("/api/v1/upload", content=data, headers={"content-type": "application/octet-stream"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["findings"][1]["count"], 3)
        overview = response.json()["overview"]
        requests = next(item for item in overview["observations"] if item["title"] == "Plaintext HTTP requests")
        self.assertTrue(requests["frames"])
        self.assertIn("http.request", requests["suggested_filter"])
        self.assertEqual(requests["controls"][0][0], "A.8.20")
