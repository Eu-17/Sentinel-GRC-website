import json
import os
import struct
import unittest
from unittest.mock import patch

from app.catalog import CAPTURES, RULES, STATIC
from app.services import pcap_parser as parser
from app.services.pipeline import build_report, qualifying_connections
from app.services.soc_triage import brief


class AnalysisTests(unittest.TestCase):
    def test_fixtures_match_real_packet_markers(self):
        expected = {"ransomware": (12, 25), "sqli": (3, 25), "ssh": (8, 15)}
        for rule in RULES:
            with self.subTest(sample=rule["sample"]):
                data = (CAPTURES / rule["file"]).read_bytes()
                offset = 24
                matched = []
                while offset < len(data):
                    _, _, size, _ = struct.unpack_from("<IIII", data, offset)
                    packet = data[offset + 16:offset + 16 + size]
                    offset += 16 + size
                    port = int.from_bytes(packet[36:38], "big")
                    has_marker = { "ransomware": b"GET /gate.php" in packet and b"MSIE" in packet,
                        "sqli": b"label=SELECT" in packet, "ssh": port == 22 and packet[47] == 2}
                    if has_marker[rule["sample"]]:
                        matched.append(packet)
                count, risk = expected[rule["sample"]]
                self.assertEqual(len(matched), count)
                with patch.object(parser, "tshark_binary", return_value=None), patch.dict(os.environ, REQUIRE_TSHARK="0"):
                    report = parser.analyze_sample(rule["sample"])
                finding, = [f for f in report["findings"] if f["count"]]
                self.assertEqual((finding["count"], finding["risk"]["score"]), (count, risk))
                self.assertEqual(report["frames"], count + 4)

    def test_offline_and_server_fixture_data_agree(self):
        script = (STATIC / "demo-data.js").read_text()
        self.assertEqual(json.loads(script.split(" = ", 1)[1].rstrip(";\n")), parser.FIXTURES)

    def test_no_matches_keep_baseline(self):
        report = build_report("clean", "TShark", 10, {r["id"]: [] for r in RULES})
        for row in report["findings"]:
            self.assertEqual(row["risk"]["score"], row["risk"]["baseline"])
            self.assertIsNone(row["risk"]["review"])
            self.assertFalse(row["firewall"])
            self.assertTrue(all(c["state"] == "PASS" for c in row["risk"]["controls"]))

    def test_ssh_deduplicates_retransmits_and_separates_hosts_and_time(self):
        rule = RULES[-1]
        flows = [{"frame": i + 1, "port": 1000 + i, "time": i, "source": "192.0.2.1",
                  "destination": "192.0.2.10"} for i in range(6)]
        self.assertEqual(len(qualifying_connections(rule, flows)), 6)
        self.assertFalse(qualifying_connections(rule, [{**f, "port": 5000} for f in flows]))
        self.assertFalse(qualifying_connections(rule, [{**f, "time": f["time"] * 61} for f in flows]))
        self.assertFalse(qualifying_connections(rule, [*flows[:5], {**flows[5], "source": "192.0.2.2"}]))

    def test_direction_of_proposals(self):
        for demo in parser.FIXTURES.values():
            row, = [f for f in demo["report"]["findings"] if f["count"]]
            flow = row["flows"][0]
            part = "OUTPUT -d " + flow["destination"] if row["id"].endswith("101") else "INPUT -s " + flow["source"]
            self.assertEqual(row["firewall"], [f"iptables -A {part} -j DROP"])

    def test_unavailable_model_keeps_deterministic_brief(self):
        row = parser.FIXTURES["ransomware"]["report"]["findings"][0]
        with patch.dict(os.environ, ENABLE_OLLAMA="1"), patch("http.client.HTTPConnection.request", side_effect=OSError):
            result = brief(RULES[0], row["flows"], row["risk"])
        self.assertEqual(result["source"], "Rule-based")

    @unittest.skipUnless(parser.tshark_binary(), "requires installed TShark")
    def test_live_dissections_match_fixtures(self):
        for rule in RULES:
            sample = rule["sample"]
            with self.subTest(sample=sample), patch.dict(os.environ, ENABLE_OLLAMA="0"):
                report = parser.analyze_sample(sample)
                self.assertEqual(report["engine"], "TShark")
                overview = report.pop("overview")
                self.assertEqual(sum(row["frames"] for row in overview["protocols"]), report["frames"])
                self.assertTrue(any(rule["id"] in row["rule_ids"] for row in overview["observations"]))
                self.assertEqual({**report, "engine": "Fixture replay"}, parser.FIXTURES[sample]["report"])
