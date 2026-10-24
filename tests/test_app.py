import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as analyzer


def make_minimal_pe() -> bytes:
    data = bytearray(1024)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    data[0x86:0x88] = (1).to_bytes(2, "little")
    data[0x94:0x96] = (224).to_bytes(2, "little")
    data[0x96:0x98] = (0x0102).to_bytes(2, "little")
    optional = 0x98
    data[optional:optional + 2] = (0x10B).to_bytes(2, "little")
    data[optional + 16:optional + 20] = (0x1000).to_bytes(4, "little")
    data[optional + 28:optional + 32] = (0x400000).to_bytes(4, "little")
    data[optional + 92:optional + 96] = (16).to_bytes(4, "little")
    data[optional + 56:optional + 60] = (0x2000).to_bytes(4, "little")
    data[optional + 104:optional + 108] = (0x1020).to_bytes(4, "little")
    data[optional + 108:optional + 112] = (40).to_bytes(4, "little")
    section = optional + 224
    data[section:section + 8] = b".text\0\0\0"
    data[section + 8:section + 12] = (0x200).to_bytes(4, "little")
    data[section + 12:section + 16] = (0x1000).to_bytes(4, "little")
    data[section + 16:section + 20] = (0x200).to_bytes(4, "little")
    data[section + 20:section + 24] = (0x200).to_bytes(4, "little")
    data[section + 36:section + 40] = (0x60000020).to_bytes(4, "little")
    data[0x200:0x400] = bytes(range(256)) * 2
    data[0x220:0x248] = bytes(40)
    data[0x260:0x268] = bytes(8)
    data[0x270:0x278] = bytes(8)
    data[0x220:0x224] = (0x1060).to_bytes(4, "little")
    data[0x22C:0x230] = (0x1050).to_bytes(4, "little")
    data[0x230:0x234] = (0x1070).to_bytes(4, "little")
    data[0x250:0x25D] = b"KERNEL32.dll\0"
    data[0x260:0x264] = (0x1080).to_bytes(4, "little")
    data[0x270:0x274] = (0x1080).to_bytes(4, "little")
    data[0x280:0x282] = (0).to_bytes(2, "little")
    data[0x282:0x295] = b"CreateRemoteThread\0"
    return bytes(data)


class AnalyzeUploadTests(unittest.TestCase):
    def setUp(self):
        analyzer.app.config.update(TESTING=True, MAX_CONTENT_LENGTH=analyzer.MAX_REQUEST_SIZE)
        self.client = analyzer.app.test_client()

    def upload(self, filename, contents):
        return self.client.post(
            "/api/analyze",
            data={"file": (io.BytesIO(contents), filename)},
            content_type="multipart/form-data",
        )

    def test_valid_pe_returns_static_metadata(self):
        response = self.upload("sample.exe", make_minimal_pe())
        self.assertEqual(response.status_code, 200)
        report = response.get_json()
        self.assertEqual(report["architecture"], "x86 (i386)")
        self.assertEqual(report["entry_point"], {"rva": 0x1000, "va": 0x401000})
        self.assertEqual(report["section_count"], 1)
        self.assertEqual(report["sections"][0]["name"], ".text")
        self.assertGreater(report["sections"][0]["entropy"], 0)
        self.assertEqual(report["imports"][0]["dll"], "KERNEL32.dll")
        self.assertEqual(report["imports"][0]["functions"][0]["name"], "CreateRemoteThread")
        self.assertEqual(report["file_size"], len(make_minimal_pe()))
        import_finding = next(item for item in report["findings"] if item["rule_id"] == "process_injection")
        entropy_finding = next(item for item in report["findings"] if item["rule_id"] == "high_entropy_sections")
        self.assertTrue(import_finding["triggered"])
        self.assertIn("CreateRemoteThread", import_finding["explanation"])
        self.assertTrue(entropy_finding["triggered"])
        self.assertEqual(report["severity"], "medium")
        self.assertEqual(report["risk"], report["severity"])

    def test_flags_unusual_permissions_and_entry_point(self):
        data = bytearray(make_minimal_pe())
        section_offset = 0x98 + 224
        data[section_offset + 36:section_offset + 40] = (0xE0000020).to_bytes(4, "little")
        data[0x98 + 16:0x98 + 20] = (0x5000).to_bytes(4, "little")
        response = self.upload("odd.exe", bytes(data))
        self.assertEqual(response.status_code, 200)
        report = response.get_json()
        triggered = {item["rule_id"] for item in report["findings"] if item["triggered"]}
        self.assertIn("writable_executable_section", triggered)
        self.assertIn("entry_point_location", triggered)

    def test_severity_thresholds_are_explainable(self):
        self.assertEqual(analyzer._severity(0), "low")
        self.assertEqual(analyzer._severity(24), "low")
        self.assertEqual(analyzer._severity(25), "medium")
        self.assertEqual(analyzer._severity(50), "high")
        self.assertEqual(analyzer._severity(75), "critical")

    def test_llm_summary_is_optional_and_disabled_by_default(self):
        with patch.dict(analyzer.app.config, {"LLM_API_KEY": ""}):
            response = self.client.post("/api/summarize", json={"report": {}})
        self.assertEqual(response.status_code, 503)
        self.assertIn("error", response.get_json())

    def test_api_status_reports_optional_summary_configuration(self):
        with patch.dict(analyzer.app.config, {"LLM_API_KEY": ""}):
            response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["llm_summary_enabled"])

    def test_llm_summary_rejects_malformed_json_with_json_error(self):
        with patch.dict(analyzer.app.config, {"LLM_API_KEY": "test-key"}):
            response = self.client.post(
                "/api/summarize",
                data="{",
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_llm_summary_receives_only_extracted_evidence(self):
        report = self.upload("private-name.exe", make_minimal_pe()).get_json()
        fake_response = io.BytesIO(json.dumps({
            "choices": [{"message": {"content": "Evidence summary. Heuristics do not prove malware."}}]
        }).encode())
        config = {
            "LLM_API_KEY": "test-key",
            "LLM_API_URL": "https://llm.example.test/v1/chat/completions",
        }
        with patch.dict(analyzer.app.config, config), patch.object(
            analyzer.urllib.request, "urlopen", return_value=fake_response
        ) as urlopen:
            response = self.client.post("/api/summarize", json={"report": report})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Heuristics do not prove malware", response.get_json()["summary"])
        request_payload = json.loads(urlopen.call_args.args[0].data)
        evidence = json.loads(request_payload["messages"][1]["content"])
        self.assertNotIn("file_name", evidence)
        self.assertNotIn("sha256", evidence)
        self.assertTrue(evidence["triggered_rules"])

    def test_upload_tempfile_is_removed_after_analysis(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(analyzer.app.config, {"UPLOAD_TEMP_DIR": temp_dir}):
                response = self.upload("sample.exe", make_minimal_pe())
            self.assertEqual(response.status_code, 200)
            self.assertEqual(list(Path(temp_dir).iterdir()), [])

    def test_rejects_missing_file(self):
        response = self.client.post("/api/analyze", data={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_unknown_route_returns_json_error(self):
        response = self.client.get("/missing-route")
        self.assertEqual(response.status_code, 404)
        self.assertIn("error", response.get_json())

    def test_request_over_limit_returns_json_error(self):
        response = self.client.post(
            "/api/analyze",
            data=b"x",
            content_type="multipart/form-data",
            environ_overrides={"CONTENT_LENGTH": str(analyzer.MAX_REQUEST_SIZE + 1)},
        )
        self.assertEqual(response.status_code, 413)
        self.assertIn("error", response.get_json())

    def test_rejects_unsupported_extension(self):
        response = self.upload("sample.sys", make_minimal_pe())
        self.assertEqual(response.status_code, 415)
        self.assertIn("error", response.get_json())

    def test_rejects_invalid_pe(self):
        response = self.upload("not-pe.dll", b"not a PE file" + bytes(100))
        self.assertEqual(response.status_code, 422)
        self.assertIn("error", response.get_json())

    def test_rejects_file_over_limit(self):
        oversized = b"x" * (analyzer.MAX_FILE_SIZE + 1)
        response = self.upload("large.exe", oversized)
        self.assertEqual(response.status_code, 413)
        self.assertIn("error", response.get_json())

    def test_over_limit_upload_also_cleans_temporary_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(analyzer.app.config, {"UPLOAD_TEMP_DIR": temp_dir}):
                response = self.upload("large.exe", b"x" * (analyzer.MAX_FILE_SIZE + 1))
            self.assertEqual(response.status_code, 413)
            self.assertEqual(list(Path(temp_dir).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
