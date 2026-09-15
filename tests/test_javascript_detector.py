import json

from languages.javascript.detector import detect_frameworks


def test_hono_detected_via_package_json_dependency(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"hono": "^4.0.0", "@hono/node-server": "^1.0.0"}}),
        encoding="utf-8",
    )
    assert detect_frameworks(tmp_path) == ["hono"]


def test_hono_detected_via_import_fallback_with_no_package_json(tmp_path):
    (tmp_path / "server.js").write_text("import { Hono } from 'hono'\n", encoding="utf-8")
    assert detect_frameworks(tmp_path) == ["hono"]
