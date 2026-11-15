"""Every rule id the scanner can emit outside dotnet_legacy has an OWASP Web
2025 / Web 2021 mapping, the central fill tags findings from every language
family end to end, and the JSON / SARIF / HTML reports carry the tags."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import owasp_inventory as inv
from core import owasp_web
from core.html_report import render_html
from core.models import Finding, Route, ScanResult
from core.owasp_web import RULES, TITLES, api_surface_for, owasp_for, tag_results
from core.report import write_json
from core.sarif_report import build_sarif
from enumerator import enumerate_target


def unmapped(rules, ids) -> list[str]:
    return sorted(i for i in ids if i not in rules)


def test_every_emitted_rule_id_is_mapped():
    ids = inv.rule_ids()
    assert len(ids) > 200, "inventory regex found suspiciously few ids"
    missing = unmapped(RULES, ids)
    assert not missing, f"rule ids with no OWASP mapping in core/owasp_web.py: {missing}"


def test_no_stale_non_dnl_mapping():
    stale = sorted(i for i in RULES if not i.startswith("DNL-") and i not in inv.rule_ids())
    assert not stale, f"mapped ids that no source emits (typo?): {stale}"


def test_check_names_a_dropped_mapping(monkeypatch):
    victim = "SQLI-001"
    assert victim in RULES
    monkeypatch.setattr(owasp_web, "RULES", {k: v for k, v in RULES.items() if k != victim})
    missing = unmapped(owasp_web.RULES, inv.rule_ids())
    assert missing == [victim], missing
    assert owasp_for(victim) == {}


def test_inventory_regex_accepts_rule_shapes_and_rejects_prose():
    for good in ("AUTH-001", "TF-S3-001", "JC-FIPS-005", "GL-TF-004", "INJ-1"):
        assert inv.ID_SHAPE.match(good), good
    for bad in ("UTF-8x", "Foo-001", "AUTH-", "auth-001"):
        assert not inv.ID_SHAPE.match(bad), bad
    assert inv._LITERAL.search('check_id="ZZZ-999"').group(1) == "ZZZ-999"
    assert "ZZZ-999" not in RULES


def test_every_mapping_is_well_formed():
    for rid, (c25, c21, api, mode) in RULES.items():
        assert c25 in TITLES["2025"] and c21 in TITLES["2021"], rid
        assert api is None or api in TITLES["api2023"], rid
        assert mode in ("always", "api_surface"), rid


def test_representative_mappings():
    assert owasp_for("SQLI-001")["2025"].startswith("A05:2025")
    assert owasp_for("SQLI-001")["2021"].startswith("A03:2021")
    assert owasp_for("SSRF-001")["api2023"].startswith("API7:2023")  # always
    assert owasp_for("IDOR-001") == {"2025": "A01:2025 Broken Access Control",
                                     "2021": "A01:2021 Broken Access Control"}
    assert owasp_for("IDOR-001", api_surface=True)["api2023"].startswith("API1:2023")
    assert owasp_for("TF-S3-001")["2025"].startswith("A01:2025")
    assert owasp_for("JC-001")["2021"].startswith("A02:2021")


# -- api_surface rule ----------------------------------------------------------

def _route(**meta):
    return Route(path="/x", methods=["GET"], handler_name="h", file="a", line=1, meta=meta)


def test_api_surface_prefers_route_meta():
    r = ScanResult(language="java", framework="spring")
    assert api_surface_for(r, Finding("IDOR-001", "low", "t", "d", "a", 1, route=_route(api_surface=True)))
    assert not api_surface_for(ScanResult(language="python", framework="fastapi"),
                               Finding("IDOR-001", "low", "t", "d", "a", 1, route=_route(api_surface=False)))


def test_api_surface_falls_back_to_api_only_frameworks():
    f = Finding("CONFIG-002", "low", "t", "d", "a", 1)
    assert api_surface_for(ScanResult(language="python", framework="fastapi"), f)
    assert api_surface_for(ScanResult(language="go", framework="gin"), f)
    assert not api_surface_for(ScanResult(language="python", framework="flask"), f)
    assert not api_surface_for(ScanResult(language="infra", framework="terraform"), f)


def test_tag_results_never_overwrites_and_is_idempotent():
    keep = {"2025": "A99:2025 custom"}
    a = Finding("DNL-CFG-001", "low", "t", "d", "a", 1, owasp=dict(keep))
    b = Finding("SQLI-001", "high", "t", "d", "a", 2)
    c = Finding("NOT-A-RULE-1", "high", "t", "d", "a", 3)
    res = ScanResult(language="java", framework="spring", findings=[a, b, c])
    tag_results([res])
    tag_results([res])
    assert a.owasp == keep and b.owasp["2025"].startswith("A05:2025") and c.owasp == {}


# -- end to end through the real analyzer path ----------------------------------

def _w(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _run(tmp_path, files, language, framework):
    for rel, text in files.items():
        _w(tmp_path, rel, text)
    results = enumerate_target(tmp_path, force_language=language, force_framework=framework)
    assert results, f"{language}/{framework} produced no ScanResult"
    return results


def _findings(results):
    return [f for r in results for f in r.findings]


FLASK = '''from flask import Flask, request
app = Flask(__name__)

@app.route("/orders/<int:order_id>")
def get_order(order_id):
    return {"id": order_id}

if __name__ == "__main__":
    app.run(debug=True)
'''

FASTAPI = '''from fastapi import FastAPI
app = FastAPI()

@app.get("/orders/{order_id}")
def get_order(order_id: int):
    return {"id": order_id}
'''

SPRING = '''package demo;
import org.springframework.web.bind.annotation.*;

@RestController
public class OrderController {
    @GetMapping("/orders/{orderId}")
    public String get(@PathVariable Long orderId) { return "x"; }
}
'''

EXPRESS = '''const express = require('express');
const app = express();
app.get('/orders/:orderId', (req, res) => { res.json({}); });
app.listen(3000);
'''

GIN = '''package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.GET("/orders/:id", getOrder)
	r.Run()
}

func getOrder(c *gin.Context) { c.JSON(200, gin.H{}) }
'''

SINATRA = '''require 'sinatra'

get '/orders/:id' do
  "order"
end
'''

ASPNET = '''using Microsoft.AspNetCore.Mvc;
namespace Demo {
  [ApiController]
  [Route("api/[controller]")]
  public class OrdersController : ControllerBase {
    [HttpGet("{id}")]
    public IActionResult Get(int id) { return Ok(); }
  }
}
'''

CASES = [
    ("python", "flask", {"app.py": FLASK}, False),
    ("python", "fastapi", {"main.py": FASTAPI}, True),
    ("java", "spring", {"src/main/java/demo/OrderController.java": SPRING}, True),
    ("javascript", "express", {"app.js": EXPRESS}, False),
    ("go", "gin", {"main.go": GIN}, True),
    ("ruby", "sinatra", {"app.rb": SINATRA}, False),
    ("dotnet", "aspnet", {"Controllers/OrdersController.cs": ASPNET}, True),
]


@pytest.mark.parametrize("language,framework,files,api", CASES, ids=[c[1] for c in CASES])
def test_app_findings_are_tagged_end_to_end(tmp_path, language, framework, files, api):
    results = _run(tmp_path, files, language, framework)
    found = _findings(results)
    assert found, f"{framework}: fixture produced no findings"
    untagged = [f.check_id for f in found if not f.owasp]
    assert not untagged, f"{framework}: findings without OWASP tags: {untagged}"
    idor = next(f for f in found if f.check_id == "IDOR-001")
    assert idor.owasp["2025"].startswith("A01:2025")
    assert ("api2023" in idor.owasp) is api, (framework, idor.owasp)


def test_terraform_findings_keep_isr_and_gain_web_tags(tmp_path):
    results = _run(tmp_path, {"main.tf": 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl    = "public-read"\n}\n'},
                   "infra", "terraform")
    found = _findings(results)
    s3 = next(f for f in found if f.check_id == "TF-S3-001")
    assert s3.category == "ISR09:2024 Insecure Access to Resources and Management Components"
    assert s3.owasp["2025"].startswith("A01:2025") and s3.owasp["2021"].startswith("A01:2021")
    assert all(f.owasp for f in found), [f.check_id for f in found if not f.owasp]
    assert all(f.category for f in found)


def test_crypto_findings_keep_isr_and_gain_web_tags(tmp_path):
    java = ('import javax.crypto.Cipher;\nclass C {\n  void f() throws Exception {\n'
            '    Cipher c = Cipher.getInstance("DES");\n  }\n}\n')
    results = _run(tmp_path, {"src/C.java": java}, "crypto", "java")
    found = _findings(results)
    jc = next(f for f in found if f.check_id == "JC-001")
    assert jc.category.startswith("ISR05:2024")
    assert jc.owasp["2025"].startswith("A04:2025") and jc.owasp["2021"].startswith("A02:2021")
    assert all(f.owasp for f in found)


# -- reports --------------------------------------------------------------------

def test_json_sarif_and_html_show_the_tags(tmp_path):
    results = _run(tmp_path, {"main.tf": 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n'},
                   "infra", "terraform")
    out = tmp_path / "r.json"
    write_json(results, out)
    data = json.loads(out.read_text(encoding="utf-8"))
    results_json = data["results"] if isinstance(data, dict) else data
    jf = next(f for f in results_json[0]["findings"] if f["check_id"] == "TF-S3-001")
    assert jf["owasp"]["2025"].startswith("A01:2025") and jf["category"].startswith("ISR09")
    rules = {r["id"]: r for r in build_sarif(results)["runs"][0]["tool"]["driver"]["rules"]}
    tags = set(rules["TF-S3-001"]["properties"]["tags"])
    assert "owasp-2025:A01" in tags and "owasp-2021:A01" in tags
    html = render_html(results, tmp_path)
    assert 'data-owasp="2025:A01' in html and 'class="finding-owasp"' in html
