from core.owasp_web import RULES, TITLES, owasp_for
from checks.dnl.findings import dnl_finding


def test_every_dnl_rule_has_2025_and_2021_tags():
    for rid, (c25, c21, api, mode) in RULES.items():
        assert rid.startswith("DNL-")
        assert c25 in TITLES["2025"] and c21 in TITLES["2021"]
        assert api is None or api in TITLES["api2023"]
        assert mode in ("always", "api_surface")


def test_titles_have_ten_entries_per_list():
    assert [len(TITLES[k]) for k in ("2025", "2021", "api2023")] == [10, 10, 10]


def test_api_tag_only_on_api_surface():
    assert owasp_for("DNL-CFG-001") == {"2025": "A02:2025 Security Misconfiguration",
                                        "2021": "A05:2021 Security Misconfiguration"}
    assert owasp_for("DNL-CFG-001", api_surface=True)["api2023"] == "API8:2023 Security Misconfiguration"
    assert owasp_for("DNL-INV-001")["api2023"] == "API9:2023 Improper Inventory Management"


def test_unknown_id_has_no_tags():
    assert owasp_for("TF-S3-001") == {}


def test_dnl_finding_sets_owasp_and_leaves_isr_category_alone():
    f = dnl_finding("DNL-AUTHZ-001", "high", "t", "d", "a.cs", 3, api_surface=True)
    assert f.owasp["api2023"].startswith("API5:2023") and f.category is None


def test_rule_table_spot_checks():
    assert RULES["DNL-CFG-007"] == ("A02", "A05", "API8", "api_surface")
    assert RULES["DNL-XSS-002"][2] is None
    assert RULES["DNL-SESS-005"][:2] == ("A04", "A02")
    assert RULES["DNL-INV-001"][3] == "always"
    assert "DNL-AUTHZ-004" in RULES and "DNL-CSRF-001" in RULES
