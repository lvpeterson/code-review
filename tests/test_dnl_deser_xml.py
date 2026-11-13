"""Insecure deserialization and XXE (DNL-DESER-001..003, DNL-XXE-001..002)."""
import re
from pathlib import Path

import pytest

from checks.dnl import project, routes, rules_deser_xml, rules_taint
from core.owasp_web import RULES
import languages.dotnet_legacy.analyzers as analyzers

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy" / "taint_app"
DX = FX / "TaintCs" / "DeserXml"


@pytest.fixture(scope="module")
def model(roslyn_helper):
    project._CACHE.clear()
    return project.prepare(FX, False)


@pytest.fixture(scope="module")
def refs(model):
    return routes.discover_mvc_webapi(model) + routes.discover_webforms(model) + routes.discover_wcf(model)


@pytest.fixture(scope="module")
def taint(model, refs):
    return rules_taint.check(model, refs)


@pytest.fixture(scope="module")
def config(model, refs):
    return rules_deser_xml.check(model, refs)


@pytest.fixture(scope="module")
def both(taint, config):
    return taint + config


def span(path: Path, method: str) -> tuple[int, int]:
    """(first, last) line of a method body found by `Name(` in a fixture file."""
    lines = path.read_text(encoding="utf-8").splitlines()
    start = next(i for i, ln in enumerate(lines) if re.search(rf"\b{method}\(", ln) and "(" in ln and ";" not in ln)
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == "}" and
               len(lines[i]) - len(lines[i].lstrip()) == indent)
    return start + 1, end + 1


def at(findings, rule, fname, method):
    path = DX / fname if (DX / fname).exists() else FX / "Legacy40" / fname
    lo, hi = span(path, method)
    return [f for f in findings if f.check_id == rule and f.file.endswith(fname) and lo <= f.line <= hi]


# -- rule metadata --------------------------------------------------------------------

def test_rules_registered():
    for rid in ("DNL-DESER-001", "DNL-DESER-002", "DNL-DESER-003", "DNL-XXE-001", "DNL-XXE-002"):
        assert rid in RULES
    assert RULES["DNL-DESER-001"][:2] == ("A08", "A08")
    assert RULES["DNL-XXE-001"] == ("A02", "A05", "API8", "api_surface")


def test_taint_kinds_mapped():
    assert rules_taint.RULE_FOR_KIND["deser"] == "DNL-DESER-001"
    assert rules_taint.RULE_FOR_KIND["xxe"] == "DNL-XXE-001"


# -- DESER-001: proven (taint) vs REVIEW (config shape) -----------------------------------

@pytest.mark.parametrize("method", ["FromBody", "Ndc", "ViewStateBlob"])
def test_deser001_proven_from_taint(taint, config, method):
    t = at(taint, "DNL-DESER-001", "FormatterController.cs", method)
    assert len(t) == 1 and t[0].severity == "high" and t[0].confidence is None
    assert t[0].route is not None and t[0].title == "Insecure deserialization"
    # the config-shape pass does not repeat a sink that already has a taint finding
    assert not at(config, "DNL-DESER-001", "FormatterController.cs", method)


def test_deser001_review_when_input_not_proven(taint, config):
    c = at(config, "DNL-DESER-001", "FormatterController.cs", "FromFile")
    assert len(c) == 1 and c[0].severity == "medium" and c[0].confidence == "REVIEW"
    assert not at(taint, "DNL-DESER-001", "FormatterController.cs", "FromFile")


def test_deser001_data_contract_serializer_not_listed(both):
    assert not at(both, "DNL-DESER-001", "FormatterController.cs", "Contract")


# -- DESER-002: Json.NET TypeNameHandling ------------------------------------------------

def test_deser002_static_settings_used_from_another_type(config):
    h = at(config, "DNL-DESER-002", "JsonCfg.cs", "ParseUnsafe")
    assert len(h) == 1 and h[0].severity == "high"
    assert len(at(config, "DNL-DESER-002", "JsonCfg.cs", "Serializer")) == 1
    assert not at(config, "DNL-DESER-002", "JsonCfg.cs", "ParseSafe")
    assert not at(config, "DNL-DESER-002", "JsonCfg.cs", "ParseDefault")


def test_deser002_review_focus4_value_assigned_in_another_method(config):
    assert len(at(config, "DNL-DESER-002", "JsonCfg.cs", "Read")) == 1
    # the setting sites that have a call are not reported on their own
    assert not at(config, "DNL-DESER-002", "JsonCfg.cs", "Init")
    all_lines = {f.line for f in config if f.check_id == "DNL-DESER-002" and f.file.endswith("JsonCfg.cs")}
    src = (DX / "JsonCfg.cs").read_text(encoding="utf-8").splitlines()
    for i, ln in enumerate(src, 1):
        if "TypeNameHandling.All" in ln or "TypeNameHandling.Auto;" in ln:
            assert i not in all_lines


def test_deser002_setting_without_call_is_reported_at_setting(config):
    h = at(config, "DNL-DESER-002", "JsonCfg.cs", "Build")
    assert len(h) == 1


def test_deser002_inline_serializer_and_attribute(config):
    assert len(at(config, "DNL-DESER-002", "JsonCfg.cs", "Make")) == 1
    assert not at(config, "DNL-DESER-002", "JsonCfg.cs", "MakeNone")
    attr = [f for f in config if f.check_id == "DNL-DESER-002" and f.file.endswith("JsonCfg.cs")
            and "JsonProperty" in f.description]
    assert len(attr) == 1
    src = (DX / "JsonCfg.cs").read_text(encoding="utf-8").splitlines()
    assert "TypeNameHandling.Auto" in src[attr[0].line - 1]


def test_deser002_total_in_json_fixture(config):
    # ParseUnsafe, Serializer, Read, Build, Make, Envelope.Payload attribute
    assert len([f for f in config if f.check_id == "DNL-DESER-002" and f.file.endswith("JsonCfg.cs")]) == 6


# -- DESER-003 -----------------------------------------------------------------------------

def test_deser003_simple_type_resolver(config):
    h = at(config, "DNL-DESER-003", "JsSerializers.cs", "WithResolver")
    assert len(h) == 1 and h[0].severity == "high"
    assert not at(config, "DNL-DESER-003", "JsSerializers.cs", "Plain")
    assert len([f for f in config if f.check_id == "DNL-DESER-003"]) == 1


# -- XXE-001: proven (taint) vs configuration shape --------------------------------------

@pytest.mark.parametrize("method", ["ResolverOn", "ResolverLate", "ParseSettings", "TextReaderOpen"])
def test_xxe001_proven(taint, config, method):
    t = at(taint, "DNL-XXE-001", "XmlController.cs", method)
    assert len(t) == 1 and t[0].severity == "high" and t[0].confidence is None
    assert t[0].route is not None and t[0].title == "XML external entity (XXE)"
    assert not at(config, "DNL-XXE-001", "XmlController.cs", method)


@pytest.mark.parametrize("method", ["ResolverOff", "ModernDefault", "ProhibitSettings", "ParseButNoResolver",
                                    "TextReaderClosed", "TextReaderLegacyFlag", "XpathPlain"])
def test_xxe001_safe_shapes_not_reported(both, method):
    assert not at(both, "DNL-XXE-001", "XmlController.cs", method)


def test_xxe001_config_shape_medium(config):
    c = at(config, "DNL-XXE-001", "XmlController.cs", "Config")
    assert len(c) == 1 and c[0].severity == "medium" and c[0].confidence is None
    assert c[0].route is not None      # inside a route handler's own method


def test_xxe001_xml_text_reader_default(both):
    assert len(at(both, "DNL-XXE-001", "XmlController.cs", "TextReaderPlain")) == 1


def test_xxe001_xpath_over_parse_reader(both):
    assert len(at(both, "DNL-XXE-001", "XmlController.cs", "Xpath")) == 1


def test_xxe001_field_resolver_set_in_constructor(both):
    assert len(at(both, "DNL-XXE-001", "XmlController.cs", "LoadLoose")) == 1
    assert not at(both, "DNL-XXE-001", "XmlController.cs", "LoadTight")


def test_xxe001_one_finding_per_line(both):
    keys = [(f.file, f.line) for f in both if f.check_id == "DNL-XXE-001"]
    assert len(keys) == len(set(keys))


# -- v4.0 project: XXE-001 config shape + XXE-002 once per project --------------------------

def test_legacy_target_framework_documents_unsafe_by_default(both):
    assert len(at(both, "DNL-XXE-001", "Parse.cs", "Read")) == 1
    assert not at(both, "DNL-XXE-001", "Parse.cs", "ReadSafe")
    assert len(at(both, "DNL-XXE-001", "Parse.cs", "Again")) == 1


def test_xxe002_once_per_project(config):
    x = [f for f in config if f.check_id == "DNL-XXE-002"]
    assert len(x) == 1 and x[0].severity == "low" and x[0].file.endswith("Parse.cs")
    assert "Legacy40" in x[0].description and "v4.0" in x[0].description


# -- wiring ----------------------------------------------------------------------------------

def test_analyzers_attach_routes_and_place_route_less(model):
    model.cache.pop("code_results", None)
    out = analyzers._code_results(model)
    flat = [f for _r, fs in out.values() for f in fs]
    proven = [f for f in flat if f.check_id == "DNL-DESER-001" and f.route is not None]
    assert proven and proven[0].route.meta["kind"] == "mvc"
    assert any(f.check_id == "DNL-XXE-002" for f in flat)
    assert any(f.check_id == "DNL-DESER-002" for f in flat)
    assert not any(f.check_id.startswith("DNL-XXE") and f.route is None and f.severity == "high" for f in flat)


# -- fix round 1: untraceable receivers, escaping state, minors ------------------------------

def test_deser002_web_api_formatter_settings_chain(config):
    assert len(at(config, "DNL-DESER-002", "Escapes.cs", "Register")) == 2
    assert not at(config, "DNL-DESER-002", "Escapes.cs", "RegisterSafe")
    assert len(at(config, "DNL-DESER-002", "Escapes.cs", "Wrap")) == 1     # object initializer entry


def test_xxe001_helper_loaded_document_resolver_set_by_caller(both, config):
    assert len(at(both, "DNL-XXE-001", "Escapes.cs", "Do")) == 1
    # the assignment in the caller is reported too (the holder escapes and is never loaded there)
    c = at(config, "DNL-XXE-001", "Escapes.cs", "Caller")
    assert len(c) == 1 and c[0].severity == "medium"
    assert not at(both, "DNL-XXE-001", "Escapes.cs", "SafeCaller")
    assert not at(both, "DNL-XXE-001", "Escapes.cs", "DoSafe")


def test_xxe001_factory_returned_document(taint, config, both):
    t = at(taint, "DNL-XXE-001", "Escapes.cs", "ViaFactory")
    assert len(t) == 1 and t[0].severity == "high" and t[0].route is not None
    assert len(at(config, "DNL-XXE-001", "Escapes.cs", "Mk")) == 1
    assert not at(both, "DNL-XXE-001", "Escapes.cs", "MkSafe")
    assert not at(both, "DNL-XXE-001", "Escapes.cs", "ViaSafeFactory")


def test_xxe001_settings_passed_to_helper(both):
    assert len(at(both, "DNL-XXE-001", "Escapes.cs", "Make")) == 1
    assert len(at(both, "DNL-XXE-001", "Escapes.cs", "Open")) == 1


def test_xxe001_non_literal_dtd_mode_is_unsafe(both):
    assert len(at(both, "DNL-XXE-001", "Escapes.cs", "Mode")) == 1


def test_xxe001_null_resolver_after_load_does_not_protect(both):
    assert len(at(both, "DNL-XXE-001", "Parse.cs", "Go")) == 1


def test_note_when_target_framework_missing(model, refs):
    rules_deser_xml.check(model, refs)
    assert any("NoTfm" in n and "TargetFrameworkVersion" in n for n in model.notes)
    assert not [f for f in rules_deser_xml.check(model, refs)
                if f.check_id == "DNL-XXE-002" and "NoTfm" in f.description]


# -- fix round 2 ---------------------------------------------------------------------------------

def test_caller_state_is_read_at_the_call(both):
    assert len(at(both, "DNL-XXE-001", "Escapes.cs", "DoA")) == 1          # set before, nulled after
    assert not at(both, "DNL-XXE-001", "Escapes.cs", "DoB")                # nulled before, set after
    assert not at(both, "DNL-XXE-001", "Escapes.cs", "NullThenCall")


def test_escape_uses_state_at_escape_point(both, model, refs):
    assert not at(both, "DNL-XXE-001", "Escapes.cs", "NullAfterSet")
    assert len(at(both, "DNL-XXE-001", "Escapes.cs", "SetThenCall")) == 1


def test_escape_only_sites_count_as_xml_parses(model, refs):
    lo, hi = span(DX / "Escapes.cs", "Mk")
    assert any(p.file.endswith("Escapes.cs") and lo <= p.line <= hi
               for p in rules_deser_xml._scan(model, refs).parses)


def test_stray_type_name_handling_needs_a_json_looking_receiver(config):
    assert not at(config, "DNL-DESER-002", "Escapes.cs", "Turn")
    assert len(at(config, "DNL-DESER-002", "Escapes.cs", "Register")) == 2
    assert len(at(config, "DNL-DESER-002", "Escapes.cs", "Wrap")) == 1


def test_dtd_mode_through_constant(both):
    assert not at(both, "DNL-XXE-001", "Escapes.cs", "ConstMode")
    assert len(at(both, "DNL-XXE-001", "Escapes.cs", "Mode")) == 1


def test_direct_call_receiver_and_named_arguments(taint, both):
    t = at(taint, "DNL-XXE-001", "Escapes.cs", "ViaDirect")
    assert len(t) == 1 and t[0].severity == "high"
    assert len(at(both, "DNL-XXE-001", "Escapes.cs", "DoNamed")) == 1


# -- fix round 3 ---------------------------------------------------------------------------------

@pytest.mark.parametrize("method", ["Num", "Lit", "FromVar", "Odd"])
def test_type_name_handling_values_other_than_the_enum_spelling(config, method):
    assert len(at(config, "DNL-DESER-002", "Escapes.cs", method)) == 1


def test_type_name_handling_none_through_a_local_is_quiet(config):
    assert not at(config, "DNL-DESER-002", "Escapes.cs", "ViaNoneLocal")


@pytest.mark.parametrize("method", ["Reassigned", "FieldMode"])
def test_dtd_mode_must_be_safe_on_every_assignment(both, method):
    assert len(at(both, "DNL-XXE-001", "Escapes.cs", method)) == 1


def test_conditional_null_does_not_clear_the_escape(both, config):
    assert len(at(config, "DNL-XXE-001", "Escapes.cs", "CondNull")) == 1
    assert not at(both, "DNL-XXE-001", "Escapes.cs", "NullAfterSet")          # unconditional null
    assert len(at(both, "DNL-XXE-001", "Escapes.cs", "DoC")) == 1             # caller state agrees


def test_each_distinct_insecure_escape_is_reported(config):
    assert len(at(config, "DNL-XXE-001", "Escapes.cs", "Twice")) == 2


# -- fix round 4 ---------------------------------------------------------------------------------

def test_variable_named_none_is_not_none(config):
    assert len(at(config, "DNL-DESER-002", "Round4.cs", "NoneNamed")) == 1
    assert len(at(config, "DNL-DESER-002", "Round4.cs", "NoneNamedStray")) == 1
    assert not at(config, "DNL-DESER-002", "Escapes.cs", "ViaNoneLocal")


def test_loop_carried_setting_after_create_counts(both):
    assert len(at(both, "DNL-XXE-001", "Round4.cs", "LoopCreate")) == 1
    assert not at(both, "DNL-XXE-001", "Round4.cs", "LoopSafe")


def test_clear_in_switch_section_is_conditional(config):
    # the IR lowers a switch section to a flat `if`, which is already a conditional construct
    assert len(at(config, "DNL-XXE-001", "Round4.cs", "SwitchNull")) == 1


@pytest.mark.parametrize("op", ["&&", "||", "AndAlso", "OrElse", "??"])
def test_short_circuit_right_operand_is_conditional(op):
    left, right, other = {"k": "name"}, {"k": "assign"}, {"k": "assign"}
    tree = [{"k": "bin", "op": op, "l": left, "r": right}, other]
    out = {}
    rules_deser_xml._mark_paths(tree, (), out)
    assert out[id(right)] != () and out[id(left)] == () and out[id(other)] == ()


def test_conditional_clear_on_a_field_in_another_method_does_not_clear(both):
    assert len(at(both, "DNL-XXE-001", "Round4.cs", "OpenFst")) == 1


def test_dtd_member_needs_the_dtd_processing_owner(both):
    assert len(at(both, "DNL-XXE-001", "Round4.cs", "ForeignIgnore")) == 1
