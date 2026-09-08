"""Tests for non-route entry point detection (@Scheduled, @KafkaListener,
etc) and its correlation with dangerous-sink findings in the HTML report's
Entry Points tab. See languages/java/spring_analyzer.py's _find_entry_points
and core/html_report.py's _findings_within_entry_point.
"""
from core.html_report import _findings_within_entry_point
from core.models import EntryPoint, Finding
from languages.java.spring_analyzer import SpringAnalyzer


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_scheduled_method_is_detected_with_cron_detail(tmp_path):
    _write(
        tmp_path,
        "Jobs.java",
        "package com.example;\n"
        "import org.springframework.scheduling.annotation.Scheduled;\n\n"
        "public class Jobs {\n"
        "    @Scheduled(cron = \"0 0 * * * *\")\n"
        "    public void cleanupOldFiles() {\n"
        "        doWork();\n"
        "    }\n"
        "}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    entry_point = next(ep for ep in result.entry_points if ep.kind == "Scheduled")
    assert entry_point.handler_name == "cleanupOldFiles"
    assert entry_point.detail == "cron=0 0 * * * *"
    # position is the method declaration's own line, not the annotation's.
    assert entry_point.source_start_line == entry_point.line == 6
    assert entry_point.source_end_line == 8


def test_kafka_listener_is_detected_with_topic_detail(tmp_path):
    _write(
        tmp_path,
        "Jobs.java",
        "package com.example;\n"
        "import org.springframework.kafka.annotation.KafkaListener;\n\n"
        "public class Jobs {\n"
        "    @KafkaListener(topics = \"orders\")\n"
        "    public void onOrderMessage(String payload) {\n"
        "        process(payload);\n"
        "    }\n"
        "}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    entry_point = next(ep for ep in result.entry_points if ep.kind == "KafkaListener")
    assert entry_point.handler_name == "onOrderMessage"
    assert entry_point.detail == "topics=orders"


def test_graphql_query_mapping_is_detected_with_name_detail(tmp_path):
    _write(
        tmp_path,
        "OrderResolver.java",
        "package com.example;\n"
        "import org.springframework.graphql.data.method.annotation.QueryMapping;\n\n"
        "public class OrderResolver {\n"
        "    @QueryMapping(name = \"order\")\n"
        "    public Order order(String id) {\n"
        "        return lookup(id);\n"
        "    }\n"
        "}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    entry_point = next(ep for ep in result.entry_points if ep.kind == "QueryMapping")
    assert entry_point.handler_name == "order"
    assert entry_point.detail == "name=order"


def test_graphql_schema_mapping_is_detected_with_field_detail(tmp_path):
    _write(
        tmp_path,
        "OrderResolver.java",
        "package com.example;\n"
        "import org.springframework.graphql.data.method.annotation.SchemaMapping;\n\n"
        "public class OrderResolver {\n"
        "    @SchemaMapping(field = \"items\")\n"
        "    public java.util.List<Item> items(Order order) {\n"
        "        return lookupItems(order);\n"
        "    }\n"
        "}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    entry_point = next(ep for ep in result.entry_points if ep.kind == "SchemaMapping")
    assert entry_point.detail == "field=items"


def test_spring_integration_service_activator_is_detected_with_channel_detail(tmp_path):
    _write(
        tmp_path,
        "OrderActivator.java",
        "package com.example;\n"
        "import org.springframework.integration.annotation.ServiceActivator;\n\n"
        "public class OrderActivator {\n"
        "    @ServiceActivator(inputChannel = \"orderChannel\")\n"
        "    public void handle(String payload) {\n"
        "        process(payload);\n"
        "    }\n"
        "}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    entry_point = next(ep for ep in result.entry_points if ep.kind == "ServiceActivator")
    assert entry_point.detail == "inputChannel=orderChannel"


def test_custom_actuator_read_operation_is_detected_with_no_detail(tmp_path):
    _write(
        tmp_path,
        "CustomEndpoint.java",
        "package com.example;\n"
        "import org.springframework.boot.actuate.endpoint.annotation.Endpoint;\n"
        "import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;\n\n"
        "@Endpoint(id = \"custom\")\n"
        "public class CustomEndpoint {\n"
        "    @ReadOperation\n"
        "    public String data() {\n"
        "        return loadData();\n"
        "    }\n"
        "}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    entry_point = next(ep for ep in result.entry_points if ep.kind == "ReadOperation")
    assert entry_point.handler_name == "data"
    assert entry_point.detail == ""


def test_plain_method_is_not_an_entry_point(tmp_path):
    _write(
        tmp_path,
        "Jobs.java",
        "package com.example;\n"
        "public class Jobs {\n"
        "    public void notAnEntryPoint() {}\n"
        "}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    assert result.entry_points == []


def test_command_injection_sink_inside_scheduled_job_is_detected_and_correlated(tmp_path):
    _write(
        tmp_path,
        "Jobs.java",
        "package com.example;\n"
        "import org.springframework.scheduling.annotation.Scheduled;\n\n"
        "public class Jobs {\n"
        "    @Scheduled(cron = \"0 0 * * * *\")\n"
        "    public void cleanupOldFiles() {\n"
        "        String target = loadTargetName();\n"
        "        Runtime.getRuntime().exec(target);\n"
        "    }\n"
        "    private String loadTargetName() { return \"abc\"; }\n"
        "}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    entry_point = next(ep for ep in result.entry_points if ep.kind == "Scheduled")
    assert any(f.check_id == "CMD-001" for f in result.findings)

    correlated = _findings_within_entry_point(entry_point, result.findings)
    assert len(correlated) == 1
    assert correlated[0].check_id == "CMD-001"


def test_findings_within_entry_point_excludes_findings_outside_its_range():
    entry_point = EntryPoint(
        kind="Scheduled",
        detail="cron=0 0 * * * *",
        handler_name="cleanupOldFiles",
        file="Jobs.java",
        line=5,
        source_start_line=5,
        source_end_line=8,
    )
    inside = Finding(
        check_id="CMD-001",
        severity="medium",
        title="t",
        description="d",
        file="Jobs.java",
        line=6,
        route=None,
    )
    outside = Finding(
        check_id="CMD-001",
        severity="medium",
        title="t",
        description="d",
        file="Jobs.java",
        line=20,
        route=None,
    )
    different_file = Finding(
        check_id="CMD-001",
        severity="medium",
        title="t",
        description="d",
        file="Other.java",
        line=6,
        route=None,
    )

    correlated = _findings_within_entry_point(entry_point, [inside, outside, different_file])
    assert correlated == [inside]
