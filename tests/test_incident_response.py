"""事件响应系统测试（人员绑定、处置、健康、知识）。"""

import os
import sys
import json
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from incident_response.models import (
    ResponsiblePerson, ApiBinding, Incident, HealthRecord,
    HealthChange, InternalizedKnowledge, determine_disposition,
    SEVERITY_LEVELS, DISPOSITION_TYPES,
)
from incident_response.person_binding import (
    add_person, find_person, list_persons, delete_person,
    add_binding, remove_binding, list_bindings, find_responsible_for_api,
)
from incident_response.health_tracker import HealthTracker
from incident_response.knowledge_internalizer import KnowledgeInternalizer
from incident_response.disposition import DispositionEngine


# ==================== 夹具 ====================

@pytest.fixture
def temp_data_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def sample_person():
    return ResponsiblePerson(
        id="p1", name="Alice", email="alice@example.com",
        phone="+1234567890", role="security-engineer",
    )


@pytest.fixture
def sample_incident():
    return Incident(
        id="inc1", log_id=42, api_endpoint="/api/users",
        severity="HIGH", confidence=0.85,
        anomaly_type="sql_injection",
        reason="SQL injection detected in user input",
    )


@pytest.fixture
def sample_health_before():
    return HealthRecord(
        id="h1", api_endpoint="/api/users",
        timestamp="2026-01-01T10:00:00",
        health_score=0.75, anomaly_count=5, total_requests=100,
        avg_response_time_ms=250.0, status="degraded",
    )


@pytest.fixture
def sample_health_after():
    return HealthRecord(
        id="h2", api_endpoint="/api/users",
        timestamp="2026-01-01T10:05:00",
        health_score=0.85, anomaly_count=2, total_requests=100,
        avg_response_time_ms=200.0, status="normal",
    )


# ==================== 模型测试 ====================

class TestModels:
    def test_responsible_person_defaults(self):
        p = ResponsiblePerson(id="p1", name="Bob", email="bob@test.com")
        assert p.role == "developer"
        assert p.phone == ""
        assert p.created_at != ""

    def test_responsible_person_to_from_dict(self):
        orig = ResponsiblePerson(id="p1", name="Alice", email="a@b.com", role="admin")
        d = orig.to_dict()
        restored = ResponsiblePerson.from_dict(d)
        assert restored.name == "Alice"
        assert restored.role == "admin"

    def test_api_binding_matches(self):
        b = ApiBinding(id="b1", api_pattern="/api/users/*", person_id="p1")
        assert b.matches("/api/users/list")
        assert b.matches("/api/users/123")
        assert not b.matches("/api/admin")

    def test_incident_properties(self):
        crit = Incident(id="i1", log_id=1, api_endpoint="/api/test",
                         severity="CRITICAL", confidence=0.95, anomaly_type="xss")
        low = Incident(id="i2", log_id=2, api_endpoint="/api/test",
                        severity="LOW", confidence=0.3, anomaly_type="info")

        assert crit.requires_immediate_action is True
        assert crit.should_notify is True
        assert low.requires_immediate_action is False
        assert low.should_notify is False

    def test_health_change_properties(self, sample_health_before, sample_health_after):
        change = HealthChange(
            api_endpoint="/api/users",
            before=sample_health_before,
            after=sample_health_after,
            incident_id="inc1",
            disposition_taken="notify_email",
        )
        assert change.health_delta == pytest.approx(0.1)
        assert change.anomaly_delta == -3
        assert change.improvement is True

    def test_health_change_no_improvement(self, sample_health_before):
        worse = HealthRecord(
            id="h3", api_endpoint="/api/users", timestamp="2026-01-01T10:05:00",
            health_score=0.6, anomaly_count=10, total_requests=100,
            avg_response_time_ms=300.0, status="critical",
        )
        change = HealthChange(
            api_endpoint="/api/users",
            before=sample_health_before,
            after=worse,
            incident_id="inc1",
            disposition_taken="auto_log",
        )
        assert change.health_delta < 0
        assert change.improvement is False

    def test_internalized_knowledge_defaults(self):
        k = InternalizedKnowledge(
            id="k1", api_endpoint="/api/users",
            incident_type="xss", severity="HIGH",
            disposition_taken="notify_email",
            health_impact="improved",
            learned_pattern="test pattern",
            recommendation="test recommendation",
        )
        assert k.created_at != ""
        assert k.effectiveness_score == 0.0


# ==================== 处置规则测试 ====================

class TestDispositionRules:
    def test_auto_block_critical_high_confidence(self):
        assert determine_disposition("CRITICAL", 0.95) == "auto_block"

    def test_notify_email_critical_medium_confidence(self):
        assert determine_disposition("CRITICAL", 0.75) == "notify_email"

    def test_notify_email_high(self):
        assert determine_disposition("HIGH", 0.0) == "notify_email"

    def test_notify_email_medium(self):
        assert determine_disposition("MEDIUM", 0.0) == "notify_email"

    def test_auto_log_low(self):
        assert determine_disposition("LOW", 0.0) == "auto_log"

    def test_none_info(self):
        assert determine_disposition("INFO", 0.0) == "none"


# ==================== 人员绑定测试 ====================

class TestPersonBinding:
    def test_add_and_find_person(self, temp_data_dir):
        # 通过环境变量或直接初始化覆盖 DATA_DIR — 我们使用临时目录
        import incident_response.person_binding as pb
        orig_dir = pb.DATA_DIR
        pb.DATA_DIR = temp_data_dir
        pb.PERSONS_FILE = os.path.join(temp_data_dir, "persons.json")
        pb.BINDINGS_FILE = os.path.join(temp_data_dir, "bindings.json")

        try:
            p = add_person("Alice", "alice@test.com", role="security")
            assert p.id is not None
            assert p.name == "Alice"

            found = find_person(p.id)
            assert found is not None
            assert found.email == "alice@test.com"

            persons = list_persons()
            assert len(persons) == 1
        finally:
            pb.DATA_DIR = orig_dir
            pb.PERSONS_FILE = os.path.join(orig_dir, "persons.json")
            pb.BINDINGS_FILE = os.path.join(orig_dir, "bindings.json")

    def test_delete_person_removes_bindings(self, temp_data_dir):
        import incident_response.person_binding as pb
        orig_dir = pb.DATA_DIR
        pb.DATA_DIR = temp_data_dir
        pb.PERSONS_FILE = os.path.join(temp_data_dir, "persons.json")
        pb.BINDINGS_FILE = os.path.join(temp_data_dir, "bindings.json")

        try:
            p = add_person("Bob", "bob@test.com")
            b = add_binding("/api/*", p.id)
            assert b is not None

            deleted = delete_person(p.id)
            assert deleted is True

            assert find_person(p.id) is None
            assert len(list_bindings()) == 0
        finally:
            pb.DATA_DIR = orig_dir
            pb.PERSONS_FILE = os.path.join(orig_dir, "persons.json")
            pb.BINDINGS_FILE = os.path.join(orig_dir, "bindings.json")

    def test_add_binding_nonexistent_person(self):
        b = add_binding("/api/test", "nonexistent")
        assert b is None

    def test_find_responsible_for_api(self, temp_data_dir):
        import incident_response.person_binding as pb
        orig_dir = pb.DATA_DIR
        pb.DATA_DIR = temp_data_dir
        pb.PERSONS_FILE = os.path.join(temp_data_dir, "persons.json")
        pb.BINDINGS_FILE = os.path.join(temp_data_dir, "bindings.json")

        try:
            alice = add_person("Alice", "alice@test.com")
            bob = add_person("Bob", "bob@test.com")

            add_binding("/api/users/*", alice.id, priority=5)
            add_binding("/api/*", bob.id, priority=1)

            matched = find_responsible_for_api("/api/users/list")
            assert len(matched) >= 2
            # Alice（更具体的模式 + 更高优先级）应该排在前面
            assert matched[0][1].name == "Alice"
        finally:
            pb.DATA_DIR = orig_dir
            pb.PERSONS_FILE = os.path.join(orig_dir, "persons.json")
            pb.BINDINGS_FILE = os.path.join(orig_dir, "bindings.json")


# ==================== 健康追踪器测试 ====================

class TestHealthTracker:
    def test_snapshot_creates_record(self, temp_data_dir):
        tracker = HealthTracker(data_dir=temp_data_dir)
        record = tracker.snapshot("/api/test", anomaly_count=2, total_requests=100)
        assert record.api_endpoint == "/api/test"
        assert record.status in ("normal", "degraded", "critical")
        assert 0.0 <= record.health_score <= 1.0
        assert record.id is not None

    def test_snapshot_high_anomaly_rate(self, temp_data_dir):
        tracker = HealthTracker(data_dir=temp_data_dir)
        # 90% 异常率：health_score = 1.0 - (0.9 * 0.5) = 0.55（无历史/时效性惩罚）
        record = tracker.snapshot("/api/test", anomaly_count=90, total_requests=100)
        assert record.health_score < 0.6
        assert record.status == "degraded"

    def test_snapshot_no_anomalies(self, temp_data_dir):
        tracker = HealthTracker(data_dir=temp_data_dir)
        record = tracker.snapshot("/api/test", anomaly_count=0, total_requests=100)
        assert record.health_score > 0.5
        assert record.status == "normal"

    def test_get_health_trend_empty(self, temp_data_dir):
        tracker = HealthTracker(data_dir=temp_data_dir)
        trend = tracker.get_health_trend("/api/nonexistent")
        assert trend["status"] == "unknown"

    def test_get_health_trend_with_data(self, temp_data_dir):
        tracker = HealthTracker(data_dir=temp_data_dir)
        tracker.snapshot("/api/test", anomaly_count=5, total_requests=100)
        tracker.snapshot("/api/test", anomaly_count=2, total_requests=100)
        tracker.snapshot("/api/test", anomaly_count=1, total_requests=100)

        trend = tracker.get_health_trend("/api/test", window=5)
        assert trend["api_endpoint"] == "/api/test"
        assert trend["records_count"] == 3
        assert trend["current_score"] is not None

    def test_record_change(self, temp_data_dir, sample_health_before, sample_health_after):
        tracker = HealthTracker(data_dir=temp_data_dir)
        change = tracker.record_change("inc1", sample_health_before, sample_health_after, "notify_email")
        assert change.health_delta == pytest.approx(0.1)
        assert change.improvement is True

        changes = tracker.get_all_changes()
        assert len(changes) == 1


# ==================== 知识内化器测试 ====================

class TestKnowledgeInternalizer:
    def test_internalize_creates_entry(self, temp_data_dir, sample_incident,
                                        sample_health_before, sample_health_after):
        ki = KnowledgeInternalizer(data_dir=temp_data_dir)
        entry = ki.internalize(sample_incident, sample_health_before,
                                sample_health_after, "completed")
        assert entry.id is not None
        assert entry.health_impact in ("improved", "degraded", "unchanged")
        assert entry.learned_pattern != ""
        assert entry.recommendation != ""
        assert 0.0 <= entry.effectiveness_score <= 1.0

    def test_internalize_effectiveness_score(self, temp_data_dir, sample_incident,
                                              sample_health_before, sample_health_after):
        ki = KnowledgeInternalizer(data_dir=temp_data_dir)
        entry = ki.internalize(sample_incident, sample_health_before,
                                sample_health_after, "completed")
        # 完成处置 + 健康改善 + 高严重性
        assert entry.effectiveness_score > 0.5

    def test_internalize_degraded(self, temp_data_dir, sample_incident, sample_health_before):
        ki = KnowledgeInternalizer(data_dir=temp_data_dir)
        worse = HealthRecord(
            id="h3", api_endpoint="/api/users", timestamp="2026-01-01T10:05:00",
            health_score=0.4, anomaly_count=15, total_requests=100,
            avg_response_time_ms=500.0, status="critical",
        )
        entry = ki.internalize(sample_incident, sample_health_before, worse, "failed")
        assert entry.health_impact == "degraded"
        assert "declined" in entry.recommendation or "degraded" in entry.health_impact

    def test_search_by_api(self, temp_data_dir, sample_incident,
                            sample_health_before, sample_health_after):
        ki = KnowledgeInternalizer(data_dir=temp_data_dir)
        ki.internalize(sample_incident, sample_health_before, sample_health_after, "completed")

        results = ki.search(api_endpoint="/api/users")
        assert len(results) >= 1

        results = ki.search(api_endpoint="/api/other")
        assert len(results) == 0

    def test_build_rag_context(self, temp_data_dir, sample_incident,
                                sample_health_before, sample_health_after):
        ki = KnowledgeInternalizer(data_dir=temp_data_dir)
        ki.internalize(sample_incident, sample_health_before, sample_health_after, "completed")

        ctx = ki.build_rag_context("/api/users", "sql_injection")
        assert "Past incident knowledge" in ctx
        assert "sql_injection" in ctx or "SQL" in ctx

        ctx_empty = ki.build_rag_context("/api/other", "xss")
        assert "No prior knowledge" in ctx_empty

    def test_get_summary(self, temp_data_dir, sample_incident,
                          sample_health_before, sample_health_after):
        ki = KnowledgeInternalizer(data_dir=temp_data_dir)
        assert ki.get_summary()["total"] == 0

        ki.internalize(sample_incident, sample_health_before, sample_health_after, "completed")
        summary = ki.get_summary()
        assert summary["total"] == 1
        assert summary["by_incident_type"].get("sql_injection") == 1
        assert summary["avg_effectiveness"] > 0

    def test_get_all(self, temp_data_dir, sample_incident,
                      sample_health_before, sample_health_after):
        ki = KnowledgeInternalizer(data_dir=temp_data_dir)
        assert len(ki.get_all()) == 0

        ki.internalize(sample_incident, sample_health_before, sample_health_after, "completed")
        assert len(ki.get_all()) == 1


# ==================== 处置引擎测试 ====================

class TestDispositionEngine:
    def test_process_incident_basic(self, temp_data_dir):
        engine = DispositionEngine(data_dir=temp_data_dir)
        inc = engine.process_incident(
            log_id=42,
            api_endpoint="/api/test",
            severity="LOW",
            confidence=0.3,
            anomaly_type="info",
            reason="测试事件",
        )
        assert inc.id is not None
        assert inc.disposition == "auto_log"
        assert inc.disposition_status == "completed"

    def test_process_incident_critical(self, temp_data_dir):
        engine = DispositionEngine(data_dir=temp_data_dir)
        inc = engine.process_incident(
            log_id=1,
            api_endpoint="/api/admin",
            severity="CRITICAL",
            confidence=0.95,
            anomaly_type="sql_injection",
            reason="SQL 注入尝试",
        )
        assert inc.disposition == "auto_block"
        assert inc.disposition_status == "completed"

    def test_process_incident_with_person(self, temp_data_dir):
        import incident_response.person_binding as pb
        orig_dir = pb.DATA_DIR
        pb.DATA_DIR = temp_data_dir
        pb.PERSONS_FILE = os.path.join(temp_data_dir, "persons.json")
        pb.BINDINGS_FILE = os.path.join(temp_data_dir, "bindings.json")

        try:
            p = add_person("Alice", "alice@test.com")
            add_binding("/api/users/*", p.id, priority=10)

            engine = DispositionEngine(data_dir=temp_data_dir)
            inc = engine.process_incident(
                log_id=2,
                api_endpoint="/api/users/profile",
                severity="HIGH",
                confidence=0.85,
                anomaly_type="xss",
                reason="检测到 XSS",
            )
            assert inc.notified_person == "Alice"
            assert inc.notified_at != ""
        finally:
            pb.DATA_DIR = orig_dir
            pb.PERSONS_FILE = os.path.join(orig_dir, "persons.json")
            pb.BINDINGS_FILE = os.path.join(orig_dir, "bindings.json")

    def test_process_batch(self, temp_data_dir):
        engine = DispositionEngine(data_dir=temp_data_dir)
        graded = [
            {"log_id": 1, "final_verdict": "anomaly", "endpoint": "/api/test",
             "severity": "LOW", "confidence": 0.3, "anomaly_type": "info",
             "reason": "test"},
            {"log_id": 2, "final_verdict": "normal", "endpoint": "/api/test",
             "severity": "LOW", "confidence": 0.0, "anomaly_type": "",
             "reason": ""},
            {"log_id": 3, "final_verdict": "anomaly", "endpoint": "/api/admin",
             "severity": "CRITICAL", "confidence": 0.95, "anomaly_type": "sql_injection",
             "reason": "SQL 注入"},
        ]
        incidents = engine.process_batch(graded)
        assert len(incidents) == 2  # 跳过正常
        assert incidents[0].disposition == "auto_log"
        assert incidents[1].disposition == "auto_block"

    def test_incident_history_empty(self, temp_data_dir):
        engine = DispositionEngine(data_dir=temp_data_dir)
        history = engine.get_incident_history()
        assert history == []

    def test_incident_history_with_data(self, temp_data_dir):
        engine = DispositionEngine(data_dir=temp_data_dir)
        engine.process_incident(1, "/api/test", "LOW", 0.3, "info", "test")
        engine.process_incident(2, "/api/admin", "HIGH", 0.8, "xss", "test")

        history = engine.get_incident_history()
        assert len(history) == 2

        filtered = engine.get_incident_history(severity="LOW")
        assert len(filtered) == 1

    def test_summary_stats_empty(self, temp_data_dir):
        engine = DispositionEngine(data_dir=temp_data_dir)
        stats = engine.get_summary_stats()
        assert stats["total"] == 0

    def test_summary_stats_with_data(self, temp_data_dir):
        engine = DispositionEngine(data_dir=temp_data_dir)
        engine.process_incident(1, "/api/test", "LOW", 0.3, "info", "test")
        engine.process_incident(2, "/api/admin", "CRITICAL", 0.95, "sql_injection", "test")
        engine.process_incident(3, "/api/test", "MEDIUM", 0.7, "xss", "test")

        stats = engine.get_summary_stats()
        assert stats["total"] == 3
        assert stats["by_severity"].get("LOW") == 1
        assert stats["by_severity"].get("CRITICAL") == 1
        assert "/api/test" in stats["by_api"]
        assert "/api/admin" in stats["by_api"]


# ==================== 集成测试 ====================

class TestEndToEnd:
    def test_full_pipeline_with_batch_and_knowledge(self, temp_data_dir):
        """测试处置 → 健康 → 知识流水线端到端工作。"""
        import incident_response.person_binding as pb
        orig_dir = pb.DATA_DIR
        pb.DATA_DIR = temp_data_dir
        pb.PERSONS_FILE = os.path.join(temp_data_dir, "persons.json")
        pb.BINDINGS_FILE = os.path.join(temp_data_dir, "bindings.json")

        try:
            # 设置：人员 + 绑定
            alice = add_person("Alice", "alice@test.com")
            add_binding("/api/users/*", alice.id, priority=10)

            # 批量处理
            engine = DispositionEngine(data_dir=temp_data_dir)
            graded = [
                {"log_id": 1, "final_verdict": "anomaly",
                 "endpoint": "/api/users/profile", "severity": "HIGH",
                 "confidence": 0.85, "anomaly_type": "xss",
                 "reason": "检测到 XSS 载荷"},
                {"log_id": 2, "final_verdict": "anomaly",
                 "endpoint": "/api/admin", "severity": "CRITICAL",
                 "confidence": 0.95, "anomaly_type": "sql_injection",
                 "reason": "检测到 SQL 注入"},
            ]
            incidents = engine.process_batch(graded)
            assert len(incidents) == 2

            # 验证事件
            assert incidents[0].disposition == "notify_email"
            assert incidents[1].disposition == "auto_block"

            # 验证健康追踪
            trend = engine.health_tracker.get_health_trend("/api/users/profile")
            assert trend["current_status"] is not None

            # 验证知识内化
            knowledge = engine.knowledge_internalizer.get_all()
            assert len(knowledge) == 2

            # 从知识构建 RAG 上下文
            ctx = engine.knowledge_internalizer.build_rag_context(
                "/api/users/profile", "xss"
            )
            assert "Past incident knowledge" in ctx

            # 总结
            stats = engine.get_summary_stats()
            assert stats["total"] == 2
        finally:
            pb.DATA_DIR = orig_dir
            pb.PERSONS_FILE = os.path.join(orig_dir, "persons.json")
            pb.BINDINGS_FILE = os.path.join(orig_dir, "bindings.json")

    def test_health_tracking_after_multiple_incidents(self, temp_data_dir):
        """测试健康评分反映事件历史。"""
        engine = DispositionEngine(data_dir=temp_data_dir)

        # 在同一个端点上处理多个事件
        for i in range(5):
            engine.process_incident(
                log_id=i, api_endpoint="/api/health-test",
                severity="HIGH" if i < 3 else "LOW",
                confidence=0.9 if i < 3 else 0.3,
                anomaly_type="xss" if i < 3 else "info",
                reason=f"test {i}",
            )

        trend = engine.health_tracker.get_health_trend("/api/health-test", window=10)
        assert trend["records_count"] == 10  # 每个事件 2 个快照（处置前 + 处置后）
        # 健康应有已记录的数据
        assert trend["current_score"] is not None
