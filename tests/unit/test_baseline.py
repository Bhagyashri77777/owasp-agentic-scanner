"""Unit tests for baseline module."""

import json
from pathlib import Path

from owasp_agentic_scanner.baseline import Baseline, BaselineFinding
from owasp_agentic_scanner.rules.base import Finding, Severity


class TestBaselineFinding:
    """Test BaselineFinding functionality."""

    def test_from_finding(self) -> None:
        """Test creating BaselineFinding from Finding."""
        finding = Finding(
            rule_id="AA05",
            rule_name="Code Execution",
            severity=Severity.CRITICAL,
            file_path="test.py",
            line_number=10,
            line_content="eval(input())",
            message="Dangerous eval",
            recommendation="Use ast.literal_eval",
            owasp_category="AA05",
            confidence="high",
        )

        baseline_finding = BaselineFinding.from_finding(finding)

        assert baseline_finding.rule_id == "AA05"
        assert baseline_finding.file_path == "test.py"
        assert baseline_finding.line_number == 10
        assert baseline_finding.message == "Dangerous eval"
        assert len(baseline_finding.hash) == 16

    def test_hash_consistency(self) -> None:
        """Test hash is consistent for same finding."""
        finding = Finding(
            rule_id="AA05",
            rule_name="Code Execution",
            severity=Severity.CRITICAL,
            file_path="test.py",
            line_number=10,
            line_content="eval(input())",
            message="Dangerous eval",
            recommendation="Use ast.literal_eval",
            owasp_category="AA05",
            confidence="high",
        )

        bf1 = BaselineFinding.from_finding(finding)
        bf2 = BaselineFinding.from_finding(finding)

        assert bf1.hash == bf2.hash

    def test_hash_different_for_different_findings(self) -> None:
        """Test hash is different for different findings."""
        finding1 = Finding(
            rule_id="AA05",
            rule_name="Code Execution",
            severity=Severity.CRITICAL,
            file_path="test.py",
            line_number=10,
            line_content="eval(input())",
            message="Dangerous eval",
            recommendation="Fix",
            owasp_category="AA05",
            confidence="high",
        )

        finding2 = Finding(
            rule_id="AA02",
            rule_name="Tool Misuse",
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=20,
            line_content="os.system(cmd)",
            message="Command injection",
            recommendation="Fix",
            owasp_category="AA02",
            confidence="high",
        )

        bf1 = BaselineFinding.from_finding(finding1)
        bf2 = BaselineFinding.from_finding(finding2)

        assert bf1.hash != bf2.hash

    def test_to_dict(self) -> None:
        """Test converting to dictionary."""
        finding = Finding(
            rule_id="AA05",
            rule_name="Code Execution",
            severity=Severity.CRITICAL,
            file_path="test.py",
            line_number=10,
            line_content="eval(input())",
            message="Dangerous eval",
            recommendation="Fix",
            owasp_category="AA05",
            confidence="high",
        )

        baseline_finding = BaselineFinding.from_finding(finding)
        data = baseline_finding.to_dict()

        assert data["rule_id"] == "AA05"
        assert data["file_path"] == "test.py"
        assert data["line_number"] == 10
        assert data["message"] == "Dangerous eval"
        assert "hash" in data

    def test_from_dict(self) -> None:
        """Test creating from dictionary."""
        data = {
            "rule_id": "AA05",
            "file_path": "test.py",
            "line_number": 10,
            "message": "Dangerous eval",
            "hash": "abc123",
        }

        bf = BaselineFinding.from_dict(data)

        assert bf.rule_id == "AA05"
        assert bf.file_path == "test.py"
        assert bf.line_number == 10
        assert bf.message == "Dangerous eval"
        assert bf.hash == "abc123"


class TestBaseline:
    """Test Baseline functionality."""

    def test_baseline_init_empty(self, tmp_path: Path) -> None:
        """Test baseline initialization without file."""
        baseline = Baseline()

        assert baseline.baseline_file is None
        assert baseline.findings == {}
        assert baseline.metadata == {}

    def test_baseline_init_with_file(self, tmp_path: Path) -> None:
        """Test baseline initialization with existing file."""
        baseline_file = tmp_path / "baseline.json"

        # Create test baseline file
        data = {
            "metadata": {"created_at": "2025-01-01T00:00:00Z", "total_findings": 1},
            "findings": [
                {
                    "rule_id": "AA05",
                    "file_path": "test.py",
                    "line_number": 10,
                    "message": "Test finding",
                    "hash": "abc123",
                }
            ],
        }
        baseline_file.write_text(json.dumps(data))

        baseline = Baseline(baseline_file)

        assert baseline.baseline_file == baseline_file
        assert len(baseline.findings) == 1
        assert "abc123" in baseline.findings

    def test_load_existing_baseline(self, tmp_path: Path) -> None:
        """Test loading baseline from file."""
        baseline_file = tmp_path / "baseline.json"

        # Create test baseline file
        data = {
            "metadata": {"created_at": "2025-01-01T00:00:00Z"},
            "findings": [
                {
                    "rule_id": "AA05",
                    "file_path": "test.py",
                    "line_number": 10,
                    "message": "Test finding",
                    "hash": "abc123",
                },
                {
                    "rule_id": "AA02",
                    "file_path": "test2.py",
                    "line_number": 20,
                    "message": "Another finding",
                    "hash": "def456",
                },
            ],
        }
        baseline_file.write_text(json.dumps(data))

        baseline = Baseline()
        baseline.load(baseline_file)

        assert len(baseline.findings) == 2
        assert "abc123" in baseline.findings
        assert "def456" in baseline.findings
        assert baseline.metadata["created_at"] == "2025-01-01T00:00:00Z"

    def test_load_handles_missing_file(self, tmp_path: Path) -> None:
        """Test load handles missing file gracefully."""
        baseline_file = tmp_path / "missing.json"

        baseline = Baseline()
        baseline.load(baseline_file)

        assert baseline.findings == {}

    def test_load_handles_corrupted_json(self, tmp_path: Path) -> None:
        """Test load handles corrupted JSON gracefully."""
        baseline_file = tmp_path / "baseline.json"
        baseline_file.write_text("{invalid json")

        baseline = Baseline()
        baseline.load(baseline_file)

        assert baseline.findings == {}

    def test_save_creates_baseline(self, tmp_path: Path) -> None:
        """Test save creates baseline file."""
        baseline_file = tmp_path / "baseline.json"
        baseline = Baseline()

        findings = [
            Finding(
                rule_id="AA05",
                rule_name="Code Execution",
                severity=Severity.CRITICAL,
                file_path="test.py",
                line_number=10,
                line_content="eval(input())",
                message="Dangerous eval",
                recommendation="Fix",
                owasp_category="AA05",
                confidence="high",
            )
        ]

        baseline.save(baseline_file, findings)

        assert baseline_file.exists()

        # Verify content
        data = json.loads(baseline_file.read_text())
        assert "metadata" in data
        assert "findings" in data
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == "AA05"

    def test_save_with_multiple_findings(self, tmp_path: Path) -> None:
        """Test save with multiple findings."""
        baseline_file = tmp_path / "baseline.json"
        baseline = Baseline()

        findings = [
            Finding(
                rule_id="AA05",
                rule_name="Code Execution",
                severity=Severity.CRITICAL,
                file_path="test.py",
                line_number=10,
                line_content="eval(input())",
                message="eval usage",
                recommendation="Fix",
                owasp_category="AA05",
                confidence="high",
            ),
            Finding(
                rule_id="AA02",
                rule_name="Tool Misuse",
                severity=Severity.HIGH,
                file_path="test2.py",
                line_number=20,
                line_content="os.system(cmd)",
                message="Command injection",
                recommendation="Fix",
                owasp_category="AA02",
                confidence="high",
            ),
        ]

        baseline.save(baseline_file, findings)

        data = json.loads(baseline_file.read_text())
        assert len(data["findings"]) == 2
        assert data["metadata"]["total_findings"] == 2
        assert data["metadata"]["files_scanned"] == 2

    def test_is_baselined_exact_match(self, tmp_path: Path) -> None:
        """Test is_baselined with exact hash match."""
        baseline = Baseline()

        finding = Finding(
            rule_id="AA05",
            rule_name="Code Execution",
            severity=Severity.CRITICAL,
            file_path="test.py",
            line_number=10,
            line_content="eval(input())",
            message="Dangerous eval",
            recommendation="Fix",
            owasp_category="AA05",
            confidence="high",
        )

        # Add to baseline
        bf = BaselineFinding.from_finding(finding)
        baseline.findings[bf.hash] = bf

        # Should be baselined
        assert baseline.is_baselined(finding) is True

    def test_is_baselined_fuzzy_match(self, tmp_path: Path) -> None:
        """Test is_baselined with fuzzy line number match."""
        baseline = Baseline()

        # Original finding at line 10
        original_finding = Finding(
            rule_id="AA05",
            rule_name="Code Execution",
            severity=Severity.CRITICAL,
            file_path="test.py",
            line_number=10,
            line_content="eval(input())",
            message="Dangerous eval",
            recommendation="Fix",
            owasp_category="AA05",
            confidence="high",
        )

        bf = BaselineFinding.from_finding(original_finding)
        baseline.findings[bf.hash] = bf

        # Same finding but line shifted to 12 (within ±5 lines)
        shifted_finding = Finding(
            rule_id="AA05",
            rule_name="Code Execution",
            severity=Severity.CRITICAL,
            file_path="test.py",
            line_number=12,
            line_content="eval(input())",
            message="Dangerous eval",
            recommendation="Fix",
            owasp_category="AA05",
            confidence="high",
        )

        # Should still be baselined due to fuzzy match
        assert baseline.is_baselined(shifted_finding) is True

    def test_is_baselined_no_match(self, tmp_path: Path) -> None:
        """Test is_baselined returns False for new finding."""
        baseline = Baseline()

        finding = Finding(
            rule_id="AA05",
            rule_name="Code Execution",
            severity=Severity.CRITICAL,
            file_path="test.py",
            line_number=10,
            line_content="eval(input())",
            message="Dangerous eval",
            recommendation="Fix",
            owasp_category="AA05",
            confidence="high",
        )

        # Empty baseline
        assert baseline.is_baselined(finding) is False

    def test_filter_new_findings(self, tmp_path: Path) -> None:
        """Test filter_new_findings separates new and baselined."""
        baseline = Baseline()

        # Add one finding to baseline
        baselined = Finding(
            rule_id="AA05",
            rule_name="Code Execution",
            severity=Severity.CRITICAL,
            file_path="test.py",
            line_number=10,
            line_content="eval(input())",
            message="Dangerous eval",
            recommendation="Fix",
            owasp_category="AA05",
            confidence="high",
        )

        bf = BaselineFinding.from_finding(baselined)
        baseline.findings[bf.hash] = bf

        # New finding
        new = Finding(
            rule_id="AA02",
            rule_name="Tool Misuse",
            severity=Severity.HIGH,
            file_path="test2.py",
            line_number=20,
            line_content="os.system(cmd)",
            message="Command injection",
            recommendation="Fix",
            owasp_category="AA02",
            confidence="high",
        )

        findings = [baselined, new]
        new_findings, baselined_findings = baseline.filter_new_findings(findings)

        assert len(new_findings) == 1
        assert new_findings[0].rule_id == "AA02"
        assert len(baselined_findings) == 1
        assert baselined_findings[0].rule_id == "AA05"

    def test_filter_all_new(self, tmp_path: Path) -> None:
        """Test filter_new_findings when all are new."""
        baseline = Baseline()

        findings = [
            Finding(
                rule_id="AA05",
                rule_name="Code Execution",
                severity=Severity.CRITICAL,
                file_path="test.py",
                line_number=10,
                line_content="eval(input())",
                message="eval usage",
                recommendation="Fix",
                owasp_category="AA05",
                confidence="high",
            )
        ]

        new_findings, baselined_findings = baseline.filter_new_findings(findings)

        assert len(new_findings) == 1
        assert len(baselined_findings) == 0

    def test_filter_all_baselined(self, tmp_path: Path) -> None:
        """Test filter_new_findings when all are baselined."""
        baseline = Baseline()

        finding = Finding(
            rule_id="AA05",
            rule_name="Code Execution",
            severity=Severity.CRITICAL,
            file_path="test.py",
            line_number=10,
            line_content="eval(input())",
            message="eval usage",
            recommendation="Fix",
            owasp_category="AA05",
            confidence="high",
        )

        bf = BaselineFinding.from_finding(finding)
        baseline.findings[bf.hash] = bf

        new_findings, baselined_findings = baseline.filter_new_findings([finding])

        assert len(new_findings) == 0
        assert len(baselined_findings) == 1

    def test_get_stats_empty(self, tmp_path: Path) -> None:
        """Test get_stats with empty baseline."""
        baseline = Baseline()
        stats = baseline.get_stats()

        assert stats["total"] == 0

    def test_get_stats_with_findings(self, tmp_path: Path) -> None:
        """Test get_stats with findings."""
        baseline = Baseline()

        findings = [
            Finding(
                rule_id="AA05",
                rule_name="Code Execution",
                severity=Severity.CRITICAL,
                file_path="test.py",
                line_number=10,
                line_content="eval(input())",
                message="eval usage",
                recommendation="Fix",
                owasp_category="AA05",
                confidence="high",
            ),
            Finding(
                rule_id="AA05",
                rule_name="Code Execution",
                severity=Severity.CRITICAL,
                file_path="test2.py",
                line_number=20,
                line_content="exec(code)",
                message="exec usage",
                recommendation="Fix",
                owasp_category="AA05",
                confidence="high",
            ),
            Finding(
                rule_id="AA02",
                rule_name="Tool Misuse",
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=30,
                line_content="os.system(cmd)",
                message="Command injection",
                recommendation="Fix",
                owasp_category="AA02",
                confidence="high",
            ),
        ]

        # Add to baseline
        for finding in findings:
            bf = BaselineFinding.from_finding(finding)
            baseline.findings[bf.hash] = bf

        stats = baseline.get_stats()

        assert stats["total"] == 3
        assert stats["by_rule"]["AA05"] == 2
        assert stats["by_rule"]["AA02"] == 1
        assert stats["by_file"]["test.py"] == 2
        assert stats["by_file"]["test2.py"] == 1
