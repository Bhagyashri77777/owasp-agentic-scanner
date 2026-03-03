"""Enhanced base rule class with AST support for Python files."""

import ast
from abc import abstractmethod
from pathlib import Path
from typing import ClassVar

from owasp_agentic_scanner.ast_analyzer import PythonASTAnalyzer
from owasp_agentic_scanner.rules.base import BaseRule, Finding, Severity


class PythonASTRule(BaseRule):
    """Base class for Python AST-based detection rules.

    This extends BaseRule to provide AST analysis capabilities for Python files,
    while still supporting pattern-based detection for other file types.
    """

    # Override to only scan Python files for AST analysis
    file_extensions: ClassVar[set[str]] = {".py"}

    def __init__(self) -> None:
        """Initialize the rule with both patterns and AST checks."""
        super().__init__()
        self.ast_checks_enabled = True

    @abstractmethod
    def check_ast_node(self, node: ast.AST, analyzer: PythonASTAnalyzer) -> list[Finding]:
        """Analyze an AST node and return findings.

        Args:
            node: The AST node to analyze
            analyzer: The analyzer instance with context information

        Returns:
            List of findings from analyzing this node
        """
        ...

    def scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a file using AST analysis for Python, patterns for others."""
        if not self.should_scan_file(file_path):
            return []

        # For Python files, use AST analysis
        if file_path.suffix == ".py" and self.ast_checks_enabled:
            return self._scan_python_ast(file_path)

        # Fall back to pattern-based scanning for non-Python files
        return super().scan_file(file_path)

    def _scan_python_ast(self, file_path: Path) -> list[Finding]:
        """Scan a Python file using AST analysis."""
        findings = []

        try:
            source = file_path.read_text(encoding="utf-8", errors="strict")
            tree = ast.parse(source, filename=str(file_path))
            lines = source.splitlines()

            analyzer = PythonASTAnalyzer(file_path)
            analyzer.analyze(source)

            # Walk the AST and check each node
            for node in ast.walk(tree):
                node_findings = self.check_ast_node(node, analyzer)
                for finding in node_findings:
                    # Check for inline suppression
                    if hasattr(node, "lineno") and node.lineno <= len(lines):
                        line_content = lines[node.lineno - 1]
                        if self._is_suppressed(line_content, finding.rule_id):
                            continue
                    findings.append(finding)

        except SyntaxError:
            # Invalid Python syntax - fall back to pattern matching
            return super().scan_file(file_path)
        except (OSError, UnicodeDecodeError):
            # File read error - skip
            return []

        return findings

    def _is_suppressed(self, line: str, rule_id: str) -> bool:
        """Check if a line has inline suppression comment."""
        import re

        noqa_pattern = re.compile(r"#\s*noqa:\s*([\w,\s]+)", re.IGNORECASE)
        match = noqa_pattern.search(line)
        if not match:
            return False

        suppressed_rules = [r.strip().upper() for r in match.group(1).split(",")]
        return rule_id in suppressed_rules or "ALL" in suppressed_rules

    def create_finding(
        self,
        node: ast.AST,
        message: str,
        recommendation: str,
        severity: Severity,
        line_content: str,
        confidence: str = "high",
    ) -> Finding:
        """Helper to create a Finding from an AST node."""
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=severity,
            file_path=str(self.file_path) if hasattr(self, "file_path") else "",
            line_number=node.lineno if hasattr(node, "lineno") else 0,
            line_content=line_content,
            message=message,
            recommendation=recommendation,
            owasp_category=self.owasp_category,
            confidence=confidence,
        )


class HybridRule(BaseRule):
    """Base class for rules that use both AST and pattern matching.

    Uses AST for Python files (more accurate) and patterns for other languages.
    """

    def __init__(self) -> None:
        """Initialize hybrid rule."""
        super().__init__()
        self.python_analyzer_class = PythonASTAnalyzer

    def scan_file(self, file_path: Path) -> list[Finding]:
        """Scan using AST for Python, patterns for other files."""
        if not self.should_scan_file(file_path):
            return []

        # Use AST for Python files
        if file_path.suffix == ".py":
            return self._scan_python_file(file_path)

        # Use pattern matching for other files
        return super().scan_file(file_path)

    @abstractmethod
    def _scan_python_file(self, file_path: Path) -> list[Finding]:
        """Scan a Python file using AST analysis.

        Subclasses must implement this method for Python-specific analysis.
        """
        ...

    def _get_ast_findings(
        self,
        file_path: Path,
        check_function: str,
        severity_map: dict[str, Severity],
        message_template: str,
        recommendation: str,
    ) -> list[Finding]:
        """Generic helper to get findings from AST analyzer.

        Args:
            file_path: Path to file
            check_function: Name of function/pattern to check
            severity_map: Map from check result to severity
            message_template: Template for finding message
            recommendation: Recommendation text

        Returns:
            List of findings
        """
        try:
            source = file_path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError):
            return []

        analyzer = self.python_analyzer_class(file_path)
        _, dangerous_calls = analyzer.analyze(source)

        findings = []
        lines = source.splitlines()

        for call_node, line_num, severity_str in dangerous_calls:
            func_name = analyzer._get_function_name(call_node.func)

            if check_function not in func_name:
                continue

            line_content = lines[line_num - 1] if line_num <= len(lines) else ""

            # Check inline suppression
            if "# noqa" in line_content and self.rule_id in line_content:
                continue

            severity = severity_map.get(severity_str, Severity.MEDIUM)
            message = message_template.format(function=func_name)

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=severity,
                    file_path=str(file_path),
                    line_number=line_num,
                    line_content=line_content,
                    message=message,
                    recommendation=recommendation,
                    owasp_category=self.owasp_category,
                    confidence="high",
                )
            )

        return findings
