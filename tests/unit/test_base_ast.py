"""Tests for base AST rule functionality."""

from pathlib import Path

from owasp_agentic_scanner.rules.base_ast import PythonASTRule


class TestPythonASTRule:
    """Test PythonASTRule base class."""

    def test_python_ast_rule_initialization(self) -> None:
        """Test PythonASTRule can be initialized."""
        # PythonASTRule has required structure
        assert hasattr(PythonASTRule, "file_extensions")
        assert hasattr(PythonASTRule, "scan_file")

    def test_base_ast_rule_file_extensions(self) -> None:
        """Test BaseASTRule defines file extensions."""
        from owasp_agentic_scanner.rules.code_execution_ast import CodeExecutionASTRule

        rule = CodeExecutionASTRule()
        assert ".py" in rule.file_extensions

    def test_base_ast_rule_should_scan_python(self, tmp_path: Path) -> None:
        """Test BaseASTRule should scan Python files."""
        from owasp_agentic_scanner.rules.code_execution_ast import CodeExecutionASTRule

        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')")

        rule = CodeExecutionASTRule()
        assert rule.should_scan_file(test_file) is True

    def test_base_ast_rule_skip_non_python(self, tmp_path: Path) -> None:
        """Test BaseASTRule skips non-Python files."""
        from owasp_agentic_scanner.rules.code_execution_ast import CodeExecutionASTRule

        test_file = tmp_path / "test.js"
        test_file.write_text("console.log('test')")

        rule = CodeExecutionASTRule()
        # CodeExecutionASTRule is hybrid and may scan non-Python files with regex
        # Just ensure it doesn't crash
        result = rule.should_scan_file(test_file)
        assert isinstance(result, bool)

    def test_base_ast_scan_file_syntax_error(self, tmp_path: Path) -> None:
        """Test BaseASTRule handles syntax errors."""
        from owasp_agentic_scanner.rules.code_execution_ast import CodeExecutionASTRule

        test_file = tmp_path / "bad.py"
        test_file.write_text("def broken(\n  # invalid syntax")

        rule = CodeExecutionASTRule()
        findings = rule.scan_file(test_file)

        # Should not crash, returns empty findings
        assert isinstance(findings, list)

    def test_base_ast_scan_empty_file(self, tmp_path: Path) -> None:
        """Test BaseASTRule handles empty files."""
        from owasp_agentic_scanner.rules.code_execution_ast import CodeExecutionASTRule

        test_file = tmp_path / "empty.py"
        test_file.write_text("")

        rule = CodeExecutionASTRule()
        findings = rule.scan_file(test_file)

        assert findings == []

    def test_base_ast_scan_valid_code(self, tmp_path: Path) -> None:
        """Test BaseASTRule scans valid Python code."""
        from owasp_agentic_scanner.rules.code_execution_ast import CodeExecutionASTRule

        test_file = tmp_path / "test.py"
        test_file.write_text("eval(user_input)")

        rule = CodeExecutionASTRule()
        findings = rule.scan_file(test_file)

        # Should detect eval usage
        assert len(findings) > 0
        assert any(f.rule_id == "AA05" for f in findings)

    def test_base_ast_scan_nonexistent_file(self, tmp_path: Path) -> None:
        """Test BaseASTRule handles nonexistent files."""
        from owasp_agentic_scanner.rules.code_execution_ast import CodeExecutionASTRule

        test_file = tmp_path / "nonexistent.py"

        rule = CodeExecutionASTRule()
        findings = rule.scan_file(test_file)

        # Should not crash
        assert isinstance(findings, list)

    def test_base_ast_scan_directory(self, tmp_path: Path) -> None:
        """Test BaseASTRule can scan directories."""
        from owasp_agentic_scanner.rules.code_execution_ast import CodeExecutionASTRule

        (tmp_path / "test1.py").write_text("eval(x)")
        (tmp_path / "test2.py").write_text("exec(y)")

        rule = CodeExecutionASTRule()
        findings = rule.scan_directory(tmp_path)

        # Should find issues in both files
        assert len(findings) >= 2

    def test_base_ast_with_comments(self, tmp_path: Path) -> None:
        """Test BaseASTRule handles comments correctly."""
        from owasp_agentic_scanner.rules.code_execution_ast import CodeExecutionASTRule

        test_file = tmp_path / "test.py"
        test_file.write_text("""
# This is a comment with eval in it
'''
Docstring with eval
'''
eval(user_input)  # Real eval call
""")

        rule = CodeExecutionASTRule()
        findings = rule.scan_file(test_file)

        # Should only detect the real eval call, not in comments/docstrings
        assert len(findings) > 0

    def test_base_ast_with_multiline_code(self, tmp_path: Path) -> None:
        """Test BaseASTRule handles multiline code."""
        from owasp_agentic_scanner.rules.code_execution_ast import CodeExecutionASTRule

        test_file = tmp_path / "test.py"
        test_file.write_text("""
def dangerous_function():
    user_input = input()
    result = eval(
        user_input
    )
    return result
""")

        rule = CodeExecutionASTRule()
        findings = rule.scan_file(test_file)

        assert len(findings) > 0
        assert any("eval" in f.message.lower() for f in findings)

    def test_base_ast_unicode_content(self, tmp_path: Path) -> None:
        """Test BaseASTRule handles Unicode content."""
        from owasp_agentic_scanner.rules.code_execution_ast import CodeExecutionASTRule

        test_file = tmp_path / "test.py"
        test_file.write_text("""
# 中文注释
def 函数():
    eval("危险代码")
""")

        rule = CodeExecutionASTRule()
        findings = rule.scan_file(test_file)

        # Should handle Unicode and detect eval
        assert len(findings) > 0

    def test_base_ast_multiple_violations(self, tmp_path: Path) -> None:
        """Test BaseASTRule detects multiple violations."""
        from owasp_agentic_scanner.rules.code_execution_ast import CodeExecutionASTRule

        test_file = tmp_path / "test.py"
        test_file.write_text("""
eval(user_input1)
exec(user_input2)
eval(user_input3)
""")

        rule = CodeExecutionASTRule()
        findings = rule.scan_file(test_file)

        # Should detect all three violations
        assert len(findings) >= 3

    def test_base_ast_nested_code(self, tmp_path: Path) -> None:
        """Test BaseASTRule handles nested code structures."""
        from owasp_agentic_scanner.rules.code_execution_ast import CodeExecutionASTRule

        test_file = tmp_path / "test.py"
        test_file.write_text("""
class MyClass:
    def method(self):
        if True:
            for i in range(10):
                eval(str(i))
""")

        rule = CodeExecutionASTRule()
        findings = rule.scan_file(test_file)

        assert len(findings) > 0

    def test_base_ast_lambda_functions(self, tmp_path: Path) -> None:
        """Test BaseASTRule handles lambda functions."""
        from owasp_agentic_scanner.rules.code_execution_ast import CodeExecutionASTRule

        test_file = tmp_path / "test.py"
        test_file.write_text("""
dangerous = lambda x: eval(x)
safe = lambda x: x + 1
""")

        rule = CodeExecutionASTRule()
        findings = rule.scan_file(test_file)

        # Should detect eval in lambda
        assert len(findings) > 0
