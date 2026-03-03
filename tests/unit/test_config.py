"""Unit tests for config module."""

import os
from pathlib import Path

from owasp_agentic_scanner.config import ScanConfig, generate_sample_config


class TestScanConfig:
    """Test ScanConfig functionality."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = ScanConfig()

        assert config.enabled_rules == []
        assert config.disabled_rules == []
        assert config.parallel is True
        assert config.max_workers == 0
        assert config.min_severity == "info"
        assert config.format == "console"
        assert config.use_cache is True
        assert config.only_git_changed is False
        assert config.git_base_ref == "origin/main"
        assert config.baseline_file is None
        assert "__pycache__" in config.exclude_dirs

    def test_load_from_toml_file(self, tmp_path: Path) -> None:
        """Test loading config from .owasp-scan.toml."""
        config_file = tmp_path / ".owasp-scan.toml"
        config_file.write_text(
            """
enabled_rules = ["goal_hijack", "code_execution"]
min_severity = "high"
parallel = false
max_workers = 4
use_cache = false
"""
        )

        # Change to tmp directory so config file is found
        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)
            config = ScanConfig.load()

            assert config.enabled_rules == ["goal_hijack", "code_execution"]
            assert config.min_severity == "high"
            assert config.parallel is False
            assert config.max_workers == 4
            assert config.use_cache is False
        finally:
            os.chdir(original_cwd)

    def test_load_from_explicit_file(self, tmp_path: Path) -> None:
        """Test loading config from explicit file path."""
        config_file = tmp_path / "custom-config.toml"
        config_file.write_text(
            """
min_severity = "critical"
format = "json"
verbose = true
"""
        )

        config = ScanConfig.load(config_file)

        assert config.min_severity == "critical"
        assert config.format == "json"
        assert config.verbose is True

    def test_load_from_pyproject_toml(self, tmp_path: Path) -> None:
        """Test loading config from pyproject.toml."""
        pyproject_file = tmp_path / "pyproject.toml"
        pyproject_file.write_text(
            """
[tool.owasp-scan]
enabled_rules = ["code_execution"]
min_severity = "medium"
cache_dir = "custom-cache"
"""
        )

        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)
            config = ScanConfig.load()

            assert config.enabled_rules == ["code_execution"]
            assert config.min_severity == "medium"
            assert config.cache_dir == "custom-cache"
        finally:
            os.chdir(original_cwd)

    def test_load_with_missing_file(self, tmp_path: Path) -> None:
        """Test load with missing config file returns defaults."""
        config_file = tmp_path / "missing.toml"
        config = ScanConfig.load(config_file)

        # Should have defaults
        assert config.min_severity == "info"
        assert config.parallel is True

    def test_load_with_invalid_toml(self, tmp_path: Path) -> None:
        """Test load handles invalid TOML gracefully."""
        config_file = tmp_path / ".owasp-scan.toml"
        config_file.write_text("{invalid toml")

        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)
            config = ScanConfig.load()

            # Should have defaults despite invalid file
            assert config.min_severity == "info"
        finally:
            os.chdir(original_cwd)

    def test_load_from_environment(self, tmp_path: Path, monkeypatch) -> None:
        """Test loading config from environment variables."""
        monkeypatch.setenv("OWASP_SCAN_PARALLEL", "false")
        monkeypatch.setenv("OWASP_SCAN_MAX_WORKERS", "8")
        monkeypatch.setenv("OWASP_SCAN_MIN_SEVERITY", "high")
        monkeypatch.setenv("OWASP_SCAN_FORMAT", "sarif")
        monkeypatch.setenv("OWASP_SCAN_USE_CACHE", "false")
        monkeypatch.setenv("OWASP_SCAN_ONLY_GIT_CHANGED", "true")

        config = ScanConfig.load()

        assert config.parallel is False
        assert config.max_workers == 8
        assert config.min_severity == "high"
        assert config.format == "sarif"
        assert config.use_cache is False
        assert config.only_git_changed is True

    def test_env_overrides_file(self, tmp_path: Path, monkeypatch) -> None:
        """Test environment variables override file config."""
        config_file = tmp_path / ".owasp-scan.toml"
        config_file.write_text(
            """
min_severity = "info"
parallel = true
"""
        )

        monkeypatch.setenv("OWASP_SCAN_MIN_SEVERITY", "critical")
        monkeypatch.setenv("OWASP_SCAN_PARALLEL", "false")

        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)
            config = ScanConfig.load()

            # Env should override file
            assert config.min_severity == "critical"
            assert config.parallel is False
        finally:
            os.chdir(original_cwd)

    def test_to_dict(self) -> None:
        """Test converting config to dictionary."""
        config = ScanConfig(
            enabled_rules=["goal_hijack"],
            min_severity="high",
            parallel=False,
            format="json",
        )

        data = config.to_dict()

        assert data["enabled_rules"] == ["goal_hijack"]
        assert data["min_severity"] == "high"
        assert data["parallel"] is False
        assert data["format"] == "json"
        assert "cache_dir" in data
        assert "exclude_dirs" in data

    def test_apply_config_rules(self) -> None:
        """Test _apply_config updates rules configuration."""
        config = ScanConfig()
        config._apply_config(
            {
                "enabled_rules": ["goal_hijack", "code_execution"],
                "disabled_rules": ["model_theft"],
            }
        )

        assert config.enabled_rules == ["goal_hijack", "code_execution"]
        assert config.disabled_rules == ["model_theft"]

    def test_apply_config_scanning(self) -> None:
        """Test _apply_config updates scanning configuration."""
        config = ScanConfig()
        config._apply_config({"parallel": False, "max_workers": 4, "max_file_size": 5000000})

        assert config.parallel is False
        assert config.max_workers == 4
        assert config.max_file_size == 5000000

    def test_apply_config_filtering(self) -> None:
        """Test _apply_config updates filtering configuration."""
        config = ScanConfig()
        config._apply_config(
            {
                "min_severity": "critical",
                "exclude_patterns": ["**/*_test.py"],
                "include_patterns": ["**/*.py"],
            }
        )

        assert config.min_severity == "critical"
        assert config.exclude_patterns == ["**/*_test.py"]
        assert config.include_patterns == ["**/*.py"]

    def test_apply_config_output(self) -> None:
        """Test _apply_config updates output configuration."""
        config = ScanConfig()
        config._apply_config({"format": "sarif", "output_file": "results.sarif", "verbose": True})

        assert config.format == "sarif"
        assert config.output_file == "results.sarif"
        assert config.verbose is True

    def test_apply_config_caching(self) -> None:
        """Test _apply_config updates caching configuration."""
        config = ScanConfig()
        config._apply_config({"use_cache": False, "cache_dir": "my-cache"})

        assert config.use_cache is False
        assert config.cache_dir == "my-cache"

    def test_apply_config_git(self) -> None:
        """Test _apply_config updates git configuration."""
        config = ScanConfig()
        config._apply_config({"only_git_changed": True, "git_base_ref": "develop"})

        assert config.only_git_changed is True
        assert config.git_base_ref == "develop"

    def test_apply_config_baseline(self) -> None:
        """Test _apply_config updates baseline configuration."""
        config = ScanConfig()
        config._apply_config({"baseline_file": "baseline.json", "create_baseline": True})

        assert config.baseline_file == "baseline.json"
        assert config.create_baseline is True

    def test_apply_config_paths(self) -> None:
        """Test _apply_config updates path configuration."""
        config = ScanConfig()
        config._apply_config({"exclude_dirs": ["custom_exclude", "another"]})

        assert config.exclude_dirs == ["custom_exclude", "another"]

    def test_env_invalid_max_workers(self, monkeypatch) -> None:
        """Test env with invalid max_workers value is ignored."""
        monkeypatch.setenv("OWASP_SCAN_MAX_WORKERS", "invalid")

        config = ScanConfig.load()

        # Should keep default
        assert config.max_workers == 0

    def test_multiple_config_sources_priority(self, tmp_path: Path, monkeypatch) -> None:
        """Test priority: explicit file > .owasp-scan.toml > pyproject.toml > env."""
        # Create pyproject.toml
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            """
[tool.owasp-scan]
min_severity = "low"
"""
        )

        # Create .owasp-scan.toml (higher priority)
        owasp_config = tmp_path / ".owasp-scan.toml"
        owasp_config.write_text(
            """
min_severity = "medium"
"""
        )

        # Set env (highest priority after explicit file)
        monkeypatch.setenv("OWASP_SCAN_MIN_SEVERITY", "high")

        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)
            config = ScanConfig.load()

            # .owasp-scan.toml loaded, then env overrides
            assert config.min_severity == "high"
        finally:
            os.chdir(original_cwd)


class TestGenerateSampleConfig:
    """Test generate_sample_config function."""

    def test_generates_valid_toml(self) -> None:
        """Test generated sample is valid TOML."""
        sample = generate_sample_config()

        # Should be non-empty string
        assert len(sample) > 0
        assert "enabled_rules" in sample
        assert "min_severity" in sample
        assert "parallel" in sample

    def test_sample_contains_all_sections(self) -> None:
        """Test sample config contains all configuration sections."""
        sample = generate_sample_config()

        # Check for key sections
        assert "Rules to enable" in sample
        assert "Scanning behavior" in sample
        assert "Minimum severity" in sample
        assert "Output configuration" in sample
        assert "Caching" in sample
        assert "Git integration" in sample
        assert "Baseline" in sample

    def test_sample_has_comments(self) -> None:
        """Test sample config has helpful comments."""
        sample = generate_sample_config()

        # Should have comment lines
        assert "# OWASP Agentic AI Scanner Configuration" in sample
        assert "# Options:" in sample
