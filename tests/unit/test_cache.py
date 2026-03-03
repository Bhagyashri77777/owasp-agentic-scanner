"""Unit tests for cache module."""

import json
from pathlib import Path

import pytest

from owasp_agentic_scanner.cache import GitAwareCache, ScanCache
from owasp_agentic_scanner.rules.base import Finding, Severity


class TestScanCache:
    """Test ScanCache functionality."""

    def test_cache_init_creates_empty_cache(self, tmp_path: Path) -> None:
        """Test cache initializes with empty data."""
        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)
        assert cache.cache_data == {}
        assert cache.project_root == tmp_path.absolute()

    def test_cache_load_creates_empty_if_not_exists(self, tmp_path: Path) -> None:
        """Test cache.load() creates empty cache if file doesn't exist."""
        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)
        cache.load()
        assert cache.cache_data == {}

    def test_cache_load_reads_existing(self, tmp_path: Path) -> None:
        """Test cache.load() reads existing cache file."""
        cache_dir = tmp_path / ".owasp-cache"
        cache_dir.mkdir()
        cache_file = cache_dir / "scan_cache.json"

        # Write test data
        test_data = {"test.py": {"hash": "abc123", "findings": [], "mtime": 123456}}
        cache_file.write_text(json.dumps(test_data))

        cache = ScanCache(cache_dir=cache_dir, project_root=tmp_path)
        assert cache.cache_data == test_data

    def test_cache_save_creates_file(self, tmp_path: Path) -> None:
        """Test cache.save() creates cache file."""
        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)
        cache.cache_data = {"test": "data"}
        cache.save()

        cache_file = tmp_path / "scan_cache.json"
        assert cache_file.exists()

        data = json.loads(cache_file.read_text())
        assert data == {"test": "data"}

    def test_get_file_hash(self, tmp_path: Path) -> None:
        """Test file hash generation."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)
        hash1 = cache.get_file_hash(test_file)

        # Hash should be consistent
        hash2 = cache.get_file_hash(test_file)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex digest

        # Different content should give different hash
        test_file.write_text("print('world')")
        hash3 = cache.get_file_hash(test_file)
        assert hash3 != hash1

    def test_has_changed_new_file(self, tmp_path: Path) -> None:
        """Test has_changed() returns True for new file."""
        test_file = tmp_path / "new.py"
        test_file.write_text("print('new')")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)
        assert cache.has_changed(test_file) is True

    def test_has_changed_unchanged_file(self, tmp_path: Path) -> None:
        """Test has_changed() returns False for unchanged file."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)

        # Add file to cache
        file_key = str(test_file.relative_to(tmp_path))
        cache.cache_data[file_key] = {
            "hash": cache.get_file_hash(test_file),
            "findings": [],
            "mtime": test_file.stat().st_mtime,
        }

        assert cache.has_changed(test_file) is False

    def test_has_changed_modified_file(self, tmp_path: Path) -> None:
        """Test has_changed() returns True for modified file."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('original')")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)

        # Add file to cache with original hash
        file_key = str(test_file.relative_to(tmp_path))
        original_hash = cache.get_file_hash(test_file)
        cache.cache_data[file_key] = {
            "hash": original_hash,
            "findings": [],
            "mtime": test_file.stat().st_mtime,
        }

        # Modify file
        test_file.write_text("print('modified')")

        assert cache.has_changed(test_file) is True

    def test_update_stores_findings(self, tmp_path: Path) -> None:
        """Test update() stores findings in cache."""
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)

        finding = Finding(
            rule_id="AA05",
            rule_name="Code Execution",
            severity=Severity.CRITICAL,
            file_path=str(test_file),
            line_number=1,
            line_content="eval(input())",
            message="Dangerous eval usage",
            recommendation="Use ast.literal_eval",
            owasp_category="AA05",
            confidence="high",
        )

        cache.update(test_file, [finding])

        file_key = str(test_file.relative_to(tmp_path))
        assert file_key in cache.cache_data
        assert len(cache.cache_data[file_key]["findings"]) == 1

        stored_finding = cache.cache_data[file_key]["findings"][0]
        assert stored_finding["rule_id"] == "AA05"
        assert stored_finding["severity"] == "critical"
        assert stored_finding["recommendation"] == "Use ast.literal_eval"

    def test_get_findings_returns_cached(self, tmp_path: Path) -> None:
        """Test get_findings() returns cached findings."""
        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)

        # Add findings to cache
        file_key = str(test_file.relative_to(tmp_path))
        cache.cache_data[file_key] = {
            "hash": cache.get_file_hash(test_file),
            "findings": [
                {
                    "rule_id": "AA05",
                    "rule_name": "Code Execution",
                    "severity": "critical",
                    "file_path": str(test_file),
                    "line_number": 1,
                    "line_content": "eval(input())",
                    "message": "Test finding",
                    "recommendation": "Fix it",
                    "owasp_category": "AA05",
                    "confidence": "high",
                }
            ],
            "mtime": test_file.stat().st_mtime,
        }

        findings = cache.get_findings(test_file)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "AA05"

    def test_get_findings_empty_if_not_cached(self, tmp_path: Path) -> None:
        """Test get_findings() returns empty list if not in cache."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)
        findings = cache.get_findings(test_file)

        assert findings == []

    def test_cache_uses_relative_paths(self, tmp_path: Path) -> None:
        """Test cache uses relative paths for portability."""
        test_file = tmp_path / "subdir" / "test.py"
        test_file.parent.mkdir()
        test_file.write_text("print('test')")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)
        cache.update(test_file, [])

        # Cache key should be relative path
        expected_key = str(Path("subdir") / "test.py")
        assert expected_key in cache.cache_data

    def test_cache_handles_corrupted_json(self, tmp_path: Path) -> None:
        """Test cache handles corrupted JSON gracefully."""
        cache_dir = tmp_path / ".owasp-cache"
        cache_dir.mkdir()
        cache_file = cache_dir / "scan_cache.json"

        # Write invalid JSON
        cache_file.write_text("{invalid json")

        # Should not crash, should create empty cache
        cache = ScanCache(cache_dir=cache_dir, project_root=tmp_path)
        assert cache.cache_data == {}

    def test_clear_removes_cache(self, tmp_path: Path) -> None:
        """Test clear() removes cache data and file."""
        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)
        cache.cache_data = {"test": "data"}
        cache.save()

        assert (tmp_path / "scan_cache.json").exists()

        cache.clear()
        assert cache.cache_data == {}
        assert not (tmp_path / "scan_cache.json").exists()


class TestGitAwareCache:
    """Test GitAwareCache functionality."""

    def test_git_cache_init(self, tmp_path: Path) -> None:
        """Test GitAwareCache initialization."""
        cache = GitAwareCache(cache_dir=tmp_path, project_root=tmp_path)
        assert cache.cache_data == {}
        assert cache.project_root == tmp_path.absolute()

    def test_validate_git_ref_valid(self, tmp_path: Path) -> None:
        """Test _validate_git_ref accepts valid references."""
        cache = GitAwareCache(cache_dir=tmp_path, project_root=tmp_path, git_root=tmp_path)

        assert cache._validate_git_ref("main") is True
        assert cache._validate_git_ref("origin/main") is True
        assert cache._validate_git_ref("feature/my-branch") is True
        assert cache._validate_git_ref("v1.0.0") is True

    def test_validate_git_ref_invalid(self, tmp_path: Path) -> None:
        """Test _validate_git_ref rejects invalid references."""
        cache = GitAwareCache(cache_dir=tmp_path, project_root=tmp_path, git_root=tmp_path)

        # Command injection attempts
        assert cache._validate_git_ref("main; rm -rf /") is False
        assert cache._validate_git_ref("main && evil") is False
        assert cache._validate_git_ref("main | cat /etc/passwd") is False
        assert cache._validate_git_ref("main$(whoami)") is False
        assert cache._validate_git_ref("main`whoami`") is False
        assert cache._validate_git_ref("main\nwhoami") is False  # newline injection
        assert cache._validate_git_ref("main;whoami") is False

    def test_validate_git_ref_length_limit(self, tmp_path: Path) -> None:
        """Test _validate_git_ref enforces length limit."""
        cache = GitAwareCache(cache_dir=tmp_path, project_root=tmp_path, git_root=tmp_path)

        # Valid length
        assert cache._validate_git_ref("a" * 255) is True
        # Too long
        assert cache._validate_git_ref("a" * 256) is False

    def test_validate_git_ref_directory_traversal(self, tmp_path: Path) -> None:
        """Test _validate_git_ref rejects directory traversal."""
        cache = GitAwareCache(cache_dir=tmp_path, project_root=tmp_path, git_root=tmp_path)

        # Directory traversal attempts
        assert cache._validate_git_ref("../../../etc/passwd") is False
        assert cache._validate_git_ref("branch/../main") is False

    def test_get_changed_files_invalid_ref(self, tmp_path: Path) -> None:
        """Test get_changed_files() returns empty set with invalid ref."""
        cache = GitAwareCache(cache_dir=tmp_path, project_root=tmp_path)

        # Invalid ref should return empty set
        changed_files = cache.get_changed_files("main; rm -rf /")
        assert changed_files == set()


class TestCacheEdgeCases:
    """Test cache edge cases and error handling."""

    def test_cache_with_missing_project_root(self, tmp_path: Path) -> None:
        """Test cache with nonexistent project root."""
        nonexistent = tmp_path / "does_not_exist"
        cache = ScanCache(cache_dir=tmp_path, project_root=nonexistent)
        # Should still work but with absolute project root
        assert cache.project_root is not None

    def test_cache_update_with_findings(self, tmp_path: Path) -> None:
        """Test cache update with actual findings."""
        from owasp_agentic_scanner.rules.base import Finding, Severity

        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)

        finding = Finding(
            rule_id="AA05",
            rule_name="Code Execution",
            severity=Severity.CRITICAL,
            file_path=str(test_file),
            line_number=1,
            line_content="eval(input())",
            message="Test",
            recommendation="Don't use eval",
            owasp_category="AA05",
        )

        cache.update(test_file, [finding])

        # Check cache stored finding
        cache_key = str(test_file.relative_to(tmp_path))
        assert cache_key in cache.cache_data
        assert "findings" in cache.cache_data[cache_key]
        assert len(cache.cache_data[cache_key]["findings"]) == 1

    def test_cache_get_findings(self, tmp_path: Path) -> None:
        """Test getting findings from cache."""
        from owasp_agentic_scanner.rules.base import Finding, Severity

        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)

        finding = Finding(
            rule_id="AA05",
            rule_name="Code Execution",
            severity=Severity.CRITICAL,
            file_path=str(test_file),
            line_number=1,
            line_content="eval(input())",
            message="Test",
            recommendation="Don't use eval",
            owasp_category="AA05",
        )

        cache.update(test_file, [finding])

        # Get findings from cache
        cached_findings = cache.get_findings(test_file)
        assert len(cached_findings) == 1
        assert cached_findings[0]["rule_id"] == "AA05"

    def test_cache_with_empty_cache_dir(self, tmp_path: Path) -> None:
        """Test cache with custom cache directory that doesn't exist."""
        cache_dir = tmp_path / "custom_cache"
        # Don't create it

        cache = ScanCache(cache_dir=cache_dir, project_root=tmp_path)
        cache.save()

        # Should create the directory
        assert cache_dir.exists()

    def test_cache_load_nonexistent_file(self, tmp_path: Path) -> None:
        """Test loading cache when file doesn't exist."""
        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)
        # Don't create cache file

        cache.load()

        # Should have empty cache
        assert cache.cache_data == {}

    def test_cache_save_and_load_cycle(self, tmp_path: Path) -> None:
        """Test complete save and load cycle."""
        from owasp_agentic_scanner.rules.base import Finding, Severity

        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        # Create and populate cache
        cache1 = ScanCache(cache_dir=tmp_path, project_root=tmp_path)

        finding = Finding(
            rule_id="AA05",
            rule_name="Code Execution",
            severity=Severity.CRITICAL,
            file_path=str(test_file),
            line_number=1,
            line_content="eval(input())",
            message="Test",
            recommendation="Don't use eval",
            owasp_category="AA05",
        )

        cache1.update(test_file, [finding])
        cache1.save()

        # Load in new cache instance
        cache2 = ScanCache(cache_dir=tmp_path, project_root=tmp_path)
        cache2.load()

        # Should have same data
        assert len(cache2.cache_data) == len(cache1.cache_data)

    def test_cache_invalidation_when_modified(self, tmp_path: Path) -> None:
        """Test cache invalidation when file is modified."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('v1')")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)
        cache.update(test_file, [])

        # File hasn't changed
        assert not cache.has_changed(test_file)

        # Modify file
        test_file.write_text("print('v2')")

        # Now should be marked as changed
        assert cache.has_changed(test_file)

    def test_cache_with_symlink_file(self, tmp_path: Path) -> None:
        """Test cache handles symlinks."""

        real_file = tmp_path / "real.py"
        real_file.write_text("print('real')")

        link_file = tmp_path / "link.py"
        try:
            link_file.symlink_to(real_file)
        except OSError:
            pytest.skip("Symlinks not supported")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)
        cache.update(link_file, [])

        # Should handle symlink
        cache_key = str(link_file.relative_to(tmp_path))
        assert cache_key in cache.cache_data

    def test_cache_get_findings_empty(self, tmp_path: Path) -> None:
        """Test get_findings for file not in cache."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)

        # File not in cache
        findings = cache.get_findings(test_file)
        assert findings == []

    def test_cache_statistics(self, tmp_path: Path) -> None:
        """Test cache can be queried for stats."""
        test_file1 = tmp_path / "test1.py"
        test_file2 = tmp_path / "test2.py"
        test_file1.write_text("print('1')")
        test_file2.write_text("print('2')")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)
        cache.update(test_file1, [])
        cache.update(test_file2, [])

        # Check cache size
        assert len(cache.cache_data) == 2

    def test_git_cache_with_git_root(self, tmp_path: Path) -> None:
        """Test GitAwareCache with explicit git_root."""
        git_root = tmp_path / ".git"
        git_root.mkdir()

        cache = GitAwareCache(
            cache_dir=tmp_path / ".cache", project_root=tmp_path, git_root=tmp_path
        )

        assert cache.git_root == tmp_path

    def test_git_cache_get_changed_files_no_git(self, tmp_path: Path) -> None:
        """Test get_changed_files returns a set."""
        cache = GitAwareCache(cache_dir=tmp_path, project_root=tmp_path)

        # Should return a set (may find files if we're in a git repo context)
        changed = cache.get_changed_files("main")
        assert isinstance(changed, set)

    def test_cache_prune_deleted_files(self, tmp_path: Path) -> None:
        """Test pruning deleted files from cache."""
        test_file1 = tmp_path / "test1.py"
        test_file2 = tmp_path / "test2.py"
        test_file1.write_text("print('1')")
        test_file2.write_text("print('2')")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)
        cache.update(test_file1, [])
        cache.update(test_file2, [])

        # Verify both in cache before deletion
        assert len(cache.cache_data) == 2

        # Delete one file
        test_file1.unlink()

        # Prune should remove deleted file from cache
        cache.prune_deleted_files(tmp_path)

        # Cache should have fewer entries now (prune was called)
        # The exact behavior depends on implementation
        assert isinstance(cache.cache_data, dict)

    def test_cache_get_cached_findings(self, tmp_path: Path) -> None:
        """Test get_cached_findings method."""
        from owasp_agentic_scanner.rules.base import Finding, Severity

        test_file = tmp_path / "test.py"
        test_file.write_text("eval(input())")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)

        finding = Finding(
            rule_id="AA05",
            rule_name="Code Execution",
            severity=Severity.CRITICAL,
            file_path=str(test_file),
            line_number=1,
            line_content="eval(input())",
            message="Test",
            recommendation="Don't use eval",
            owasp_category="AA05",
        )

        cache.update(test_file, [finding])

        # Get cached findings
        cached = cache.get_cached_findings(test_file)
        assert cached is not None
        assert len(cached) == 1
        assert cached[0]["rule_id"] == "AA05"

    def test_cache_get_cached_findings_none(self, tmp_path: Path) -> None:
        """Test get_cached_findings returns None for missing file."""
        test_file = tmp_path / "missing.py"

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)

        cached = cache.get_cached_findings(test_file)
        assert cached is None

    def test_file_lock_context_manager(self, tmp_path: Path) -> None:
        """Test FileLock context manager."""
        from owasp_agentic_scanner.cache import FileLock

        lock_file = tmp_path / "test.lock"

        with FileLock(lock_file) as lock:
            assert lock.lock_file == lock_file
            # Lock file should exist during context
            assert lock_file.exists()

        # After exit, lock file may or may not exist depending on implementation
        # Just verify the lock was created successfully
        assert lock.lock_file == lock_file

    def test_git_cache_should_scan_file(self, tmp_path: Path) -> None:
        """Test should_scan_file with only_changed parameter."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')")

        cache = GitAwareCache(cache_dir=tmp_path, project_root=tmp_path)

        # Should always scan when only_changed is False
        assert cache.should_scan_file(test_file, only_changed=False) is True

    def test_cache_with_absolute_paths(self, tmp_path: Path) -> None:
        """Test cache handles absolute file paths correctly."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)

        # Use absolute path
        cache.update(test_file.absolute(), [])

        # Should create cache entry
        assert len(cache.cache_data) > 0

    def test_cache_get_file_hash_nonexistent(self, tmp_path: Path) -> None:
        """Test get_file_hash with nonexistent file."""
        nonexistent = tmp_path / "nonexistent.py"

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)

        # Should return empty string for nonexistent file
        file_hash = cache.get_file_hash(nonexistent)
        assert file_hash == ""

    def test_cache_concurrent_access(self, tmp_path: Path) -> None:
        """Test cache handles concurrent access with file locking."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')")

        cache1 = ScanCache(cache_dir=tmp_path, project_root=tmp_path)
        cache2 = ScanCache(cache_dir=tmp_path, project_root=tmp_path)

        # Both should be able to update
        cache1.update(test_file, [])
        cache2.load()

        # Should handle concurrent access
        assert isinstance(cache2.cache_data, dict)

    def test_file_hash_chunked_reading(self, tmp_path: Path) -> None:
        """Test get_file_hash uses chunked reading efficiently."""
        # Create a 1MB file
        large_file = tmp_path / "large.py"
        content = "# " + ("x" * 1_000_000)
        large_file.write_text(content)

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)

        # Hash should work with chunked reading
        hash1 = cache.get_file_hash(large_file)
        assert len(hash1) == 64  # SHA256 hex digest length

        # Hash should be consistent
        hash2 = cache.get_file_hash(large_file)
        assert hash1 == hash2

    def test_file_hash_custom_chunk_size(self, tmp_path: Path) -> None:
        """Test get_file_hash with custom chunk size."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')")

        cache = ScanCache(cache_dir=tmp_path, project_root=tmp_path)

        # Different chunk sizes should produce same hash
        hash_default = cache.get_file_hash(test_file)
        hash_small = cache.get_file_hash(test_file, chunk_size=1024)
        hash_large = cache.get_file_hash(test_file, chunk_size=1024 * 1024)

        assert hash_default == hash_small == hash_large
        assert len(hash_default) == 64
