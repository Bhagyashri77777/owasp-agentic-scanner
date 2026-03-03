"""Tests for constants module."""

from owasp_agentic_scanner.constants import (
    CACHE_LOCK_TIMEOUT_SECONDS,
    CHUNK_SIZE_BYTES,
    CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    CIRCUIT_BREAKER_TIMEOUT_SECONDS,
    DEFAULT_CPU_COUNT,
    DEFAULT_MAX_FILE_SIZE,
    FILE_SCAN_TIMEOUT_SECONDS,
    MAX_FINDINGS_PER_BATCH,
    MAX_GIT_REF_LENGTH,
    MAX_REPETITIVE_CHAR_TYPES,
    MAX_UPPERCASE_PLACEHOLDER_LENGTH,
    MAX_WORKERS_LIMIT,
    MIN_CHARACTER_TYPES,
    MIN_CREDENTIAL_LENGTH,
    MIN_ENTROPY_THRESHOLD,
    MIN_REPETITIVE_LENGTH,
    MIN_SEQUENTIAL_LENGTH,
    SCAN_BATCH_SIZE,
    WORKER_CPU_MULTIPLIER,
)


class TestConstants:
    """Test that constants have sensible values."""

    def test_scanner_constants(self) -> None:
        """Test scanner resource limit constants."""
        assert MAX_FINDINGS_PER_BATCH == 10000
        assert FILE_SCAN_TIMEOUT_SECONDS == 5.0
        assert CIRCUIT_BREAKER_FAILURE_THRESHOLD == 10
        assert CIRCUIT_BREAKER_TIMEOUT_SECONDS == 60
        assert SCAN_BATCH_SIZE == 100
        assert MAX_WORKERS_LIMIT == 32
        assert DEFAULT_CPU_COUNT == 4
        assert WORKER_CPU_MULTIPLIER == 4

    def test_file_processing_constants(self) -> None:
        """Test file processing constants."""
        assert CHUNK_SIZE_BYTES == 65536  # 64KB
        assert DEFAULT_MAX_FILE_SIZE == 10 * 1024 * 1024  # 10MB

    def test_credential_detection_constants(self) -> None:
        """Test credential detection constants."""
        assert MIN_CREDENTIAL_LENGTH == 8
        assert MIN_CHARACTER_TYPES == 2
        assert MIN_ENTROPY_THRESHOLD == 3.0
        assert MAX_REPETITIVE_CHAR_TYPES == 3
        assert MIN_REPETITIVE_LENGTH == 8
        assert MIN_SEQUENTIAL_LENGTH == 8
        assert MAX_UPPERCASE_PLACEHOLDER_LENGTH == 10

    def test_git_validation_constants(self) -> None:
        """Test git validation constants."""
        assert MAX_GIT_REF_LENGTH == 255

    def test_cache_constants(self) -> None:
        """Test cache-related constants."""
        assert CACHE_LOCK_TIMEOUT_SECONDS == 10
