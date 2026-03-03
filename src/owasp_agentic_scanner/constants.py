"""Global constants for OWASP Agentic Scanner.

This module centralizes all magic numbers and configuration values
to improve code maintainability and reduce cognitive complexity.
"""

# Scanner Resource Limits
MAX_FINDINGS_PER_BATCH = 10000
"""Maximum number of findings to collect per batch to prevent memory exhaustion."""

FILE_SCAN_TIMEOUT_SECONDS = 5.0
"""Timeout in seconds for scanning a single file."""

CIRCUIT_BREAKER_FAILURE_THRESHOLD = 10
"""Number of consecutive failures before circuit breaker opens."""

CIRCUIT_BREAKER_TIMEOUT_SECONDS = 60
"""Seconds to wait before attempting to close circuit breaker."""

SCAN_BATCH_SIZE = 100
"""Number of scan tasks to submit in each batch during parallel scanning."""

MAX_WORKERS_LIMIT = 32
"""Maximum number of worker threads allowed for parallel scanning."""

DEFAULT_CPU_COUNT = 4
"""Default CPU count to assume if os.cpu_count() returns None."""

WORKER_CPU_MULTIPLIER = 4
"""Additional workers to add beyond CPU count for I/O-bound operations."""

# File Processing
CHUNK_SIZE_BYTES = 65536  # 64KB
"""Size of chunks for streaming file hash calculation."""

DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
"""Default maximum file size to scan in bytes."""

# Credential Detection
MIN_CREDENTIAL_LENGTH = 8
"""Minimum length for a value to be considered a credential."""

MIN_CHARACTER_TYPES = 2
"""Minimum number of character types (lower, upper, digit, special) for real credentials."""

MIN_ENTROPY_THRESHOLD = 3.0
"""Minimum Shannon entropy for a value to be considered a real credential."""

MAX_REPETITIVE_CHAR_TYPES = 3
"""Maximum unique characters for a string to be considered repetitive."""

MIN_REPETITIVE_LENGTH = 8
"""Minimum length for repetitive character detection."""

MIN_SEQUENTIAL_LENGTH = 8
"""Minimum length for sequential number pattern detection."""

MAX_UPPERCASE_PLACEHOLDER_LENGTH = 10
"""Strings longer than this in all caps are likely placeholders."""

# Git Validation
MAX_GIT_REF_LENGTH = 255
"""Maximum allowed length for git references."""

# Cache
CACHE_LOCK_TIMEOUT_SECONDS = 10
"""Timeout in seconds for acquiring cache batch update lock."""
