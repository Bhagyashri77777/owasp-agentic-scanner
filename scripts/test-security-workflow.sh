#!/usr/bin/env bash
# Test script for security workflow changes
# This simulates the GitHub Actions security workflow locally

set -e

echo "========================================="
echo "Testing Security Workflow Components"
echo "========================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo -e "${RED}Error: Must run from project root${NC}"
    exit 1
fi

echo "1. Testing OWASP Self-Scan"
echo "-------------------------------------------"

# Run the scanner on src/ with exclusions (like the workflow does)
echo "Running: uv run owasp-scan scan src/ --config .owasp-scan-ci.toml --format sarif --output results.sarif"
uv run owasp-scan scan src/ \
    --config .owasp-scan-ci.toml \
    --format sarif \
    --output results.sarif || true

# Copy results for testing
if [ -f results.sarif ]; then
    cp results.sarif test-results.sarif
fi

# Check results
if [ -f test-results.sarif ]; then
    CRITICAL_COUNT=$(grep -o '"level":"error"' test-results.sarif | wc -l | tr -d ' ')
    echo -e "${YELLOW}Found $CRITICAL_COUNT critical/high severity issues${NC}"

    if [ "$CRITICAL_COUNT" -gt 0 ]; then
        echo -e "${RED}✗ Security scan would fail in CI due to $CRITICAL_COUNT critical/high findings${NC}"
        echo ""
        echo "Issues found (showing console output):"
        # Show a summary of findings
        uv run owasp-scan scan src/ --config .owasp-scan-ci.toml 2>/dev/null || true
    else
        echo -e "${GREEN}✓ No critical/high severity issues found${NC}"
    fi
else
    echo -e "${RED}✗ SARIF file not generated${NC}"
    exit 1
fi

echo ""
echo "2. Testing Dependency Vulnerability Scan"
echo "-------------------------------------------"

# Export requirements
echo "Exporting requirements..."
uv export --no-hashes --format requirements-txt > test-requirements.txt

# Install pip-audit if not already installed
echo "Installing pip-audit..."
uv pip install pip-audit --quiet 2>/dev/null || true

# Run pip-audit
echo "Running: uv run pip-audit --requirement test-requirements.txt"
# Note: pip-audit can fail on certain environments, so we allow it to continue
if uv run pip-audit --desc --requirement test-requirements.txt 2>&1 | tee test-pip-audit-output.txt; then
    echo -e "${GREEN}✓ No vulnerable dependencies found${NC}"
else
    # Check if it's a real vulnerability or just an error
    if grep -q "Found" test-pip-audit-output.txt; then
        echo -e "${YELLOW}⚠ Vulnerabilities detected - see output above${NC}"
    else
        echo -e "${YELLOW}⚠ pip-audit encountered an error (may not work in all environments)${NC}"
    fi
fi

rm -f test-pip-audit-output.txt

echo ""
echo "3. Cleanup"
echo "-------------------------------------------"
rm -f test-results.sarif test-requirements.txt test-pip-audit.json results.sarif
echo -e "${GREEN}✓ Test files cleaned up${NC}"

echo ""
echo "========================================="
echo "Security Workflow Test Complete"
echo "========================================="
