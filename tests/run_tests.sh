#!/bin/bash
# Run all tests for the security log analysis system
# Usage: bash tests/run_tests.sh [options]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "========================================"
echo "Security Log Analysis System - Test Suite"
echo "========================================"
echo ""

# Ensure data files exist
for f in final_training_data.csv test_without_type.csv sampled_dataset.csv cleaned_test.csv; do
    if [ ! -f "$f" ]; then
        echo "❌ Missing required data file: $f"
        echo "   Run test data preparation first."
        exit 1
    fi
done
echo "✅ All data files present"
echo ""

# Check embedding model
EMBED_PATH="/root/.cache/modelscope/hub/models/BAAI/bge-large-en-v1.5"
if [ -d "$EMBED_PATH" ]; then
    echo "✅ Embedding model found"
else
    echo "⚠️  Embedding model not found at $EMBED_PATH"
    echo "   Some tests may be skipped"
fi
echo ""

# Run pytest with coverage report
echo "--- Running tests ---"
python3 -m pytest tests/ \
    -v \
    --tb=short \
    --disable-warnings \
    "$@"

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ All tests passed!"
else
    echo "❌ Some tests failed (exit code: $EXIT_CODE)"
fi

exit $EXIT_CODE
