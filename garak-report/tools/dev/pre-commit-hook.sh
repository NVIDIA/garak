#!/bin/bash
#
# Standalone pre-commit hook for garak-report
#
# RECOMMENDED: Add hooks to .pre-commit-config.yaml instead (see README.md)
#
# Alternative (standalone, may interfere with other hooks):
#   ln -sf ../../garak-report/tools/dev/pre-commit-hook.sh .git/hooks/pre-commit
#
# To disable:
#   rm .git/hooks/pre-commit
#

set -e

cd "$(git rev-parse --show-toplevel)/garak-report"

echo "🔍 Running pre-commit checks..."

# Check if there are staged files in garak-report
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep "^garak-report/.*\.\(ts\|tsx\)$" || true)

if [ -n "$STAGED_FILES" ]; then
    echo "📝 Linting staged files..."
    yarn lint --max-warnings=0
    
    echo "✨ Checking formatting..."
    yarn format --check
fi

echo "🔎 Type checking..."
yarn check

echo "🧪 Running tests..."
yarn test

echo "✅ All checks passed!"
