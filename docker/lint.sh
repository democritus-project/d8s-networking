#!/usr/bin/env bash

set -euxo pipefail

echo "Running linters and formatters..."

isort democritus_networking/ tests/

black democritus_networking/ tests/

mypy democritus_networking/ tests/

pylint --fail-under 9 democritus_networking/*.py

flake8 democritus_networking/ tests/

bandit -r democritus_networking/

# we run black again at the end to undo any odd changes made by any of the linters above
black democritus_networking/ tests/
