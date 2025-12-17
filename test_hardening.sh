#!/bin/bash

# Test script to verify hardening.sh can find its dependencies
echo "Testing hardening.sh dependencies..."

# Check if ubuntu.cfg exists
if [ -f "./ubuntu.cfg" ]; then
    echo "✓ ubuntu.cfg found"
else
    echo "✗ ubuntu.cfg not found"
fi

# Check if scripts directory exists
if [ -d "./scripts" ]; then
    echo "✓ scripts directory found"
    echo "  Scripts count: $(ls -1 ./scripts | wc -l)"
else
    echo "✗ scripts directory not found"
fi

# Check if misc directory exists
if [ -d "./misc" ]; then
    echo "✓ misc directory found"
else
    echo "✗ misc directory not found"
fi

# Test sourcing ubuntu.cfg
if source ./ubuntu.cfg 2>/dev/null; then
    echo "✓ ubuntu.cfg can be sourced"
    echo "  CHANGEME value: '$CHANGEME'"
else
    echo "✗ ubuntu.cfg cannot be sourced"
fi

echo "Current working directory: $(pwd)"
echo "Script location: $(dirname "${BASH_SOURCE[0]}")"