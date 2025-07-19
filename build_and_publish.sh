#!/bin/bash
# Build and publish pilfer to PyPI
# Usage: ./build_and_publish.sh [test|prod]

set -e

TARGET="${1:-test}"

echo "🏗️  Building pilfer package..."

# Clean previous builds
rm -rf build/ dist/ *.egg-info/

# Build the package
python -m build

echo "📦 Package built successfully!"

if [ "$TARGET" = "test" ]; then
    echo "🧪 Publishing to TestPyPI..."
    python -m twine upload --repository testpypi dist/*
    echo "✅ Published to TestPyPI!"
    echo "🔗 View at: https://test.pypi.org/project/pilfer/"
    echo ""
    echo "To install from TestPyPI:"
    echo "pip install --index-url https://test.pypi.org/simple/ pilfer"
elif [ "$TARGET" = "prod" ]; then
    echo "🚀 Publishing to PyPI..."
    python -m twine upload dist/*
    echo "✅ Published to PyPI!"
    echo "🔗 View at: https://pypi.org/project/pilfer/"
    echo ""
    echo "To install:"
    echo "pipx install pilfer"
else
    echo "❓ Unknown target: $TARGET"
    echo "Usage: $0 [test|prod]"
    exit 1
fi

echo ""
echo "📋 Next steps:"
echo "1. Test the installation: pipx install pilfer"
echo "2. Verify functionality: pilfer --help"
echo "3. Update version in pyproject.toml for next release" 
