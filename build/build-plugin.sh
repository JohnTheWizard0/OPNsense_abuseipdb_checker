#!/bin/sh

set -e

# Configuration
PLUGIN_NAME="abuseipdbchecker"
PLUGIN_VERSION="${1:-$(date +%Y.%m.%d)}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="/tmp/opnsense-plugin-build"
PACKAGES_DIR="${REPO_ROOT}/packages"

echo "=========================================="
echo "Building os-${PLUGIN_NAME} v${PLUGIN_VERSION}"
echo "=========================================="

# Clean build environment
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/usr/local"
mkdir -p "${PACKAGES_DIR}"

# Step 1: Copy all plugin files
echo "Copying plugin files..."
if [ -d "${REPO_ROOT}/src/opnsense" ]; then
    cp -r "${REPO_ROOT}/src/opnsense" "${BUILD_DIR}/usr/local/"
    echo "✓ Copied MVC framework files"
fi

if [ -d "${REPO_ROOT}/src/etc" ]; then
    mkdir -p "${BUILD_DIR}/usr/local/etc"
    cp -r "${REPO_ROOT}/src/etc"/* "${BUILD_DIR}/usr/local/etc/"
    echo "✓ Copied configuration files"
fi

if [ -d "${REPO_ROOT}/src/www" ]; then
    mkdir -p "${BUILD_DIR}/usr/local/www"
    cp -r "${REPO_ROOT}/src/www"/* "${BUILD_DIR}/usr/local/www/"
    echo "✓ Copied web assets"
fi

# Step 2: Set proper permissions
echo "Setting file permissions..."
find "${BUILD_DIR}" -type f -name "*.php" -exec chmod 644 {} \;
find "${BUILD_DIR}" -type f -name "*.py" -exec chmod 755 {} \;
find "${BUILD_DIR}" -type f -name "*.sh" -exec chmod 755 {} \;
find "${BUILD_DIR}" -type d -exec chmod 755 {} \;

# Step 3: Generate file manifest
echo "Generating file manifest..."
cd "${BUILD_DIR}"
python3 "${REPO_ROOT}/build/generate-manifest.py" \
    --name "os-${PLUGIN_NAME}" \
    --version "${PLUGIN_VERSION}" \
    --build-dir "${BUILD_DIR}" \
    --output "${BUILD_DIR}/+MANIFEST"

# Step 4: Create package
echo "Creating package..."
pkg create -M "${BUILD_DIR}/+MANIFEST" -r "${BUILD_DIR}" -o "${PACKAGES_DIR}/"

# Step 5: Update repository metadata
echo "Updating repository..."
cd "${PACKAGES_DIR}"

# Use existing meta.conf or create if missing
if [ ! -f "meta.conf" ]; then
    echo "Creating meta.conf..."
    cat > meta.conf << 'EOF'
version = 2;
packing_format = "txz";
manifests = "packagesite.yaml";
filesite = "filesite.yaml";
manifests_archive = "packagesite";
filesite_archive = "filesite";
EOF
fi

# Generate repository with verbose output
echo "Generating repository metadata..."
pkg repo . || {
    echo "❌ pkg repo command failed"
    ls -la
    exit 1
}

# List generated files for debugging
echo "Repository files generated:"
ls -la *.pkg *.yaml 2>/dev/null || true

# More lenient verification - check for any repository files
if [ -f "packagesite.yaml" ] || [ -f "packagesite.pkg" ]; then
    echo "✓ Repository metadata generated successfully"
else
    echo "❌ Repository generation failed - no metadata files found"
    echo "Directory contents:"
    ls -la
    exit 1
fi

# Step 6: Generate installation stats
PACKAGE_FILE="${PACKAGES_DIR}/os-${PLUGIN_NAME}-${PLUGIN_VERSION}.pkg"
if [ -f "${PACKAGE_FILE}" ]; then
    PACKAGE_SIZE=$(du -h "${PACKAGE_FILE}" | cut -f1)
    echo "=========================================="
    echo "✓ Build completed successfully!"
    echo "Package: os-${PLUGIN_NAME}-${PLUGIN_VERSION}.pkg"
    echo "Size: ${PACKAGE_SIZE}"
    echo "Location: ${PACKAGE_FILE}"
    echo "=========================================="
else
    echo "❌ Build failed - package not created"
    exit 1
fi