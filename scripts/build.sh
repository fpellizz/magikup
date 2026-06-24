#!/bin/bash
# Build Docker image for MagikUp
set -e

# Colors
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
NC=$'\033[0m'

# Configuration (overridable via environment)
IMAGE_NAME="${IMAGE_NAME:-magikup}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REGISTRY="${REGISTRY:-}"
PUSH="${PUSH:-false}"
PLATFORM="${PLATFORM:-linux/amd64}"

# Get script/project directories
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# ─── Help ────────────────────────────────────────────────────────────
usage() {
    cat <<EOF

${BOLD}MagikUp — Docker Image Build Script${NC}

${CYAN}Usage:${NC}
  $0 [OPTIONS]

${CYAN}Options:${NC}
  ${GREEN}-n, --name${NC} NAME       Image name (default: ${BOLD}magikup${NC})
  ${GREEN}-t, --tag${NC} TAG         Image tag (default: ${BOLD}latest${NC})
  ${GREEN}-r, --registry${NC} URL    Container registry URL (e.g. myregistry.io/myproject)
  ${GREEN}-p, --push${NC}            Push image to registry after build
  ${GREEN}    --platform${NC} ARCH   Target platform (default: ${BOLD}linux/amd64${NC})
  ${GREEN}-h, --help${NC}            Show this help message

${CYAN}Environment variables:${NC}
  IMAGE_NAME    Same as --name
  IMAGE_TAG     Same as --tag
  REGISTRY      Same as --registry
  PUSH=true     Same as --push
  PLATFORM      Same as --platform

${CYAN}Examples:${NC}
  ${YELLOW}# Build local image with default name (magikup:latest)${NC}
  $0

  ${YELLOW}# Build with custom tag${NC}
  $0 -t v3.3.0

  ${YELLOW}# Build and push to registry${NC}
  $0 -r ghcr.io/fpellizz -t v3.3.0 --push

  ${YELLOW}# Using environment variables${NC}
  REGISTRY=myregistry.io IMAGE_TAG=v3.3.0 PUSH=true $0

${CYAN}Notes:${NC}
  - If Trivy is installed, a security scan runs automatically after build
  - Non-latest tags are also tagged as :latest locally
  - The image includes: app, templates, static files, docs (manuals + screenshots)

EOF
    exit 0
}

# ─── Parse arguments ─────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--name)     IMAGE_NAME="$2"; shift 2 ;;
        -t|--tag)      IMAGE_TAG="$2"; shift 2 ;;
        -r|--registry) REGISTRY="$2"; shift 2 ;;
        -p|--push)     PUSH="true"; shift ;;
        --platform)    PLATFORM="$2"; shift 2 ;;
        -h|--help)     usage ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}" >&2
            echo "Run '$0 --help' for usage information."
            exit 1 ;;
    esac
done

# ─── Build ───────────────────────────────────────────────────────────
cd "$PROJECT_ROOT"

if [ -n "$REGISTRY" ]; then
    FULL_IMAGE_NAME="$REGISTRY/$IMAGE_NAME:$IMAGE_TAG"
else
    FULL_IMAGE_NAME="$IMAGE_NAME:$IMAGE_TAG"
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} MagikUp — Docker Build${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "  Image:    ${BOLD}$FULL_IMAGE_NAME${NC}"
echo -e "  Platform: ${BOLD}$PLATFORM${NC}"
echo -e "  Push:     ${BOLD}$PUSH${NC}"
echo ""

echo -e "${YELLOW}Building image...${NC}"
docker build \
    --platform "$PLATFORM" \
    --tag "$FULL_IMAGE_NAME" \
    --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --build-arg VCS_REF="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
    --file Dockerfile \
    .

echo -e "${GREEN}✓ Build complete: $FULL_IMAGE_NAME${NC}"

# ─── Security scan (optional) ───────────────────────────────────────
if command -v trivy &> /dev/null; then
    echo ""
    echo -e "${YELLOW}Running security scan with Trivy...${NC}"
    trivy image "$FULL_IMAGE_NAME"
fi

# ─── Push (if requested) ────────────────────────────────────────────
if [ -n "$REGISTRY" ] && [ "$PUSH" = "true" ]; then
    echo ""
    echo -e "${YELLOW}Pushing to registry...${NC}"
    docker push "$FULL_IMAGE_NAME"
    echo -e "${GREEN}✓ Pushed: $FULL_IMAGE_NAME${NC}"
fi

# ─── Tag as latest ──────────────────────────────────────────────────
if [ "$IMAGE_TAG" != "latest" ]; then
    LATEST_TAG="${REGISTRY:+$REGISTRY/}$IMAGE_NAME:latest"
    docker tag "$FULL_IMAGE_NAME" "$LATEST_TAG"
    echo -e "${GREEN}✓ Tagged as: $LATEST_TAG${NC}"

    if [ -n "$REGISTRY" ] && [ "$PUSH" = "true" ]; then
        docker push "$LATEST_TAG"
        echo -e "${GREEN}✓ Pushed: $LATEST_TAG${NC}"
    fi
fi

# ─── Summary ────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} Build completed successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Image: ${BOLD}$FULL_IMAGE_NAME${NC}"
echo ""
echo "Next steps:"
echo "  1. Update kubernetes/deployment.yaml with the image name"
echo "  2. Run: ./scripts/deploy.sh"
echo ""
