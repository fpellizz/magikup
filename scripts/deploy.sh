#!/bin/bash
# Deploy MagikUp to Kubernetes via a self-contained per-environment folder.
set -euo pipefail

# Colors
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'

# Configuration (overridable via environment)
KUBECTL="${KUBECTL:-kubectl}"
# Path (under kubernetes/) to the kustomize overlay to deploy — each project is
# <project>/overlays/<env>, copied from kubernetes/template/ (untracked; see
# kubernetes/template/README.md). ENV_NAME / OVERLAY kept as aliases.
DEPLOY_PATH="${DEPLOY_PATH:-${ENV_NAME:-${OVERLAY:-panservice-servizi/overlays/prod}}}"
TIMEOUT="${TIMEOUT:-300s}"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
K8S_DIR="$PROJECT_ROOT/kubernetes"

usage() {
    cat <<EOF

${BOLD}MagikUp — Kubernetes Deployment Script (kustomize base + overlay)${NC}

${CYAN}Usage:${NC}
  $0 [OPTIONS]

${CYAN}Options:${NC}
  ${GREEN}-e, --env${NC} PATH        overlay path under kubernetes/ (default: ${BOLD}panservice-servizi/overlays/prod${NC})
  ${GREEN}-t, --timeout${NC} DUR     Rollout timeout (default: ${BOLD}300s${NC})
  ${GREEN}-h, --help${NC}            Show this help

${CYAN}Layout:${NC}
  Each project under kubernetes/ is a kustomize ${BOLD}base/${NC} + ${BOLD}overlays/<env>/${NC}.
  Deploy an overlay, e.g. panservice-servizi/overlays/prod. Only the
  ${BOLD}template/${NC} project is committed; the rest are untracked (real cluster
  values on disk — see kubernetes/template/README.md).

${CYAN}Prerequisites:${NC}
  1. kubectl configured for the target cluster
  2. ${BOLD}kubernetes/secret.yaml${NC} created out-of-band (never committed):
       ./scripts/create-secret.sh           # generates it with a fresh Fernet key
     (or: cp kubernetes/secret.yaml.example kubernetes/secret.yaml && edit ENCRYPTION_KEY)
  3. Image published (ghcr.io/fpellizz/magikup:<tag>) — see ./scripts/build.sh

${CYAN}Examples:${NC}
  $0                                        # panservice-servizi/overlays/prod
  $0 -e testdialberto/overlays/test         # TestDiAlberto
  DEPLOY_PATH=vetri_speciali_gcp/overlays/prod $0

EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--env|-o|--overlay) DEPLOY_PATH="$2"; shift 2 ;;
        -t|--timeout) TIMEOUT="$2"; shift 2 ;;
        -h|--help)    usage ;;
        *) echo -e "${RED}Unknown option: $1${NC}" >&2; echo "Run '$0 --help'."; exit 1 ;;
    esac
done

ENV_DIR="$K8S_DIR/$DEPLOY_PATH"
SECRET_FILE="$K8S_DIR/secret.yaml"

# ─── Preflight ───────────────────────────────────────────────────────
command -v "$KUBECTL" &>/dev/null || { echo -e "${RED}Error: $KUBECTL not found${NC}"; exit 1; }
[ -d "$ENV_DIR" ] || { echo -e "${RED}Error: overlay '$DEPLOY_PATH' not found ($ENV_DIR)${NC}"; exit 1; }
$KUBECTL cluster-info &>/dev/null || { echo -e "${RED}Error: cannot reach the cluster (check kubeconfig)${NC}"; exit 1; }
if [ ! -f "$SECRET_FILE" ]; then
    echo -e "${RED}Error: $SECRET_FILE not found${NC}"
    echo "Create it once (out-of-band): ./scripts/create-secret.sh"
    exit 1
fi

# Namespace comes from the environment kustomization itself (`namespace:`), so the
# out-of-band Secret and the rollout wait always target the same place.
NAMESPACE="$($KUBECTL kustomize "$ENV_DIR" | awk '/^  namespace:/{print $2; exit}')"
NAMESPACE="${NAMESPACE:-default}"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} MagikUp — Kubernetes Deploy${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "  Overlay:   ${BOLD}$DEPLOY_PATH${NC}"
echo -e "  Namespace: ${BOLD}$NAMESPACE${NC}"
echo -e "  Timeout:   ${BOLD}$TIMEOUT${NC}"
echo ""

$KUBECTL get namespace "$NAMESPACE" &>/dev/null || {
    echo -e "${YELLOW}Creating namespace: $NAMESPACE${NC}"; $KUBECTL create namespace "$NAMESPACE"; }

echo -e "${YELLOW}1. Applying Secret (out-of-band, not in kustomize)...${NC}"
$KUBECTL apply -f "$SECRET_FILE" -n "$NAMESPACE"

echo -e "${YELLOW}2. Applying overlay '$DEPLOY_PATH'...${NC}"
$KUBECTL apply -k "$ENV_DIR"

echo ""
echo -e "${YELLOW}Waiting for rollout (timeout: $TIMEOUT)...${NC}"
$KUBECTL rollout status deployment/magikup -n "$NAMESPACE" --timeout="$TIMEOUT"

echo ""
echo -e "${GREEN}Deployment completed.${NC}"
$KUBECTL get pods -n "$NAMESPACE" -l app=magikup
echo ""
echo "Logs:  $KUBECTL logs -n $NAMESPACE -l app=magikup -f"
echo "Local: $KUBECTL port-forward -n $NAMESPACE svc/magikup 8000:8000"
