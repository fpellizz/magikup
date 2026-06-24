#!/bin/bash
# Deploy MagikUp to Kubernetes
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
NAMESPACE="${NAMESPACE:-default}"
KUBECTL="${KUBECTL:-kubectl}"
DEPLOY_INGRESS="${DEPLOY_INGRESS:-false}"
DEPLOY_NETPOL="${DEPLOY_NETPOL:-false}"
TIMEOUT="${TIMEOUT:-300s}"

# Get script/project directories
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
K8S_DIR="$PROJECT_ROOT/kubernetes"

# ─── Help ────────────────────────────────────────────────────────────
usage() {
    cat <<EOF

${BOLD}MagikUp — Kubernetes Deployment Script${NC}

${CYAN}Usage:${NC}
  $0 [OPTIONS]

${CYAN}Options:${NC}
  ${GREEN}-n, --namespace${NC} NS     Target Kubernetes namespace (default: ${BOLD}default${NC})
  ${GREEN}-i, --ingress${NC}          Also deploy the Ingress resource
  ${GREEN}    --network-policy${NC}   Also deploy the NetworkPolicy resource
  ${GREEN}-t, --timeout${NC} DURATION Rollout timeout (default: ${BOLD}300s${NC})
  ${GREEN}-h, --help${NC}             Show this help message

${CYAN}Environment variables:${NC}
  NAMESPACE          Same as --namespace
  KUBECTL            kubectl binary to use (default: kubectl)
  DEPLOY_INGRESS     Same as --ingress (set to "true")
  DEPLOY_NETPOL      Same as --network-policy (set to "true")
  TIMEOUT            Same as --timeout

${CYAN}Prerequisites:${NC}
  1. kubectl configured with access to the target cluster
  2. ${BOLD}kubernetes/secret.yaml${NC} created from the example:
       cp kubernetes/secret.yaml.example kubernetes/secret.yaml
       # Edit and set ENCRYPTION_KEY (base64-encoded Fernet key)
  3. Docker image already built and available to the cluster
       (see: ./scripts/build.sh --help)

${CYAN}Deployed resources (in order):${NC}
  1. RBAC         ServiceAccount
  2. ConfigMap    Application config (config.ini)
  3. Secret       Encryption key
  4. PVC          Persistent volumes (backups 50Gi, config 1Gi, logs 1Gi)
  5. Deployment   Application pod (port 8000)
  6. Service      ClusterIP service
  7. Ingress      (optional, with --ingress)
  8. NetworkPolicy (optional, with --network-policy)

${CYAN}Examples:${NC}
  ${YELLOW}# Deploy to default namespace${NC}
  $0

  ${YELLOW}# Deploy to a specific namespace with ingress${NC}
  $0 -n magikup-prod --ingress

  ${YELLOW}# Deploy with all optional resources${NC}
  $0 -n magikup --ingress --network-policy

  ${YELLOW}# Using environment variables${NC}
  NAMESPACE=magikup DEPLOY_INGRESS=true $0

${CYAN}Post-deployment:${NC}
  ${YELLOW}# Port-forward to access locally${NC}
  kubectl port-forward -n <namespace> svc/magikup 8000:8000

  ${YELLOW}# View logs${NC}
  kubectl logs -n <namespace> -l app=magikup -f

  ${YELLOW}# Check pod status${NC}
  kubectl get pods -n <namespace> -l app=magikup

EOF
    exit 0
}

# ─── Parse arguments ─────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace)      NAMESPACE="$2"; shift 2 ;;
        -i|--ingress)        DEPLOY_INGRESS="true"; shift ;;
        --network-policy)    DEPLOY_NETPOL="true"; shift ;;
        -t|--timeout)        TIMEOUT="$2"; shift 2 ;;
        -h|--help)           usage ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}" >&2
            echo "Run '$0 --help' for usage information."
            exit 1 ;;
    esac
done

# ─── Preflight checks ───────────────────────────────────────────────
cd "$K8S_DIR"

if ! command -v $KUBECTL &> /dev/null; then
    echo -e "${RED}Error: $KUBECTL not found${NC}"
    echo "Install kubectl or set KUBECTL env var to the correct binary."
    exit 1
fi

if ! $KUBECTL cluster-info &> /dev/null; then
    echo -e "${RED}Error: Cannot connect to Kubernetes cluster${NC}"
    echo "Check your kubeconfig and cluster connectivity."
    exit 1
fi

if [ ! -f "secret.yaml" ]; then
    echo -e "${RED}Error: kubernetes/secret.yaml not found!${NC}"
    echo ""
    echo "Create it from the example:"
    echo "  cp kubernetes/secret.yaml.example kubernetes/secret.yaml"
    echo "  # Edit and set your ENCRYPTION_KEY"
    exit 1
fi

# ─── Deploy ──────────────────────────────────────────────────────────
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} MagikUp — Kubernetes Deploy${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "  Namespace: ${BOLD}$NAMESPACE${NC}"
echo -e "  Ingress:   ${BOLD}$DEPLOY_INGRESS${NC}"
echo -e "  NetPolicy: ${BOLD}$DEPLOY_NETPOL${NC}"
echo -e "  Timeout:   ${BOLD}$TIMEOUT${NC}"
echo ""

# Create namespace if needed
if ! $KUBECTL get namespace "$NAMESPACE" &> /dev/null; then
    echo -e "${YELLOW}Creating namespace: $NAMESPACE${NC}"
    $KUBECTL create namespace "$NAMESPACE"
fi

STEP=1

echo -e "${YELLOW}${STEP}. Deploying RBAC (ServiceAccount)...${NC}"
$KUBECTL apply -f rbac.yaml -n "$NAMESPACE"
((STEP++))

echo -e "${YELLOW}${STEP}. Deploying ConfigMap...${NC}"
$KUBECTL apply -f configmap.yaml -n "$NAMESPACE"
((STEP++))

echo -e "${YELLOW}${STEP}. Deploying Secret...${NC}"
$KUBECTL apply -f secret.yaml -n "$NAMESPACE"
((STEP++))

echo -e "${YELLOW}${STEP}. Deploying PVC...${NC}"
$KUBECTL apply -f pvc.yaml -n "$NAMESPACE"
((STEP++))

echo -e "${YELLOW}${STEP}. Deploying Application...${NC}"
$KUBECTL apply -f deployment.yaml -n "$NAMESPACE"
((STEP++))

echo -e "${YELLOW}${STEP}. Deploying Service...${NC}"
$KUBECTL apply -f service.yaml -n "$NAMESPACE"
((STEP++))

if [ "$DEPLOY_INGRESS" = "true" ] && [ -f "ingress.yaml" ]; then
    echo -e "${YELLOW}${STEP}. Deploying Ingress...${NC}"
    $KUBECTL apply -f ingress.yaml -n "$NAMESPACE"
    ((STEP++))
fi

if [ "$DEPLOY_NETPOL" = "true" ] && [ -f "networkpolicy.yaml" ]; then
    echo -e "${YELLOW}${STEP}. Deploying NetworkPolicy...${NC}"
    $KUBECTL apply -f networkpolicy.yaml -n "$NAMESPACE"
    ((STEP++))
fi

# ─── Wait for rollout ───────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Waiting for deployment rollout (timeout: $TIMEOUT)...${NC}"
$KUBECTL rollout status deployment/magikup -n "$NAMESPACE" --timeout="$TIMEOUT"

# ─── Summary ────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} Deployment completed successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

echo -e "${BLUE}Pod status:${NC}"
$KUBECTL get pods -n "$NAMESPACE" -l app=magikup
echo ""

echo -e "${BLUE}Service:${NC}"
$KUBECTL get svc -n "$NAMESPACE" -l app=magikup
echo ""

echo -e "Access the application:"
echo "  $KUBECTL port-forward -n $NAMESPACE svc/magikup 8000:8000"
echo "  Then open: http://localhost:8000"
echo ""
echo "View logs:"
echo "  $KUBECTL logs -n $NAMESPACE -l app=magikup -f"
echo ""
