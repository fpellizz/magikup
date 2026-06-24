#!/bin/bash
# Generate Kubernetes secret for MagikUp
# Creates kubernetes/secret.yaml with a Fernet encryption key

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SECRET_FILE="$PROJECT_ROOT/kubernetes/secret.yaml"

# Check if secret.yaml already exists
if [ -f "$SECRET_FILE" ]; then
    echo -e "${YELLOW}Warning: $SECRET_FILE already exists.${NC}"
    read -rp "Overwrite? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# Generate Fernet encryption key
echo -e "${GREEN}Generating Fernet encryption key...${NC}"

# Try python3 first, then python
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo -e "${RED}Error: Python is required to generate the Fernet key.${NC}"
    echo "Install Python 3 and the 'cryptography' package, then retry."
    exit 1
fi

ENCRYPTION_KEY=$($PYTHON -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null)

if [ -z "$ENCRYPTION_KEY" ]; then
    echo -e "${RED}Error: Failed to generate Fernet key.${NC}"
    echo "Make sure the 'cryptography' Python package is installed:"
    echo "  pip install cryptography"
    exit 1
fi

# Write secret.yaml
cat > "$SECRET_FILE" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: magikup-secret
  labels:
    app: magikup
type: Opaque
stringData:
  ENCRYPTION_KEY: "$ENCRYPTION_KEY"
EOF

echo -e "${GREEN}Secret created at: $SECRET_FILE${NC}"
echo -e "${YELLOW}Do not share or log the encryption key.${NC}"
echo ""
echo -e "${GREEN}Deploy with:${NC}"
echo "  kubectl apply -f $SECRET_FILE"
