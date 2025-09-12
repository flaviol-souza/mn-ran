#!/usr/bin/env bash
set -euo pipefail

VENV_DIR="${VENV_DIR:-.venv39}"
PY_BIN="${PY_BIN:-python3.9}"

echo "[*] Verificando Python..."
if ! command -v "$PY_BIN" >/dev/null 2>&1; then
  echo "ERRO: $PY_BIN não encontrado. Instale python3.9 (ex.: deadsnakes) e tente de novo."
  echo "    sudo apt-get update && sudo apt-get install -y python3.9 python3.9-venv python3.9-dev"
  exit 1
fi

echo "[*] Criando venv em $VENV_DIR ..."
"$PY_BIN" -m venv "$VENV_DIR"

echo "[*] Atualizando pip/setuptools..."
"$VENV_DIR/bin/pip" install --upgrade "pip==23.2.1" "setuptools==65.5.1" wheel

echo "[*] Instalando requirements.txt ..."
"$VENV_DIR/bin/pip" install -r requirements.txt

echo
echo "[OK] Ambiente pronto:"
echo " - VENV: $VENV_DIR"
echo " - Ryu:  $('$VENV_DIR/bin/python' - <<'PY'
import ryu; print(getattr(ryu,'__version__','?'))
PY
)"
echo
echo "Use em dois terminais:"
echo "  1) $VENV_DIR/bin/ryu-manager --ofp-tcp-listen-port 6653 controller.py --verbose"
echo "  2) sudo $VENV_DIR/bin/python ucv_mininet.py --ctrl_port 6653 --start_cli --events events.yaml"
