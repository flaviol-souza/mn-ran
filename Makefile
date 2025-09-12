# ---- Configs ----
PYTHON ?= python3.9
VENV   ?= .venv39
PIP    := $(VENV)/bin/pip
PY     := $(VENV)/bin/python
RYU    := $(VENV)/bin/ryu-manager

CTRL_PORT ?= 6653
CTRL_APP  ?= controller.py      # ajuste para controller_ryu.py se for o seu nome

# ---- Alvos ----
.PHONY: help venv ryu mn freeze clean

help:
	@echo "Alvos disponíveis:"
	@echo "  make venv     -> cria venv e instala requirements"
	@echo "  make ryu      -> inicia ryu-manager na porta $(CTRL_PORT)"
	@echo "  make mn       -> inicia Mininet usando o venv (sudo)"
	@echo "  make freeze   -> gera requirements.freeze.txt"
	@echo "  make clean    -> apaga venv e caches"

venv: $(VENV)/bin/activate
$(VENV)/bin/activate:
	@echo "[*] criando venv em $(VENV) com $(PYTHON)"
	@$(PYTHON) -m venv $(VENV)
	@$(PIP) install --upgrade "pip==23.2.1" "setuptools==65.5.1" wheel
	@$(PIP) install -r requirements.txt
	@echo "[OK] venv pronto."

ryu: $(VENV)/bin/activate
	@$(RYU) --ofp-tcp-listen-port $(CTRL_PORT) $(CTRL_APP) --verbose

mn: $(VENV)/bin/activate
	@sudo $(PY) ucv_mininet.py --ctrl_port $(CTRL_PORT) --start_cli --events events.yaml

freeze: $(VENV)/bin/activate
	@$(PIP) freeze > requirements.freeze.txt
	@echo "[OK] requirements.freeze.txt gerado."

clean:
	@rm -rf $(VENV) __pycache__ */__pycache__ *.pyc *.pyo requirements.freeze.txt

