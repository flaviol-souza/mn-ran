#!/usr/bin/env bash
# move_all.sh — copia tudo de um diretório origem para destino (criando-o se preciso)
# e, após cópia bem-sucedida de cada arquivo, remove o original.
# Uso: ./move_all.sh /caminho/origem /caminho/destino

set -Eeuo pipefail

usage() {
  echo "Uso: $0 <dir_origem> <dir_destino>" >&2
  exit 1
}

# --- validação de argumentos ---
[[ $# -eq 2 ]] || usage
SRC="$1"
DST="$2"

# remove barras finais redundantes só para comparação
SRC="${SRC%/}"
DST="${DST%/}"

if [[ ! -d "$SRC" ]]; then
  echo "Erro: origem não é diretório: $SRC" >&2
  exit 2
fi

if [[ "$SRC" == "$DST" ]]; then
  echo "Erro: origem e destino não podem ser o mesmo diretório." >&2
  exit 3
fi

# --- prepara destino ---
mkdir -p "$DST"

# --- copia e remove originais com segurança ---
# -a  : recursivo, preserva atributos
# -HAX: preserva hardlinks, ACLs, xattrs (quando suportado)
# --remove-source-files : apaga cada arquivo de origem após cópia bem-sucedida
# As barras finais (/) significam "conteúdo de SRC para dentro de DST".
rsync -aHAX --remove-source-files "$SRC/" "$DST/"

# --- limpa diretórios vazios remanescentes na origem ---
# (rsync remove só arquivos; aqui removemos diretórios que ficaram vazios)
find "$SRC" -type d -empty -delete

echo "Concluído: arquivos copiados de '$SRC' para '$DST' e originais removidos."
