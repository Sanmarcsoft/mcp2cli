#!/usr/bin/env bash
set -euo pipefail

if ! command -v toon &>/dev/null; then
  echo "Error: 'toon' is required on PATH but was not found" >&2
  exit 1
fi

if ! command -v uv &>/dev/null; then
  echo "Error: 'uv' is required on PATH but was not found" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PYTHON_VERSIONS=("3.10" "3.13")
MCP_SPECS=("mcp==1.26.0" "mcp<2" "mcp>=2,<3")

RESULTS=()
ANY_FAILED=0

for py in "${PYTHON_VERSIONS[@]}"; do
  for spec in "${MCP_SPECS[@]}"; do
    echo "=== Running test matrix: Python ${py}, ${spec} ==="
    clean_spec="$(echo "${spec}" | tr -c 'a-zA-Z0-9' '_')"
    venv_dir="${TMP_DIR}/venv_${py}_${clean_spec}"
    py_bin="${venv_dir}/bin/python"
    resolved_mcp="unknown"
    status="PASS"

    if ! uv venv --python "${py}" "${venv_dir}"; then
      status="FAIL"
    elif ! uv pip install --python "${py_bin}" -e . --no-deps; then
      status="FAIL"
    elif ! uv pip install --python "${py_bin}" "${spec}" httpx pyyaml pytest pytest-asyncio tiktoken; then
      status="FAIL"
    else
      if resolved_mcp="$("${py_bin}" -c "import importlib.metadata as m; print(m.version('mcp'))")"; then
        echo "${resolved_mcp}"
      else
        resolved_mcp="unknown"
        status="FAIL"
      fi
      if ! "${py_bin}" -m pytest -q -p no:cacheprovider; then
        status="FAIL"
      fi
    fi

    if [[ "${status}" == "FAIL" ]]; then
      ANY_FAILED=1
    fi
    RESULTS+=("${py}|${spec}|${resolved_mcp}|${status}")
  done
done

echo ""
printf "%-10s %-15s %-20s %-10s
" "Python" "MCP Spec" "Resolved MCP" "Status"
printf "%-10s %-15s %-20s %-10s
" "------" "--------" "------------" "------"
for r in "${RESULTS[@]}"; do
  IFS="|" read -r r_py r_spec r_mcp r_status <<< "$r"
  printf "%-10s %-15s %-20s %-10s
" "$r_py" "$r_spec" "$r_mcp" "$r_status"
done

if [[ "${ANY_FAILED}" -ne 0 ]]; then
  exit 1
fi
exit 0
