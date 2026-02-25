#!/usr/bin/env bash
set -euo pipefail
trap 'echo "FATAL: script exited at line $LINENO (last command: $BASH_COMMAND)" >&2' ERR


ROOT="${1:-CWE_Examples}"
OUT="${2:-cwe_examples_complexity_scores.csv}"
STUBS_DIR="${3:-CWE_Examples/stubs}"

# Build an array of stub files
shopt -s nullglob
STUB_FILES=("$STUBS_DIR"/*.sv)
shopt -u nullglob

if (( ${#STUB_FILES[@]} == 0 )); then
  echo "ERROR: No stub .sv files found in $STUBS_DIR" >&2
  exit 1
fi

STUB_ARGS=""
for s in "${STUB_FILES[@]}"; do
  s="${s//$'\r'/}"              # strip CR if present
  STUB_ARGS+="$s "
done

echo "cwe,label,file,top,total_cells,ff_cells,mux_cells,cmp_cells" > "$OUT"

# Build list of RTL files (excluding stubs) into an array.
# Using -print0 + read -d '' handles spaces safely.
FILES=()
while IFS= read -r -d '' path; do
  FILES+=("$path")
done < <(find "$ROOT" -type f \( -name "*.v" -o -name "*.sv" \) ! -path "$STUBS_DIR/*" -print0)

# Optional: stable order
IFS=$'\n' FILES=($(printf '%s\n' "${FILES[@]}" | sort))
unset IFS

echo "Found ${#FILES[@]} RTL files to process." >&2


# Find all Verilog/SystemVerilog files under ROOT
# find "$ROOT" -type f \( -name "*.v" -o -name "*.sv" \) ! -path "$STUBS_DIR/*" | sort | while read -r f; do
for f in "${FILES[@]}"; do
    f="${f//$'\r'/}"
    cwe=$(echo "$f" | awk -F'/' '{for (i=1;i<=NF;i++) if ($i ~ /^CWE-[0-9]+$/) {print $i; exit}}')

    label="Unknown"
    if echo "$f" | grep -q "/Secure_Code/"; then
        label="Secure"
    elif echo "$f" | grep -q "/Vulnerable_Code/"; then
        label="Vulnerable"
    fi
    echo "CWE: $cwe, Label: $label" >&2
    # Guess top module as the first "module <name>" in the file (common in single-design files)
    top=$(grep -E '^[[:space:]]*module[[:space:]]+[A-Za-z_][A-Za-z0-9_]*' "$f" \
        | head -n 1 | sed -E 's/^[[:space:]]*module[[:space:]]+([A-Za-z_][A-Za-z0-9_]*).*/\1/')

    echo "Processing: CWE=$cwe, label=$label, file=$f, top=$top" >&2

    # Run yosys and capture stat output
    stat_out=$(
        yosys -Q \
            -p "read_verilog -sv ${STUB_ARGS}$f" \
            -p "hierarchy -check -top $top" \
            -p "proc; opt; fsm; opt" \
            -p "stat" \
            2>&1
    ) || {
        echo "YOSYS ERROR for: $f" >&2
        # echo "$stat_out" >&2
        echo >&2
        continue
    }

    # Total cells: sum all numeric entries in the 'Number of cells' table
    total=$(printf '%s\n' "$stat_out" | awk '/^[[:space:]]*[0-9]+[[:space:]]+cells[[:space:]]*$/ {print $1; found=1; exit} END {if (!found) print 0}' || true)

    # lines look like: "        2   $sdffe"
    ff=$(echo "$stat_out" | awk '
        /^[[:space:]]*[0-9]+[[:space:]]+\$.*dff/ {sum += $1}
        END {print sum+0}
    ')

    mux=$(echo "$stat_out" | awk '
        /^[[:space:]]*[0-9]+[[:space:]]+(\$mux|\$pmux|\$bmux)[[:space:]]*$/ {sum += $1}
        END {print sum+0}
    ')

    cmp=$(echo "$stat_out" | awk '
        /^[[:space:]]*[0-9]+[[:space:]]+(\$eq|\$ne|\$lt|\$le|\$gt|\$ge)[[:space:]]*$/ {sum += $1}
        END {print sum+0}
    ')

    echo "$cwe,$label,$f,$top,$total,$ff,$mux,$cmp" >> "$OUT"
    echo "Scored: $f  total_cells=$total, ff_cells=$ff, mux_cells=$mux, cmp_cells=$cmp" >&2
    echo
done

echo "Wrote: $OUT"