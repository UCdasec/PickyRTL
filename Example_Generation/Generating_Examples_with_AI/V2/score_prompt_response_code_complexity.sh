#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-Prompts}"
OUT="${2:-generated_code_complexity_scores.csv}"

echo "cwe,cwe_id,file,top,total_cells,ff_cells,mux_cells,cmp_cells" > "$OUT"

# Find all Verilog/SystemVerilog files under ROOT
find "$ROOT" -type f \( -name "*.v" -o -name "*.sv" \) | sort | while read -r f; do
    # Extract CWE and cwe_id from path: Prompts/<CWE>/<cwe_id>/...
    cwe=$(echo "$f" | awk -F'/' '{print $(NF-2)}')
    cwe_id=$(echo "$f" | awk -F'/' '{print $(NF-1)}')


    # Guess top module as the first "module <name>" in the file (common in single-design files)
    top=$(grep -E '^[[:space:]]*module[[:space:]]+[A-Za-z_][A-Za-z0-9_]*' "$f" \
        | head -n 1 | sed -E 's/^[[:space:]]*module[[:space:]]+([A-Za-z_][A-Za-z0-9_]*).*/\1/')

    echo "Processing: CWE=$cwe, cwe_id=$cwe_id, file=$f, top=$top" >&2

    # Run yosys and capture stat output
    stat_out=$(
        yosys -Q -p "
        read_verilog -sv $f;
        hierarchy -check -top $top;
        proc; opt; fsm; opt;
        stat
        " 2>&1
    ) || {
        echo "Skipping (yosys failed): $f" >&2
        continue
    }

    # Total cells: sum all numeric entries in the 'Number of cells' table
    total=$(echo "$stat_out" | awk '
        /^[[:space:]]*[0-9]+[[:space:]]+cells[[:space:]]*$/ {
            print $1
            found=1
            exit
        }
        END {
            if (!found) print 0
        }
    ')

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

    echo "$cwe,$cwe_id,$f,$top,$total,$ff,$mux,$cmp" >> "$OUT"
    echo "Scored: $f  total_cells=$total, ff_cells=$ff, mux_cells=$mux, cmp_cells=$cmp" >&2
    echo
done

echo "Wrote: $OUT"