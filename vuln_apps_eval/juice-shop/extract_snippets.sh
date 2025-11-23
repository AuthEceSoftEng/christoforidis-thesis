#!/usr/bin/env bash
set -uo pipefail
if [ -z "${1-}" ]; then
  echo "Usage: $0 <project-folder>"
  exit 1
fi
PROJECT="$1"
if [ ! -d "$PROJECT" ]; then
  echo "Error: folder '$PROJECT' not found."
  exit 1
fi
cd "$PROJECT" || exit 1

# Find all files with 'vuln-code-snippet start'
mapfile -t FILES < <(grep -R "vuln-code-snippet start" -n . 2>/dev/null | cut -d: -f1 | sort -u)

declare -A ENTRY_FILE
declare -A ENTRY_START
declare -A ENTRY_END
declare -A ENTRY_VULN

for file in "${FILES[@]}"; do
  awk -v F="$file" '
    /vuln-code-snippet start/ {
      startLine = NR
      delete keys; kc = 0
      
      for (i = 1; i <= NF; i++) {
        if ($i == "start") {
          for (j = i+1; j <= NF; j++) {
            gsub(/^[#\/]+/, "", $j)
            keys[kc++] = $j
          }
          break
        }
      }
      
      # Store this snippet in a stack
      snippetCount++
      for (k = 0; k < kc; k++) {
        snippetKeys[snippetCount, k] = keys[k]
      }
      snippetKeyCount[snippetCount] = kc
      snippetStart[snippetCount] = startLine
      snippetVulnCount[snippetCount] = 0
      next
    }
    
    /vuln-code-snippet vuln-line/ {
      # Add vuln line to all active snippets
      for (s = 1; s <= snippetCount; s++) {
        vc = snippetVulnCount[s]
        snippetVuln[s, vc] = NR
        snippetVulnCount[s]++
      }
      next
    }
    
    /vuln-code-snippet end/ {
      if (snippetCount > 0) {
        endLine = NR
        
        # Output all active snippets
        for (s = 1; s <= snippetCount; s++) {
          kc = snippetKeyCount[s]
          for (k = 0; k < kc; k++) {
            key = snippetKeys[s, k]
            printf "%s\t%s\t%d\t%d\t", key, F, snippetStart[s], endLine
            printf "["
            vc = snippetVulnCount[s]
            for (i = 0; i < vc; i++) {
              printf "%d", snippetVuln[s, i]
              if (i < vc-1) printf ", "
            }
            printf "]\n"
          }
        }
        
        # Clear all snippets
        snippetCount = 0
      }
      next
    }
  ' "$file"
done > /tmp/_juice_snips_raw.tsv

# Ingest TSV into associative arrays, handle duplicate keys
while IFS=$'\t' read -r key file start end vuln; do
  if [ -n "${ENTRY_FILE[$key]-}" ]; then
    suffix=1
    newkey="${key}_${suffix}"
    while [ -n "${ENTRY_FILE[$newkey]-}" ]; do
      suffix=$((suffix+1))
      newkey="${key}_${suffix}"
    done
    key="$newkey"
  fi
  ENTRY_FILE["$key"]="$file"
  ENTRY_START["$key"]="$start"
  ENTRY_END["$key"]="$end"
  ENTRY_VULN["$key"]="$vuln"
done < /tmp/_juice_snips_raw.tsv

# Output JSON
echo "{"
first=1
for key in "${!ENTRY_FILE[@]}"; do
  if [ "$first" -eq 0 ]; then
    echo ","
  fi
  first=0
  printf "  \"%s\": {\n" "$key"
  printf "    \"file\": \"%s\",\n" "${ENTRY_FILE[$key]}"
  printf "    \"startLine\": %s,\n" "${ENTRY_START[$key]}"
  printf "    \"endLine\": %s,\n" "${ENTRY_END[$key]}"
  printf "    \"vulnLines\": %s\n" "${ENTRY_VULN[$key]}"
  printf "  }"
done
echo
echo "}"