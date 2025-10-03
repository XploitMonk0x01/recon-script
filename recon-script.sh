#!/bin/bash

# --- Simplified CTF Reconnaissance Script (BASE DIR = only CTF name) ---
# Usage: ./recon_script.sh <target_ip>
# Interactive CTF name input, comprehensive scanning
set -euo pipefail

# --- Configuration ---
# Dirsearch Configuration
DIRSEARCH_EXTENSIONS="php,html,txt,js,css,json,xml,bak,old,zip,tar,gz,asp,aspx,jsp"
DIRSEARCH_THREADS=50
DIRSEARCH_TIMEOUT=10

# Other Tools Configuration
FFUF_EXTENSIONS="html,php,txt,js,css,json,xml,bak,old,zip,tar,gz"
GOBUSTER_TIMEOUT="10s"
FFUF_THREADS=30
MAX_FUZZ_TIME=900
DEFAULT_TIMEOUT=10
RECURSIVE_DEPTH=2
RECURSIVE_TIMEOUT=300

# Wordlists (prioritized) - Add fallback wordlists
WORDLISTS=(
  "/usr/share/wordlists/dirb/common.txt"
  "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
  "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
  "/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt"
  "/usr/share/wordlists/dirb/big.txt"
  "/usr/share/seclists/Discovery/Web-Content/common.txt"
)

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Global Variables ---
TARGET=""
CTF_NAME=""
TIMESTAMP=""
BASE_DIR=""
NMAP_DIR=""
WEB_DIR=""
DIRSEARCH_DIR=""
RUSTSCAN_DIR=""
NOTES_DIR=""
OPEN_PORTS=""
HTTP_PORTS=()

# --- Banner ---
display_banner() {
    echo -e "${PURPLE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                    CTF Reconnaissance Script                  ║"
    echo "║      RustScan → Nmap → Dirsearch → FFUF (Recursive)          ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# --- Usage ---
usage() {
    echo -e "${YELLOW}Usage: $0 <target_ip>${NC}"
    echo ""
    echo "This script performs comprehensive CTF reconnaissance:"
    echo "• Interactive CTF/Room name input"
    echo "• Fast port discovery with RustScan"
    echo "• Detailed service enumeration with Nmap"
    echo "• Targeted web directory fuzzing with Dirsearch"
    echo "• Optimized web fuzzing with FFUF (auto-calibration + recursive)"
    echo "• Organized output structure with detailed reports"
    echo ""
    echo -e "${RED}Requirements: nmap, gobuster, ffuf, curl, dirsearch${NC}"
    echo -e "${YELLOW}Optional: rustscan, httpx, jq${NC}"
    exit 1
}

# --- Tool Check ---
check_tools() {
    local required=(nmap gobuster ffuf curl dirsearch)
    local missing=()
    
    for tool in "${required[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Missing required tools: ${missing[*]}${NC}"
        echo "Install them and re-run."
        echo -e "${YELLOW}Install commands:${NC}"
        for tool in "${missing[@]}"; do
            case "$tool" in
                "dirsearch")
                    echo "  pip3 install dirsearch"
                    ;;
                "gobuster")
                    echo "  apt install gobuster  # Ubuntu/Debian"
                    echo "  go install github.com/OJ/gobuster/v3@latest  # Go install"
                    ;;
                "ffuf")
                    echo "  apt install ffuf  # Ubuntu/Debian"
                    echo "  go install github.com/ffuf/ffuf@latest  # Go install"
                    ;;
                "nmap")
                    echo "  apt install nmap  # Ubuntu/Debian"
                    ;;
            esac
        done
        exit 1
    fi
    
    # Check for at least one wordlist
    local wordlist_found=false
    for wordlist in "${WORDLISTS[@]}"; do
        if [ -f "$wordlist" ]; then
            wordlist_found=true
            echo -e "${GREEN}[+] Found wordlist: $wordlist${NC}"
            break
        fi
    done
    
    if [ "$wordlist_found" = false ]; then
        echo -e "${YELLOW}[!] No wordlists found. Please install SecLists or other wordlists:${NC}"
        echo "  git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists"
        echo "  apt install dirb dirbuster  # For dirb/dirbuster wordlists"
    fi
    
    local optional=(rustscan httpx jq)
    for tool in "${optional[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "${GREEN}[+] $tool available${NC}"
        else
            echo -e "${YELLOW}[i] $tool not found (optional)${NC}"
        fi
    done
}

# --- Get CTF Name ---
get_ctf_name() {
    echo ""
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                    CTF/Room Information                       ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    while true; do
        echo -e "${CYAN}Enter the CTF/Room/Box name:${NC}"
        echo -e "${YELLOW}(This will be used for organizing your results; base directory will be exactly this name)${NC}"
        echo -n "> "
        read -r CTF_NAME
        
        if [ -n "$CTF_NAME" ]; then
            # Sanitize the name (allow letters, numbers, dot, underscore, dash)
            CTF_NAME=$(echo "$CTF_NAME" | sed 's/[^a-zA-Z0-9._-]/_/g' | sed 's/__*/_/g')
            echo ""
            echo -e "${GREEN}✓ CTF/Room: ${CTF_NAME}${NC}"
            echo -e "${GREEN}✓ Target: ${TARGET}${NC}"
            echo ""
            break
        else
            echo -e "${RED}Please enter a valid name.${NC}"
            echo ""
        fi
    done
}

# --- Setup Directories ---
setup_directories() {
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    # BASE_DIR must be exactly the CTF name per requirement
    BASE_DIR="${CTF_NAME}"
    NMAP_DIR="$BASE_DIR/nmap"
    WEB_DIR="$BASE_DIR/web"
    DIRSEARCH_DIR="$BASE_DIR/dirsearch"
    RUSTSCAN_DIR="$BASE_DIR/rustscan"
    NOTES_DIR="$BASE_DIR/notes"
    
    # Create directories with error checking
    if ! mkdir -p "$NMAP_DIR" "$WEB_DIR" "$DIRSEARCH_DIR" "$RUSTSCAN_DIR" "$NOTES_DIR" 2>/dev/null; then
        echo -e "${RED}Error: Failed to create directories. Check permissions.${NC}"
        exit 1
    fi
    
    # Create notes template
    cat > "$NOTES_DIR/notes.md" << EOF
# $CTF_NAME - Reconnaissance Notes

## Target Information
- **Target**: $TARGET
- **CTF/Room**: $CTF_NAME
- **Scan Date**: $(date)
- **Base Directory**: $BASE_DIR

## Open Ports
<!-- Add discovered ports here -->

## Service Versions
<!-- Add detailed service versions and potential vulnerabilities here -->

## Services Analysis
<!-- Add service-specific information and attack vectors here -->

## Web Applications
<!-- Add web findings here -->

## Vulnerabilities
<!-- Add potential vulnerabilities here -->

## Exploitation Notes
<!-- Add exploitation attempts here -->

## Flags Found
<!-- Add any flags discovered here -->
EOF

    echo -e "${GREEN}[+] Directory structure created:${NC}"
    echo "    $BASE_DIR/"
    echo "    ├── rustscan/     (Fast port discovery)"
    echo "    ├── nmap/         (Detailed service scans)"
    echo "    ├── dirsearch/    (Targeted web directory fuzzing)" 
    echo "    ├── web/          (Comprehensive web fuzzing results)"
    echo "    └── notes/        (Your notes & findings)"
    echo ""
}

# --- Cleanup ---
cleanup() {
    echo -e "${YELLOW}[!] Cleaning up background processes...${NC}"
    # Kill all child processes
    local pids
    pids=$(jobs -p 2>/dev/null || true)
    if [ -n "$pids" ]; then
        echo "$pids" | xargs -r kill -TERM 2>/dev/null || true
        sleep 2
        # Force kill if still running
        pids=$(jobs -p 2>/dev/null || true)
        if [ -n "$pids" ]; then
            echo "$pids" | xargs -r kill -KILL 2>/dev/null || true
        fi
    fi
    
    # Kill any remaining dirsearch/gobuster/ffuf processes
    pkill -f "dirsearch\|gobuster\|ffuf" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# --- Port Discovery ---
run_rustscan() {
    if command -v rustscan &>/dev/null; then
        echo -e "${BLUE}[*] Running RustScan for fast port discovery...${NC}"
        local output="$RUSTSCAN_DIR/rustscan_${TARGET}_${TIMESTAMP}.txt"
        
        rustscan -a "$TARGET" --ulimit 5000 -t 500 --range 1-65535 -g > "$output" 2>&1 || true
        
        # Extract ports in format suitable for nmap -p flag
        OPEN_PORTS=$(grep -oE '\[[0-9,]+\]' "$output" 2>/dev/null | tr -d '[]' | head -1 || echo "")
        
        # Validate and clean port format
        if [ -n "$OPEN_PORTS" ]; then
            # Remove any extra spaces and validate format
            OPEN_PORTS=$(echo "$OPEN_PORTS" | tr -s ',' | sed 's/^,//;s/,$//')
            if [[ "$OPEN_PORTS" =~ ^[0-9,]+$ ]]; then
                echo -e "${GREEN}[+] RustScan found ports: $OPEN_PORTS${NC}"
                echo -e "${CYAN}[*] These ports will be used for detailed Nmap scan with -p flag${NC}"
            else
                echo -e "${YELLOW}[!] RustScan port format invalid, will use nmap for full discovery${NC}"
                OPEN_PORTS=""
            fi
        else
            echo -e "${YELLOW}[!] RustScan found no ports, will use nmap for full discovery${NC}"
            OPEN_PORTS=""
        fi
    else
        echo -e "${YELLOW}[i] RustScan not available, will use nmap for discovery${NC}"
        OPEN_PORTS=""
    fi
}

# --- Nmap Scanning ---
run_nmap() {
    echo -e "${BLUE}[*] Running Nmap scans...${NC}"
    
    local quick_output="$NMAP_DIR/nmap_quick_${TIMESTAMP}.txt"
    local detailed_output="$NMAP_DIR/nmap_detailed_${TIMESTAMP}.txt"
    local xml_output="$NMAP_DIR/nmap_detailed_${TIMESTAMP}.xml"
    
    echo -e "${YELLOW}    • Quick TCP scan with service detection (top 1000 ports)${NC}"
    nmap -T4 -F -sV "$TARGET" -oN "$quick_output" || true
    
    if [ -n "$OPEN_PORTS" ]; then
        echo -e "${YELLOW}    • Detailed service version & script scan on RustScan ports: $OPEN_PORTS${NC}"
        nmap -sC -sV -A -T4 -p"$OPEN_PORTS" "$TARGET" -oN "$detailed_output" -oX "$xml_output" || true
        
        # Store the ports for later use
        echo "$OPEN_PORTS" > "$NMAP_DIR/rustscan_ports.txt"
    else
        echo -e "${YELLOW}    • Full port discovery (may take time)${NC}"
        nmap -p- --max-retries 2 -T4 "$TARGET" -oN "$NMAP_DIR/nmap_allports_${TIMESTAMP}.txt" || true
        
        local discovered_ports
        discovered_ports=$(grep '^[0-9]\+/tcp.*open' "$NMAP_DIR/nmap_allports_${TIMESTAMP}.txt" 2>/dev/null | awk '{print $1}' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//' || echo "")
        
        if [ -n "$discovered_ports" ]; then
            echo -e "${YELLOW}    • Service version & vulnerability scan on ports: $discovered_ports${NC}"
            nmap -sC -sV -A -T4 -p"$discovered_ports" "$TARGET" -oN "$detailed_output" -oX "$xml_output" || true
        else
            echo -e "${YELLOW}    • No ports found, running default service version scan${NC}"
            nmap -sC -sV -A -T4 "$TARGET" -oN "$detailed_output" -oX "$xml_output" || true
        fi
    fi
    
    # Extract and display service versions for quick reference
    local detailed_file
    detailed_file=$(find "$NMAP_DIR" -name "nmap_detailed_*.txt" -type f | head -1)
    if [ -f "$detailed_file" ]; then
        echo -e "${CYAN}[*] Service Versions Summary:${NC}"
        grep -E "^[0-9]+/tcp.*open" "$detailed_file" | head -10 | while read -r line; do
            echo -e "${YELLOW}    $line${NC}"
        done
        echo ""
    fi
    
    echo -e "${GREEN}[+] Nmap scanning complete${NC}"
}

# --- Extract HTTP Ports ---
extract_http_ports() {
    HTTP_PORTS=()
    local nmap_file
    nmap_file=$(find "$NMAP_DIR" -name "nmap_detailed_*.txt" -type f | head -1)
    
    if [ -z "$nmap_file" ] || [ ! -f "$nmap_file" ]; then
        echo -e "${YELLOW}[!] No detailed nmap results found${NC}"
        return
    fi
    
    while IFS= read -r line; do
        if echo "$line" | grep -Eq "^[0-9]+/tcp[[:space:]]+open.*http"; then
            port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
            HTTP_PORTS+=("$port")
        fi
    done < "$nmap_file"
    
    for common_port in 80 443 8080 8443 8000 9000; do
        if grep -q "^${common_port}/tcp.*open" "$nmap_file" 2>/dev/null; then
            local found=0
            for existing in "${HTTP_PORTS[@]}"; do
                if [ "$existing" = "$common_port" ]; then
                    found=1
                    break
                fi
            done
            if [ $found -eq 0 ]; then
                HTTP_PORTS+=("$common_port")
            fi
        fi
    done
    
    if [ ${#HTTP_PORTS[@]} -gt 0 ]; then
        echo -e "${GREEN}[+] HTTP services detected on ports: ${HTTP_PORTS[*]}${NC}"
    else
        echo -e "${YELLOW}[!] No HTTP services detected${NC}"
    fi
}

# --- Test Web Connectivity ---
test_web_connectivity() {
    local url="$1"
    local code
    
    code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time "$DEFAULT_TIMEOUT" "$url" 2>/dev/null || echo "000")
    
    if [ "$code" = "000" ]; then
        return 1
    fi
    
    echo -e "${GREEN}    ✓ $url responds (HTTP $code)${NC}"
    return 0
}

# --- Targeted Dirsearch Scanning on Discovered Ports ---
run_dirsearch_on_discovered_ports() {
    if [ ${#HTTP_PORTS[@]} -eq 0 ]; then
        echo -e "${YELLOW}[!] No HTTP ports discovered, running dirsearch on common ports...${NC}"
        # Fallback to common ports if no HTTP services detected
        local common_urls=(
            "http://${TARGET}"
            "https://${TARGET}"
            "http://${TARGET}:8080"
            "https://${TARGET}:8443"
        )
    else
        echo -e "${BLUE}[*] Running targeted Dirsearch on discovered HTTP ports: ${HTTP_PORTS[*]}${NC}"
        local common_urls=()
        for port in "${HTTP_PORTS[@]}"; do
            local protocol="http"
            local nmap_file
            nmap_file=$(find "$NMAP_DIR" -name "nmap_detailed_*.txt" -type f | head -1)
            
            # Determine protocol based on port and nmap results
            if [ "$port" = "443" ] || [ "$port" = "8443" ]; then
                protocol="https"
            elif [ -f "$nmap_file" ] && grep -q "^${port}/tcp.*\(ssl\|tls\|https\)" "$nmap_file"; then
                protocol="https"
            fi
            
            # Build URL
            if { [ "$protocol" = "https" ] && [ "$port" = "443" ]; } || \
               { [ "$protocol" = "http" ] && [ "$port" = "80" ]; }; then
                common_urls+=("${protocol}://${TARGET}")
            else
                common_urls+=("${protocol}://${TARGET}:${port}")
            fi
        done
    fi
    
    echo -e "${BLUE}[*] Running Dirsearch scan...${NC}"
    
    for url in "${common_urls[@]}"; do
        if test_web_connectivity "$url"; then
            echo -e "${YELLOW}    • Dirsearch on $url${NC}"
            
            local port_from_url
            if [[ "$url" =~ :([0-9]+)$ ]]; then
                port_from_url="${BASH_REMATCH[1]}"
            elif [[ "$url" =~ ^https:// ]]; then
                port_from_url="443"
            else
                port_from_url="80"
            fi
            
            local output_file="$DIRSEARCH_DIR/dirsearch_${port_from_url}_${TIMESTAMP}.txt"
            local json_output="$DIRSEARCH_DIR/dirsearch_${port_from_url}_${TIMESTAMP}.json"
            
            # Run dirsearch with comprehensive options and error handling
            if command -v timeout >/dev/null 2>&1; then
                timeout 300 dirsearch -u "$url" \
                    -e "$DIRSEARCH_EXTENSIONS" \
                    --threads="$DIRSEARCH_THREADS" \
                    --timeout="$DIRSEARCH_TIMEOUT" \
                    --include-status=200,201,202,204,301,302,307,308,401,403,405,500 \
                    --exclude-status=404,429 \
                    --format=plain \
                    --output="$output_file" \
                    --quiet \
                    --random-agent \
                    --follow-redirects \
                    2>/dev/null &
            else
                dirsearch -u "$url" \
                    -e "$DIRSEARCH_EXTENSIONS" \
                    --threads="$DIRSEARCH_THREADS" \
                    --timeout="$DIRSEARCH_TIMEOUT" \
                    --include-status=200,201,202,204,301,302,307,308,401,403,405,500 \
                    --exclude-status=404,429 \
                    --format=plain \
                    --output="$output_file" \
                    --quiet \
                    --random-agent \
                    --follow-redirects \
                    2>/dev/null &
            fi
            
            local dirsearch_pid=$!
            
            # Also run with JSON output for easier parsing (shorter timeout for JSON)
            if command -v timeout >/dev/null 2>&1; then
                timeout 200 dirsearch -u "$url" \
                    -e "php,html,txt,js" \
                    --threads="$DIRSEARCH_THREADS" \
                    --timeout="$DIRSEARCH_TIMEOUT" \
                    --include-status=200,201,202,204,301,302,307,308,401,403,405,500 \
                    --exclude-status=404,429 \
                    --format=json \
                    --output="$json_output" \
                    --quiet \
                    --random-agent \
                    --follow-redirects \
                    2>/dev/null &
            else
                dirsearch -u "$url" \
                    -e "php,html,txt,js" \
                    --threads="$DIRSEARCH_THREADS" \
                    --timeout="$DIRSEARCH_TIMEOUT" \
                    --include-status=200,201,202,204,301,302,307,308,401,403,405,500 \
                    --exclude-status=404,429 \
                    --format=json \
                    --output="$json_output" \
                    --quiet \
                    --random-agent \
                    --follow-redirects \
                    2>/dev/null &
            fi
                
            echo "Dirsearch started for $url (PID: $dirsearch_pid and $!)" >> "$DIRSEARCH_DIR/dirsearch.log"
        fi
    done
    
    echo -e "${GREEN}[+] Dirsearch scans initiated on discovered ports${NC}"
    
    # Wait for dirsearch to complete before continuing
    echo -e "${YELLOW}[i] Waiting for dirsearch to complete...${NC}"
    wait
    
    echo -e "${GREEN}[+] Dirsearch completed${NC}"
}

# --- Web Fuzzing ---
run_web_fuzzing() {
    if [ ${#HTTP_PORTS[@]} -eq 0 ]; then
        echo -e "${YELLOW}[!] No HTTP ports to fuzz${NC}"
        return
    fi
    
    echo -e "${BLUE}[*] Starting web directory fuzzing...${NC}"
    
    for port in "${HTTP_PORTS[@]}"; do
        local protocol="http"
        local nmap_file
        nmap_file=$(find "$NMAP_DIR" -name "nmap_detailed_*.txt" -type f | head -1)
        
        if [ "$port" = "443" ] || [ "$port" = "8443" ]; then
            protocol="https"
        elif [ -f "$nmap_file" ] && grep -q "^${port}/tcp.*\(ssl\|tls\|https\)" "$nmap_file"; then
            protocol="https"
        fi
        
        local base_url
        if { [ "$protocol" = "https" ] && [ "$port" = "443" ]; } || \
           { [ "$protocol" = "http" ] && [ "$port" = "80" ]; }; then
            base_url="${protocol}://${TARGET}"
        else
            base_url="${protocol}://${TARGET}:${port}"
        fi
        
        local port_dir="$WEB_DIR/port_${port}"
        mkdir -p "$port_dir"
        
        echo ""
        echo -e "${BLUE}[*] Fuzzing $base_url${NC}"
        
        if ! test_web_connectivity "$base_url"; then
            echo -e "${RED}    ✗ Cannot connect to $base_url${NC}"
            echo "Connection failed" > "$port_dir/connection_failed.txt"
            continue
        fi
        
        fuzz_port "$base_url" "$port_dir" &
    done
    
    wait
    
    for port in "${HTTP_PORTS[@]}"; do
        local port_dir="$WEB_DIR/port_${port}"
        if [ -d "$port_dir" ] && [ ! -f "$port_dir/connection_failed.txt" ]; then
            process_web_results "$port_dir"
        fi
    done
}

# --- Fuzz Individual Port ---
fuzz_port() {
    local base_url="$1"
    local port_dir="$2"
    local fuzz_log="$port_dir/fuzzing.log"
    
    echo "Fuzzing started: $(date)" > "$fuzz_log"
    
    # Find the best wordlist to use
    local primary_wordlist=""
    local quick_wordlist=""
    
    for wordlist in "${WORDLISTS[@]}"; do
        if [ -f "$wordlist" ]; then
            if [ -z "$primary_wordlist" ]; then
                primary_wordlist="$wordlist"
            fi
            # Use common.txt or small wordlist for quick gobuster scan
            if [[ "$wordlist" == *"common.txt" ]] && [ -z "$quick_wordlist" ]; then
                quick_wordlist="$wordlist"
            fi
        fi
    done
    
    # Fallback: use primary for quick if no common.txt found
    if [ -z "$quick_wordlist" ]; then
        quick_wordlist="$primary_wordlist"
    fi
    
    # Run a single quick gobuster scan as fallback/comparison (only with common wordlist)
    if [ -n "$quick_wordlist" ]; then
        local gobuster_output="$port_dir/gobuster_quick.txt"
        echo -e "${YELLOW}    • Gobuster (quick baseline): $(basename "$quick_wordlist")${NC}"
        
        gobuster dir \
            -u "$base_url" \
            -w "$quick_wordlist" \
            -o "$gobuster_output" \
            -x "php,html,txt" \
            -b "404,500" \
            --timeout "$GOBUSTER_TIMEOUT" \
            -q &
        
        echo "Gobuster PID $! started with $(basename "$quick_wordlist")" >> "$fuzz_log"
    fi
    
    # Primary FFUF scan with auto-calibration for better accuracy
    if [ -n "$primary_wordlist" ]; then
        local ffuf_output="$port_dir/ffuf_results.json"
        local ffuf_text="$port_dir/ffuf_results.txt"
        echo -e "${YELLOW}    • FFUF (primary with auto-calibration)${NC}"
        
        ffuf \
            -u "${base_url}/FUZZ" \
            -w "$primary_wordlist" \
            -e ".$FFUF_EXTENSIONS" \
            -mc 200,201,202,204,301,302,307,308,401,403,405 \
            -fc 404 \
            -ac \
            -o "$ffuf_output" \
            -of json \
            -t "$FFUF_THREADS" \
            -timeout 10 \
            -s 2>/dev/null &
        
        local ffuf_pid=$!
        echo "FFUF PID $ffuf_pid started with auto-calibration" >> "$fuzz_log"
    fi
    
    # Wait for scans to complete
    local waited=0
    while [ $waited -lt $MAX_FUZZ_TIME ]; do
        local running_jobs
        running_jobs=$(jobs -r 2>/dev/null | wc -l)
        if [ "$running_jobs" -eq 0 ]; then
            break
        fi
        sleep 5
        waited=$((waited + 5))
    done
    
    if [ $waited -ge $MAX_FUZZ_TIME ]; then
        echo "Timeout reached, killing fuzzing processes..." >> "$fuzz_log"
        jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
    fi
    
    echo "Initial fuzzing completed: $(date)" >> "$fuzz_log"
    
    # Run recursive fuzzing on discovered directories
    if [ -f "$port_dir/ffuf_results.json" ] && [ -s "$port_dir/ffuf_results.json" ]; then
        echo -e "${CYAN}    • Starting recursive fuzzing on discovered directories...${NC}"
        recursive_fuzz "$base_url" "$port_dir" "$primary_wordlist"
    fi
    
    echo "All fuzzing completed: $(date)" >> "$fuzz_log"
}

# --- Recursive Fuzzing ---
recursive_fuzz() {
    local base_url="$1"
    local port_dir="$2"
    local wordlist="$3"
    local recursive_log="$port_dir/recursive_fuzzing.log"
    
    echo "Recursive fuzzing started: $(date)" > "$recursive_log"
    
    if [ ! -f "$wordlist" ] || [ ! -f "$port_dir/ffuf_results.json" ]; then
        echo "Wordlist or initial results not found, skipping recursive scan" >> "$recursive_log"
        return
    fi
    
    # Extract directories from initial scan (status 301, 302, 307, 308 or ends with /)
    local directories=()
    
    if command -v jq &>/dev/null; then
        # Parse JSON to find directories
        mapfile -t directories < <(jq -r '.results[]? | select(.status == 301 or .status == 302 or .status == 307 or .status == 308) | .url' "$port_dir/ffuf_results.json" 2>/dev/null | sed "s|^${base_url}/||" | sed 's|/$||' || true)
        
        # Also check for URLs that look like directories (even with 200 status)
        mapfile -t -O "${#directories[@]}" directories < <(jq -r '.results[]? | select(.status == 200) | .url' "$port_dir/ffuf_results.json" 2>/dev/null | grep '/$' | sed "s|^${base_url}/||" | sed 's|/$||' || true)
    else
        # Fallback: grep for common directory indicators
        mapfile -t directories < <(grep -oP '"url":"\K[^"]+' "$port_dir/ffuf_results.json" 2>/dev/null | grep -E '(/$|/admin|/api|/backup|/config|/data|/files|/images|/uploads|/user|/app)' | sed "s|^${base_url}/||" | sed 's|/$||' | sort -u || true)
    fi
    
    # Remove duplicates and limit depth
    local unique_dirs=($(printf '%s\n' "${directories[@]}" | sort -u | head -n "$RECURSIVE_DEPTH"))
    
    if [ ${#unique_dirs[@]} -eq 0 ]; then
        echo "No directories found for recursive scanning" >> "$recursive_log"
        echo -e "${YELLOW}    ! No directories to recurse into${NC}"
        return
    fi
    
    echo "Found ${#unique_dirs[@]} directories for recursive scanning" >> "$recursive_log"
    echo -e "${CYAN}    • Recursively fuzzing ${#unique_dirs[@]} directories${NC}"
    
    local recursive_results="$port_dir/ffuf_recursive.json"
    echo '{"results":[]}' > "$recursive_results"
    
    local count=0
    for dir in "${unique_dirs[@]}"; do
        count=$((count + 1))
        if [ $count -gt "$RECURSIVE_DEPTH" ]; then
            break
        fi
        
        # Skip if directory is too long or suspicious
        if [ ${#dir} -gt 100 ]; then
            continue
        fi
        
        echo "Scanning directory: $dir" >> "$recursive_log"
        echo -e "${CYAN}      ↳ Fuzzing: ${dir}/${NC}"
        
        local dir_output="$port_dir/ffuf_recursive_${count}.json"
        
        # Run ffuf on this directory with timeout
        timeout "$RECURSIVE_TIMEOUT" ffuf \
            -u "${base_url}/${dir}/FUZZ" \
            -w "$wordlist" \
            -e ".$FFUF_EXTENSIONS" \
            -mc 200,201,202,204,301,302,307,401,403 \
            -fc 404 \
            -ac \
            -o "$dir_output" \
            -of json \
            -t "$FFUF_THREADS" \
            -timeout 10 \
            -s 2>/dev/null || true
        
        # Merge results if jq is available
        if [ -f "$dir_output" ] && [ -s "$dir_output" ] && command -v jq &>/dev/null; then
            jq -s '.[0].results + .[1].results | {results: .}' "$recursive_results" "$dir_output" > "${recursive_results}.tmp" 2>/dev/null && mv "${recursive_results}.tmp" "$recursive_results" || true
        fi
    done
    
    echo "Recursive fuzzing completed: $(date)" >> "$recursive_log"
    
    # Count recursive findings
    if [ -f "$recursive_results" ] && command -v jq &>/dev/null; then
        local recursive_count
        recursive_count=$(jq '.results | length' "$recursive_results" 2>/dev/null || echo "0")
        if [ "$recursive_count" -gt 0 ]; then
            echo -e "${GREEN}    ✓ Recursive scan found $recursive_count additional paths${NC}"
            echo "Total recursive findings: $recursive_count" >> "$recursive_log"
        fi
    fi
}

# --- Process Web Results ---
process_web_results() {
    local port_dir="$1"
    local findings="$port_dir/interesting_findings.txt"
    
    echo "# Web Fuzzing Results" > "$findings"
    echo "" >> "$findings"
    
    # Process gobuster results (quick baseline)
    for gobuster_file in "$port_dir"/gobuster_*.txt; do
        if [ -f "$gobuster_file" ] && [ -s "$gobuster_file" ]; then
            echo "## Gobuster Quick Scan" >> "$findings"
            awk '/^\/[^ ]/ { print "- " $0 }' "$gobuster_file" >> "$findings" 2>/dev/null || true
            echo "" >> "$findings"
        fi
    done
    
    # Process primary FFUF results with enhanced formatting
    if [ -f "$port_dir/ffuf_results.json" ] && [ -s "$port_dir/ffuf_results.json" ]; then
        echo "## FFUF Primary Scan (Auto-Calibrated)" >> "$findings"
        if command -v jq &>/dev/null; then
            # Enhanced formatting with status code, length, and words
            jq -r '.results[]? | "- " + .url + " [HTTP " + (.status|tostring) + "] [Size: " + (.length|tostring) + "B] [Words: " + (.words|tostring) + "]"' \
                "$port_dir/ffuf_results.json" 2>/dev/null | sort -t'[' -k2 -n >> "$findings" || true
        else
            # Fallback without jq
            grep -o '"url":"[^"]*"' "$port_dir/ffuf_results.json" 2>/dev/null | \
                sed 's/"url":"//;s/"$//' | sed 's/^/- /' | sort >> "$findings" || true
        fi
        echo "" >> "$findings"
    fi
    
    # Process recursive FFUF results
    if [ -f "$port_dir/ffuf_recursive.json" ] && [ -s "$port_dir/ffuf_recursive.json" ]; then
        echo "## FFUF Recursive Scan" >> "$findings"
        if command -v jq &>/dev/null; then
            local rec_count
            rec_count=$(jq '.results | length' "$port_dir/ffuf_recursive.json" 2>/dev/null || echo "0")
            if [ "$rec_count" -gt 0 ]; then
                jq -r '.results[]? | "- " + .url + " [HTTP " + (.status|tostring) + "] [Size: " + (.length|tostring) + "B]"' \
                    "$port_dir/ffuf_recursive.json" 2>/dev/null | sort -t'[' -k2 -n >> "$findings" || true
            else
                echo "- No additional paths found in recursive scan" >> "$findings"
            fi
        else
            grep -o '"url":"[^"]*"' "$port_dir/ffuf_recursive.json" 2>/dev/null | \
                sed 's/"url":"//;s/"$//' | sed 's/^/- /' | sort >> "$findings" || true
        fi
        echo "" >> "$findings"
    fi
    
    local total_findings
    total_findings=$(grep -c "^- " "$findings" 2>/dev/null || echo "0")
    
    if [ "$total_findings" -gt 0 ]; then
        echo -e "${GREEN}    ✓ Found $total_findings interesting paths${NC}"
        local high_value
        # Enhanced pattern matching for high-value targets
        high_value=$(grep -iE "(admin|login|signin|config|flag|key|secret|backup|upload|api|dashboard|panel|control|manage|portal|console|debug|swagger|graphql|auth|token|password|internal|private|_admin|phpmyadmin)" "$findings" 2>/dev/null | \
                    grep -v -E '(logout|signout|\.css|\.js|/img/|/fonts/|/assets/)' | head -5 || true)
        if [ -n "$high_value" ]; then
            echo -e "${PURPLE}    High-value targets found:${NC}"
            echo "$high_value" | sed 's/^/      /'
        fi
    else
        echo -e "${YELLOW}    ! No successful paths discovered${NC}"
    fi
}

# --- Process Dirsearch Results ---
process_dirsearch_results() {
    echo -e "${BLUE}[*] Processing Dirsearch results...${NC}"
    
    local summary_file="$DIRSEARCH_DIR/dirsearch_summary.txt"
    echo "# Dirsearch Priority Scan Results" > "$summary_file"
    echo "Scan completed: $(date)" >> "$summary_file"
    echo "" >> "$summary_file"
    
    local total_found=0
    
    for result_file in "$DIRSEARCH_DIR"/dirsearch_*.txt; do
        if [ -f "$result_file" ] && [ -s "$result_file" ]; then
            local port=$(echo "$(basename "$result_file")" | grep -o '[0-9]\+' | head -1)
            echo "## Port $port Results" >> "$summary_file"
            
            # Extract successful findings with better filtering
            local findings
            # Only include successful status codes and filter noise
            findings=$(grep -E '(^[0-9]{3}[[:space:]]+|200|201|202|204|301|302|307|308|401|403|405)' "$result_file" 2>/dev/null | \
                      grep -v -E '(404|429|502|503|504)' | \
                      grep -v -E '(favicon\.ico|robots\.txt.*404|.well-known.*404)' | head -30 || true)
            
            if [ -z "$findings" ]; then
                # Alternative pattern for different dirsearch formats
                findings=$(grep -E '(200|201|202|204|301|302|307|308|401|403|405)' "$result_file" 2>/dev/null | \
                          grep -v -E '(404|429|502|503)' | head -30 || true)
            fi
            
            if [ -n "$findings" ]; then
                echo "$findings" | while read -r line; do
                    echo "- $line" >> "$summary_file"
                done
                local line_count
                line_count=$(echo "$findings" | wc -l)
                total_found=$((total_found + line_count))
            else
                echo "- No significant findings" >> "$summary_file"
            fi
            echo "" >> "$summary_file"
        fi
    done
    
    # Process JSON results for high-value targets with enhanced patterns
    for json_file in "$DIRSEARCH_DIR"/dirsearch_*.json; do
        if [ -f "$json_file" ] && [ -s "$json_file" ] && command -v jq &>/dev/null; then
            local high_value
            # Enhanced pattern matching for more high-value paths
            high_value=$(jq -r '.results[]? | select(.status != 404 and .status != 429 and .status != 403) | .url' "$json_file" 2>/dev/null | \
                        grep -iE "(admin|login|signin|signup|config|flag|key|secret|backup|upload|api|dashboard|panel|control|manage|portal|cms|wp-admin|phpmyadmin|console|debug|test|dev|staging|private|internal|auth|user|account|profile|settings|register|forgot|reset|password|token|ajax|rest|graphql|swagger|docs|_admin)" | \
                        grep -v -E '(logout|signout|css|js|img|fonts|assets|static)' | head -10 || true)
            
            if [ -n "$high_value" ]; then
                echo "## High-Value Targets Found" >> "$summary_file"
                echo "$high_value" | sed 's/^/- /' >> "$summary_file"
                echo "" >> "$summary_file"
            fi
        fi
    done
    
    if [ -f "$summary_file" ] && [ -s "$summary_file" ]; then
        local findings_count
        findings_count=$(grep -c "^- " "$summary_file" 2>/dev/null || echo "0")
        echo -e "${GREEN}[+] Dirsearch found $findings_count interesting paths${NC}"
        
        # Show top findings with enhanced pattern matching
        local top_findings
        top_findings=$(grep -iE "(admin|login|signin|config|flag|key|secret|backup|upload|api|dashboard|panel|console|swagger|auth|token|password|internal|private|_admin)" "$summary_file" 2>/dev/null | \
                      grep -v -E '(logout|signout|\.css|\.js)' | head -5 || true)
        if [ -n "$top_findings" ]; then
            echo -e "${PURPLE}    Priority targets:${NC}"
            echo "$top_findings" | sed 's/^/      /'
        fi
    fi
}

# --- Generate Final Report ---
generate_report() {
    local report="$BASE_DIR/REPORT.md"
    
    cat > "$report" << EOF
# CTF Reconnaissance Report

## Target Information
- **Target**: $TARGET
- **CTF/Room**: $CTF_NAME
- **Scan Date**: $(date)
- **Duration**: Started at $TIMESTAMP

## Summary
EOF

    if [ -n "$OPEN_PORTS" ]; then
        echo "- **Open Ports**: $OPEN_PORTS" >> "$report"
    fi
    
    if [ ${#HTTP_PORTS[@]} -gt 0 ]; then
        echo "- **HTTP Services**: ${HTTP_PORTS[*]}" >> "$report"
    fi
    
    # Add service versions section
    local detailed_nmap
    detailed_nmap=$(find "$NMAP_DIR" -name "nmap_detailed_*.txt" -type f 2>/dev/null | head -1)
    if [ -f "$detailed_nmap" ] && [ -r "$detailed_nmap" ]; then
        echo "" >> "$report"
        echo "## Service Versions Detected" >> "$report"
        echo "\`\`\`" >> "$report"
        if grep -E "^[0-9]+/tcp.*open" "$detailed_nmap" 2>/dev/null | head -15 >> "$report"; then
            :  # Success, do nothing
        else
            echo "No detailed service information available" >> "$report"
        fi
        echo "\`\`\`" >> "$report"
    else
        echo "" >> "$report"
        echo "## Service Versions Detected" >> "$report"
        echo "No nmap results available yet" >> "$report"
    fi
    
    cat >> "$report" << EOF

## Directory Structure
\`\`\`
$BASE_DIR/
├── rustscan/     # Fast port discovery
├── nmap/         # Detailed port scans and service detection  
├── dirsearch/    # Targeted web directory scanning results
├── web/          # Comprehensive web fuzzing results by port
└── notes/        # Your manual notes
\`\`\`

## Key Files
- **Main Report**: $report
- **Dirsearch Summary**: $DIRSEARCH_DIR/dirsearch_summary.txt
- **Notes Template**: $NOTES_DIR/notes.md
EOF

    # Add Dirsearch findings summary
    if [ -f "$DIRSEARCH_DIR/dirsearch_summary.txt" ]; then
        local dirsearch_count
        dirsearch_count=$(grep -c "^- " "$DIRSEARCH_DIR/dirsearch_summary.txt" 2>/dev/null || echo "0")
        echo "- **Dirsearch Findings**: $dirsearch_count paths discovered" >> "$report"
    fi
    
    if [ ${#HTTP_PORTS[@]} -gt 0 ]; then
        echo "" >> "$report"
        echo "## Web Findings Summary" >> "$report"
        
        # Show dirsearch results first (priority)
        if [ -f "$DIRSEARCH_DIR/dirsearch_summary.txt" ]; then
            local dirsearch_count
            dirsearch_count=$(grep -c "^- " "$DIRSEARCH_DIR/dirsearch_summary.txt" 2>/dev/null || echo "0")
            echo "- **Dirsearch (Priority)**: $dirsearch_count paths discovered" >> "$report"
        fi
        
        # Then show comprehensive fuzzing results
        for port in "${HTTP_PORTS[@]}"; do
            local findings_file="$WEB_DIR/port_${port}/interesting_findings.txt"
            if [ -f "$findings_file" ]; then
                local count
                count=$(grep -c "^- " "$findings_file" 2>/dev/null || echo "0")
                echo "- **Port $port (Comprehensive)**: $count paths discovered" >> "$report"
            fi
        done
    fi
    
    cat >> "$report" << EOF

## Next Steps
1. Review service versions for known vulnerabilities
2. Analyze web findings for potential entry points
3. Test discovered paths manually
4. Check for default credentials
5. Look for hidden parameters and forms

## Quick Commands
\`\`\`bash
# View priority dirsearch findings
cat $DIRSEARCH_DIR/dirsearch_summary.txt

# View all comprehensive web findings  
find $WEB_DIR -name "interesting_findings.txt" -exec cat {} \;

# Search for high-value targets across all results
grep -r -i "admin\|login\|config\|flag\|api\|dashboard" $DIRSEARCH_DIR/ $WEB_DIR/

# Extract service versions and potential vulnerabilities
grep -E "^[0-9]+/tcp.*open" $NMAP_DIR/nmap_detailed_*.txt

# Check for specific service versions
grep -i "version\|product" $NMAP_DIR/nmap_detailed_*.txt

# View full nmap results
cat $NMAP_DIR/nmap_detailed_*.txt

# Quick access to dirsearch raw results
ls -la $DIRSEARCH_DIR/
\`\`\`
EOF

    echo -e "${GREEN}[+] Final report generated: $report${NC}"
}

# --- Main Function ---
main() {
    if [ $# -ne 1 ]; then
        usage
    fi
    
    TARGET="$1"
    
    # Validate IP address format and ranges
    if ! [[ $TARGET =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo -e "${RED}Error: Please provide a valid IP address format${NC}"
        exit 1
    fi
    
    # Check if octets are within valid range (0-255)
    IFS='.' read -ra ADDR <<< "$TARGET"
    for octet in "${ADDR[@]}"; do
        if [ "$octet" -gt 255 ] || [ "$octet" -lt 0 ]; then
            echo -e "${RED}Error: IP address octets must be between 0-255${NC}"
            exit 1
        fi
    done
    
    display_banner
    check_tools
    get_ctf_name
    setup_directories
    
    echo -e "${PURPLE}Starting reconnaissance for $CTF_NAME...${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Step 1: Fast port discovery with RustScan
    run_rustscan
    
    # Step 2: Detailed service enumeration with Nmap using RustScan ports (-p flag)
    run_nmap
    extract_http_ports
    
    # Step 3: Targeted web directory discovery with Dirsearch on HTTP ports
    run_dirsearch_on_discovered_ports
    
    # Step 4: Process Dirsearch results for immediate analysis
    process_dirsearch_results
    
    # Step 5: Comprehensive web fuzzing: Gobuster + FFUF on all discovered ports
    run_web_fuzzing
    
    # Step 6: Generate final report
    generate_report
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}Reconnaissance completed for $CTF_NAME!${NC}"
    echo ""
    echo -e "${YELLOW}All results: ./$BASE_DIR/${NC}"
    echo -e "${YELLOW}Main report: ./$BASE_DIR/REPORT.md${NC}"
    echo -e "${YELLOW}Notes: ./$BASE_DIR/notes/notes.md${NC}"
    echo ""
}

main "$@"
 
                                                                                                                                                                                              