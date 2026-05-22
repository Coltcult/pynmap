#!/bin/bash

# PyNmap Master Control Script
# Usage: ./pynmap_master.sh [TARGET] [MODE]

COLOR_RESET='\033[0m'
COLOR_GREEN='\033[92m'
COLOR_YELLOW='\033[93m'
COLOR_RED='\033[91m'
COLOR_BLUE='\033[94m'
COLOR_CYAN='\033[96m'

PYNMAP_SCRIPT="/home/kali/Documents/tools/pynmap_v2_fixed.py"
WORKSPACE="$HOME/pynmap_workspace"

show_banner() {
    echo -e "${COLOR_CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                    PyNmap Master Controller                    ║"
    echo "║                   Automated Vulnerability Scanner              ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${COLOR_RESET}"
}

show_menu() {
    echo -e "\n${COLOR_GREEN}Available Modes:${COLOR_RESET}"
    echo "  1) Quick Scan (Common ports, fast)"
    echo "  2) Full Scan (All ports, all scripts)"
    echo "  3) Web Focus (Ports 80,443,8080,8443)"
    echo "  4) CTF Mode (Common CTF ports, flag detection)"
    echo "  5) Learning Mode (Build knowledge base)"
    echo "  6) Batch Scan (Multiple targets from file)"
    echo "  7) Show Statistics"
    echo "  8) Clean Learning Data"
    echo "  9) Export Results"
    echo "  0) Exit"
}

quick_scan() {
    local target=$1
    echo -e "${COLOR_BLUE}[*] Quick scanning $target...${COLOR_RESET}"
    python3 $PYNMAP_SCRIPT $target --learn -T5 --script "http-title,http-headers,http-security-headers" -p 80,443,8080,8443 -v
}

full_scan() {
    local target=$1
    echo -e "${COLOR_BLUE}[*] Full scanning $target...${COLOR_RESET}"
    python3 $PYNMAP_SCRIPT $target --learn --script "all" -p 1-10000 -v --show-stats
}

web_focus() {
    local target=$1
    echo -e "${COLOR_BLUE}[*] Web-focused scan on $target...${COLOR_RESET}"
    python3 $PYNMAP_SCRIPT $target --learn --script "http-sql-injection,http-xss,http-lfi,http-enum,http-git,http-robots-txt" -p 80,443,8080,8443 -v
}

ctf_mode() {
    local target=$1
    echo -e "${COLOR_BLUE}[*] CTF mode on $target...${COLOR_RESET}"
    python3 $PYNMAP_SCRIPT $target --learn --script "ctf-flag-search,ctf-common-ports,http-enum" -p 1-10000 -v --show-stats
}

batch_scan() {
    local target_file=$1
    if [ ! -f "$target_file" ]; then
        echo -e "${COLOR_RED}Target file not found: $target_file${COLOR_RESET}"
        return
    fi
    
    echo -e "${COLOR_BLUE}[*] Batch scanning targets from $target_file...${COLOR_RESET}"
    while IFS= read -r target || [ -n "$target" ]; do
        if [ ! -z "$target" ] && [[ ! "$target" =~ ^# ]]; then
            echo -e "\n${COLOR_CYAN}=== Scanning: $target ===${COLOR_RESET}"
            python3 $PYNMAP_SCRIPT $target --learn --script "http-title,http-headers" -p 80,443 -v
            echo -e "${COLOR_GREEN}=== Completed $target ===${COLOR_RESET}"
        fi
    done < "$target_file"
}

show_stats() {
    echo -e "${COLOR_CYAN}=== LEARNING STATISTICS ===${COLOR_RESET}"
    
    echo -e "\n${COLOR_GREEN}Q-Table (Attack Knowledge):${COLOR_RESET}"
    if [ -f ~/.pynmap_qtable.json ]; then
        cat ~/.pynmap_qtable.json | python3 -m json.tool | head -30
    else
        echo "  No Q-table data yet"
    fi
    
    echo -e "\n${COLOR_GREEN}Memory Stats:${COLOR_RESET}"
    if [ -f ~/.pynmap_memory.json ]; then
        cat ~/.pynmap_memory.json | python3 -c "
import sys,json
d=json.load(sys.stdin)
stats=d.get('stats',{})
print(f\"  Total Scans: {stats.get('total_scans',0)}\")
print(f\"  Vulnerabilities: {stats.get('total_vulnerabilities',0)}\")
print(f\"  Flags Found: {stats.get('total_flags',0)}\")
"
    else
        echo "  No memory data yet"
    fi
}

clean_learning() {
    echo -e "${COLOR_YELLOW}Cleaning learning data...${COLOR_RESET}"
    rm -f ~/.pynmap_*.json
    echo -e "${COLOR_GREEN}Done. Learning data reset.${COLOR_RESET}"
}

export_results() {
    local target=$1
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local report_file="$WORKSPACE/reports/pynmap_report_${target}_${timestamp}.txt"
    
    echo -e "${COLOR_BLUE}Exporting results to $report_file...${COLOR_RESET}"
    mkdir -p "$WORKSPACE/reports"
    
    {
        echo "PyNmap Scan Report"
        echo "=================="
        echo "Target: $target"
        echo "Date: $(date)"
        echo ""
        echo "Learning Statistics:"
        show_stats
    } > "$report_file"
    
    echo -e "${COLOR_GREEN}Report saved to $report_file${COLOR_RESET}"
}

main() {
    show_banner
    
    if [ -n "$1" ] && [ -n "$2" ]; then
        # Command line mode
        target=$1
        mode=$2
        case $mode in
            1) quick_scan "$target" ;;
            2) full_scan "$target" ;;
            3) web_focus "$target" ;;
            4) ctf_mode "$target" ;;
            *) echo "Invalid mode" ;;
        esac
    else
        # Interactive mode
        echo -e "${COLOR_YELLOW}Enter target IP/Domain:${COLOR_RESET}"
        read target
        
        while true; do
            show_menu
            echo -e "\n${COLOR_YELLOW}Select mode [0-9]:${COLOR_RESET}"
            read choice
            
            case $choice in
                1) quick_scan "$target"; break ;;
                2) full_scan "$target"; break ;;
                3) web_focus "$target"; break ;;
                4) ctf_mode "$target"; break ;;
                5) 
                    echo -e "${COLOR_YELLOW}Learning Mode - Scanning multiple targets${COLOR_RESET}"
                    echo "Enter targets separated by space:"
                    read targets
                    for t in $targets; do
                        echo -e "\n${COLOR_CYAN}Learning from: $t${COLOR_RESET}"
                        python3 $PYNMAP_SCRIPT $t --learn --script "all" -p 80,443 -v
                    done
                    break
                    ;;
                6)
                    echo -e "${COLOR_YELLOW}Enter target file path:${COLOR_RESET}"
                    read target_file
                    batch_scan "$target_file"
                    break
                    ;;
                7) show_stats ;;
                8) clean_learning ;;
                9) export_results "$target" ;;
                0) echo -e "${COLOR_GREEN}Goodbye!${COLOR_RESET}"; exit 0 ;;
                *) echo -e "${COLOR_RED}Invalid option${COLOR_RESET}" ;;
            esac
        done
    fi
}

main "$@"
