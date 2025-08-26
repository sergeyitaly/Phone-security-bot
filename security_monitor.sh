#!/data/data/com.termux/files/usr/bin/bash
# =====================================================
# TERMUX ADVANCED SECURITY MONITOR WITH TELEGRAM ALERTS
# =====================================================
termux-wake-lock
trap "termux-wake-unlock" EXIT

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

LOGFILE="$HOME/security_monitor.log"
SAFE_DIRS="/system/bin|/bin|/usr/bin|/data/data/com.termux/files/usr/bin"
MY_PID=$$
MY_EXE=$(readlink -f /proc/$$/exe)

# ===== TELEGRAM SETTINGS =====
BOT_TOKEN="telegrambottoken"
CHAT_ID="chatid"

send_telegram() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
         -d chat_id="$CHAT_ID" \
         -d text="$message" > /dev/null
}

echo "=== Security Monitor Started at $(date) ===" >> "$LOGFILE"

# -----------------------------
# Detect suspicious processes
# -----------------------------
detect_suspicious() {
    ps -eo pid,ppid,cmd --no-headers | while read pid ppid cmd; do
        exe_path=$(readlink -f /proc/$pid/exe 2>/dev/null)
        if [ "$pid" -eq "$MY_PID" ] || [ "$exe_path" == "$MY_EXE" ]; then
            continue
        fi
        if [ -n "$exe_path" ] && [[ ! $exe_path =~ $SAFE_DIRS ]]; then
            msg="⚠️ Suspicious PID $pid -> $exe_path"
            echo -e "${RED}$msg${NC}"
            echo "$(date): $msg" >> "$LOGFILE"
            kill -9 $pid && echo "$(date): Killed PID $pid" >> "$LOGFILE"
            send_telegram "$msg"
        fi
        if echo "$cmd" | grep -Eq "nc|bash -i|sh -i|python -c|perl -e"; then
            msg="🚨 Potential reverse shell PID $pid -> $cmd"
            echo -e "${RED}$msg${NC}"
            echo "$(date): $msg" >> "$LOGFILE"
            send_telegram "$msg"
        fi
    done
}

# -----------------------------
# Detect suspicious Python scripts
# -----------------------------
detect_python_scripts() {
    ps -eo pid,ppid,cmd --no-headers | while read pid ppid cmd; do
        exe_path=$(readlink -f /proc/$pid/exe 2>/dev/null)
        if [ "$pid" -eq "$MY_PID" ] || [ "$exe_path" == "$MY_EXE" ]; then
            continue
        fi
        if echo "$cmd" | grep -E "python|python3" >/dev/null 2>&1; then
            msg="⚠️ Suspicious Python script running PID $pid -> $cmd"
            echo -e "${RED}$msg${NC}"
            echo "$(date): $msg" >> "$LOGFILE"
            send_telegram "$msg"
        fi
    done
}

# -----------------------------
# Check network connections (external only)
# -----------------------------
declare -A external_ip_count
check_network() {
    ss -tunp 2>/dev/null | while read line; do
        if echo "$line" | grep -q "$MY_PID"; then continue; fi
        echo "$(date): Network -> $line" >> "$LOGFILE"
        peer_ip=$(echo "$line" | awk '{print $5}' | cut -d':' -f1)
        if [ -z "$peer_ip" ] || [ "$peer_ip" == "127.0.0.1" ]; then continue; fi
        if ! echo "$peer_ip" | grep -Eq "^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\."; then
            ((external_ip_count[$peer_ip]++))
            send_telegram "⚠️ External connection detected: $line"
            echo "$(date): External connection alert -> $line" >> "$LOGFILE"
            if [ "${external_ip_count[$peer_ip]}" -ge 3 ]; then
                send_telegram "🚨 Persistent attacker detected from $peer_ip"
                echo "$(date): Persistent attacker -> $peer_ip" >> "$LOGFILE"
                external_ip_count[$peer_ip]=0
            fi
        fi
    done
}

# -----------------------------
# Check world-writable files
# -----------------------------
check_files() {
    find $HOME -type f -perm -002 2>/dev/null | while read f; do
        msg="World-writable file -> $f"
        echo "$(date): $msg" >> "$LOGFILE"
        send_telegram "$msg"
    done
}

# -----------------------------
# Check SUID/SGID binaries
# -----------------------------
check_suid() {
    find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read s; do
        msg="SUID/SGID binary -> $s"
        echo "$(date): $msg" >> "$LOGFILE"
        send_telegram "$msg"
    done
}

# -----------------------------
# Monitor CPU/Memory
# -----------------------------
check_resources() {
    top -b -n 1 | head -n 20 | while read line; do
        echo "$(date): CPU/Memory -> $line" >> "$LOGFILE"
    done
}

# -----------------------------
# Main loop
# -----------------------------
while true; do
    detect_suspicious
    detect_python_scripts
    check_network
    check_files
    check_suid
    check_resources
    sleep 2
done
