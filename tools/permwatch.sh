#!/usr/bin/env bash
# ============================================================
#  permwatch — Auditoría de permisos inseguros en Linux
#  Herramienta de bastionado | v1.0
# ============================================================

# Sin set -e para evitar cortes silenciosos
set -uo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

COUNT_CRITICAL=0
COUNT_WARNING=0
COUNT_INFO=0

LOGFILE=""
if [[ "${1:-}" == "--log" && -n "${2:-}" ]]; then
    LOGFILE="$2"
    > "$LOGFILE"
fi

log() {
    local level="$1"; shift
    local msg="$*"
    local timestamp; timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$level" in
        CRITICAL)
            printf "${RED}${BOLD}[CRITICAL]${RESET} ${RED}%s${RESET}\n" "$msg"
            COUNT_CRITICAL=$(( COUNT_CRITICAL + 1 ))
            ;;
        WARNING)
            printf "${YELLOW}${BOLD}[WARNING] ${RESET} ${YELLOW}%s${RESET}\n" "$msg"
            COUNT_WARNING=$(( COUNT_WARNING + 1 ))
            ;;
        INFO)
            printf "${CYAN}[INFO]    ${RESET} %s\n" "$msg"
            COUNT_INFO=$(( COUNT_INFO + 1 ))
            ;;
        FIX)
            printf "  ${GREEN}${DIM}-> Recomendacion: %s${RESET}\n" "$msg"
            ;;
        SECTION)
            printf "\n${BOLD}=== %s ===${RESET}\n" "$msg"
            ;;
    esac

    [[ -n "$LOGFILE" ]] && printf "[%s] [%s] %s\n" "$timestamp" "$level" "$msg" >> "$LOGFILE"
}

print_banner() {
    printf "${BOLD}${CYAN}  permwatch — Auditoria de Permisos Inseguros en Linux — v1.0${RESET}\n"
    printf "${DIM}  %s${RESET}\n\n" "$(date '+%Y-%m-%d %H:%M:%S')"
}

check_root_warning() {
    if [[ $EUID -ne 0 ]]; then
        printf "${YELLOW}${BOLD}[!] No estas ejecutando como root. Algunos analisis pueden estar limitados.${RESET}\n\n"
    fi
}

audit_world_writable_files() {
    log SECTION "Archivos world-writable (777 / o+w)"
    local paths=(/home /var/www /tmp /var/tmp /opt /srv /etc)
    local found=0
    for base in "${paths[@]}"; do
        [[ -d "$base" ]] || continue
        while IFS= read -r -d '' file; do
            log CRITICAL "Archivo world-writable: $file"
            log FIX      "chmod o-w \"$file\""
            found=$(( found + 1 ))
        done < <(find "$base" -maxdepth 6 -type f -perm -0002 \
                      ! -path '/proc/*' ! -path '/sys/*' \
                      -print0 2>/dev/null)
    done
    [[ $found -eq 0 ]] && log INFO "Sin archivos world-writable en rutas auditadas."
}

audit_world_writable_dirs() {
    log SECTION "Directorios world-writable sin sticky bit"
    local found=0
    while IFS= read -r -d '' dir; do
        if [[ "$dir" == "/tmp" || "$dir" == "/var/tmp" ]]; then
            log WARNING "Directorio sensible sin sticky bit: $dir"
            log FIX     "chmod +t \"$dir\""
        else
            log CRITICAL "Directorio world-writable sin sticky bit: $dir"
            log FIX      "chmod o-w \"$dir\""
        fi
        found=$(( found + 1 ))
    done < <(find / -maxdepth 8 -type d -perm -0002 ! -perm -1000 \
                  ! -path '/proc/*' ! -path '/sys/*' ! -path '/run/*' \
                  -print0 2>/dev/null)
    [[ $found -eq 0 ]] && log INFO "No se encontraron directorios world-writable sin sticky bit."
}

# ─────────────────────────────────────────────────────────────
# WHITELIST DE SUID/SGID
# Para añadir binarios propios sin modificar el script, crea el
# fichero /etc/permwatch/suid_whitelist.conf con una ruta por línea.
# Ejemplo:
#   /opt/myapp/helper
#   /usr/local/bin/mytool
# ─────────────────────────────────────────────────────────────
SUID_WHITELIST_FILE="/etc/permwatch/suid_whitelist.conf"

SUID_WHITELIST=(
    /usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/newgrp
    /usr/bin/gpasswd /usr/bin/chfn /usr/bin/chsh /usr/bin/pkexec
    /usr/lib/openssh/ssh-keysign /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /usr/bin/mount /usr/bin/umount /usr/bin/ping /usr/bin/traceroute6
    /bin/mount /bin/umount /bin/ping /bin/su /sbin/unix_chkpwd
)

# Cargar entradas del fichero de whitelist personalizado si existe
load_custom_whitelist() {
    [[ ! -f "$SUID_WHITELIST_FILE" ]] && return
    while IFS= read -r line; do
        [[ "$line" =~ ^# || -z "$line" ]] && continue
        SUID_WHITELIST+=("$line")
    done < "$SUID_WHITELIST_FILE"
}

is_whitelisted() {
    local bin="$1"
    for w in "${SUID_WHITELIST[@]}"; do
        [[ "$bin" == "$w" ]] && return 0
    done
    return 1
}

audit_suid_sgid() {
    log SECTION "Binarios con bit SUID / SGID"
    local found_suid=0 found_sgid=0

    while IFS= read -r -d '' bin; do
        if is_whitelisted "$bin"; then
            log INFO "SUID (conocido): $bin"
        else
            log CRITICAL "SUID NO reconocido: $bin"
            log FIX      "chmod u-s \"$bin\""
        fi
        found_suid=$(( found_suid + 1 ))
    done < <(find / -xdev -type f -perm -4000 -print0 2>/dev/null)

    while IFS= read -r -d '' bin; do
        log WARNING "SGID detectado: $bin"
        log FIX     "chmod g-s \"$bin\""
        found_sgid=$(( found_sgid + 1 ))
    done < <(find / -xdev -type f -perm -2000 ! -perm -4000 -print0 2>/dev/null)

    [[ $found_suid -eq 0 ]] && log INFO "No se encontraron binarios SUID."
    [[ $found_sgid -eq 0 ]] && log INFO "No se encontraron binarios SGID."
}

audit_home_dirs() {
    log SECTION "Permisos en directorios /home"
    [[ -d /home ]] || { log INFO "/home no existe en este sistema."; return; }

    while IFS= read -r -d '' homedir; do
        local perm; perm=$(stat -c '%a' "$homedir" 2>/dev/null || echo "???")
        local owner; owner=$(stat -c '%U' "$homedir" 2>/dev/null || echo "?")
        if [[ "${perm: -1}" =~ [67] && "${perm:1:1}" =~ [67] ]]; then
            log CRITICAL "/home/$owner tiene permisos $perm (demasiado permisivo)"
            log FIX      "chmod 750 \"$homedir\""
        elif [[ "$perm" == "755" ]]; then
            log WARNING  "/home/$owner tiene permisos 755 (lectura por todos)"
            log FIX      "chmod 750 \"$homedir\""
        else
            log INFO     "/home/$owner — permisos: $perm (OK)"
        fi
    done < <(find /home -maxdepth 1 -mindepth 1 -type d -print0 2>/dev/null)
}

audit_ssh_dirs() {
    log SECTION "Directorios y ficheros .ssh"
    local found=0
    while IFS= read -r -d '' sshdir; do
        local dperm; dperm=$(stat -c '%a' "$sshdir" 2>/dev/null || echo "???")
        local owner; owner=$(stat -c '%U' "$sshdir" 2>/dev/null || echo "?")

        if [[ "$dperm" != "700" ]]; then
            log CRITICAL "Directorio .ssh con permisos $dperm (debe ser 700): $sshdir"
            log FIX      "chmod 700 \"$sshdir\""
        else
            log INFO     "$sshdir — permisos $dperm (OK)"
        fi

        while IFS= read -r -d '' sshfile; do
            local fperm; fperm=$(stat -c '%a' "$sshfile" 2>/dev/null || echo "???")
            local fname; fname=$(basename "$sshfile")
            case "$fname" in
                authorized_keys|id_rsa|id_ecdsa|id_ed25519)
                    if [[ "$fperm" != "600" && "$fperm" != "400" ]]; then
                        log CRITICAL "$sshfile tiene permisos $fperm (debe ser 600)"
                        log FIX      "chmod 600 \"$sshfile\""
                    else
                        log INFO     "$sshfile — permisos $fperm (OK)"
                    fi ;;
                *.pub)
                    if [[ "$fperm" != "644" && "$fperm" != "600" ]]; then
                        log WARNING "$sshfile (clave publica) tiene permisos $fperm"
                        log FIX     "chmod 644 \"$sshfile\""
                    fi ;;
            esac
        done < <(find "$sshdir" -maxdepth 1 -type f -print0 2>/dev/null)
        found=$(( found + 1 ))
    done < <(find /home /root -maxdepth 2 -name '.ssh' -type d -print0 2>/dev/null)
    [[ $found -eq 0 ]] && log INFO "No se encontraron directorios .ssh."
}

audit_var_www() {
    log SECTION "Permisos en /var/www"
    [[ -d /var/www ]] || { log INFO "/var/www no existe en este sistema."; return; }
    local found=0
    while IFS= read -r -d '' file; do
        log CRITICAL "Archivo world-writable en webroot: $file"
        log FIX      "chmod o-w \"$file\""
        found=$(( found + 1 ))
    done < <(find /var/www -type f -perm -0002 -print0 2>/dev/null)
    while IFS= read -r -d '' dir; do
        log CRITICAL "Directorio world-writable en webroot: $dir"
        log FIX      "chmod o-w \"$dir\""
        found=$(( found + 1 ))
    done < <(find /var/www -type d -perm -0002 -print0 2>/dev/null)
    [[ $found -eq 0 ]] && log INFO "Sin permisos peligrosos detectados en /var/www."
}

audit_tmp() {
    log SECTION "/tmp y /var/tmp"
    for tmpdir in /tmp /var/tmp; do
        [[ -d "$tmpdir" ]] || continue
        local perm; perm=$(stat -c '%a' "$tmpdir" 2>/dev/null || echo "???")
        if [[ "$perm" != "1777" ]]; then
            log WARNING "$tmpdir tiene permisos $perm (esperado: 1777)"
            log FIX     "chmod 1777 $tmpdir"
        else
            log INFO    "$tmpdir — permisos $perm (OK)"
        fi
    done

    if mount | grep -q ' /tmp '; then
        if mount | grep '/tmp' | grep -q 'noexec'; then
            log INFO "/tmp montado con noexec (OK)"
        else
            log WARNING "/tmp NO esta montado con 'noexec'"
            log FIX     "Anadir 'noexec,nosuid,nodev' a /tmp en /etc/fstab"
        fi
    fi
}

audit_orphaned() {
    log SECTION "Archivos sin propietario valido (orphaned)"
    local found=0
    while IFS= read -r -d '' file; do
        log WARNING "Archivo sin propietario: $file"
        log FIX     "chown root:root \"$file\""
        found=$(( found + 1 ))
    done < <(find / -xdev \( -nouser -o -nogroup \) -print0 2>/dev/null)
    [[ $found -eq 0 ]] && log INFO "No se encontraron archivos huerfanos."
}

print_summary() {
    printf "\n${BOLD}================================================${RESET}\n"
    printf "${BOLD}  RESUMEN DE LA AUDITORIA${RESET}\n"
    printf "${BOLD}================================================${RESET}\n"
    printf "  ${RED}${BOLD}CRITICAL : %d${RESET}\n" "$COUNT_CRITICAL"
    printf "  ${YELLOW}${BOLD}WARNING  : %d${RESET}\n" "$COUNT_WARNING"
    printf "  ${CYAN}INFO     : %d${RESET}\n" "$COUNT_INFO"
    printf "${BOLD}================================================${RESET}\n"

    if [[ $COUNT_CRITICAL -gt 0 ]]; then
        printf "\n${RED}${BOLD}[!] %d hallazgo(s) CRITICO(S). Corregir inmediatamente.${RESET}\n" "$COUNT_CRITICAL"
    elif [[ $COUNT_WARNING -gt 0 ]]; then
        printf "\n${YELLOW}${BOLD}[!] %d advertencia(s). Revisalas pronto.${RESET}\n" "$COUNT_WARNING"
    else
        printf "\n${GREEN}${BOLD}[OK] Sistema limpio: no se detectaron problemas de permisos.${RESET}\n"
    fi

    [[ -n "$LOGFILE" ]] && printf "\n${DIM}  Log guardado en: %s${RESET}\n" "$LOGFILE"
    printf "\n"
}

main() {
    print_banner
    check_root_warning
    load_custom_whitelist
    audit_world_writable_files
    audit_world_writable_dirs
    audit_suid_sgid
    audit_home_dirs
    audit_ssh_dirs
    audit_var_www
    audit_tmp
    audit_orphaned
    print_summary
}

main "$@"
