#!/usr/bin/env bash
# ============================================================
#  confguardian — Monitorización de Integridad de Configuración
#  Herramienta de bastionado | v1.0
# ============================================================

set -uo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

BASELINE_DIR="/var/lib/confguardian"
BASELINE_FILE="${BASELINE_DIR}/baseline.db"
HISTORY_DIR="${BASELINE_DIR}/history"
ALERT_LOG="${BASELINE_DIR}/alerts.log"
CUSTOM_LIST_FILE="${BASELINE_DIR}/custom_paths.conf"

MODE=""
WATCH_INTERVAL=60
LOGFILE=""
NOTIFY_EMAIL=""
HASH_ALGO="sha256"
ADD_TARGET=""

COUNT_OK=0
COUNT_MODIFIED=0
COUNT_DELETED=0
COUNT_NEW=0

DEFAULT_WATCH_FILES=(
    /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers
    /etc/security/limits.conf /etc/ssh/sshd_config /etc/ssh/ssh_config
    /etc/fstab /etc/crypttab /etc/hosts /etc/resolv.conf
    /etc/nsswitch.conf /etc/hostname /etc/network/interfaces
    /etc/pam.conf /etc/pam.d/common-auth /etc/pam.d/common-account
    /etc/pam.d/sshd /etc/pam.d/sudo /etc/pam.d/su
    /etc/crontab /etc/sysctl.conf /etc/ld.so.conf
    /etc/rsyslog.conf /etc/logrotate.conf
)

usage() {
    cat << EOF
Uso:
  sudo $0 <modo> [opciones]

Modos:
  init              Genera el baseline inicial
  check             Verifica integridad comparando contra el baseline
  watch             Monitorizacion continua (daemon ligero)
  report            Muestra historial de alertas pasadas
  add <ruta>        Anade un archivo/directorio al baseline
  reset             Elimina el baseline y el historial

Opciones:
  --interval <s>    Segundos entre verificaciones en modo watch [60]
  --algo <alg>      Algoritmo de hash: sha256 | sha512 | md5   [sha256]
  --log <fichero>   Guarda la salida en el fichero indicado
  --email <addr>    Direccion para notificaciones
EOF
    exit 0
}

parse_args() {
    [[ $# -eq 0 ]] && usage
    MODE="$1"; shift

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interval) shift; WATCH_INTERVAL="${1:-60}" ;;
            --algo)     shift; HASH_ALGO="${1:-sha256}" ;;
            --log)      shift; LOGFILE="${1:-}" ;;
            --email)    shift; NOTIFY_EMAIL="${1:-}" ;;
            -h|--help)  usage ;;
            *)
                if [[ "$MODE" == "add" ]]; then
                    ADD_TARGET="$1"
                else
                    printf "Opcion desconocida: %s\n" "$1"; usage
                fi
                ;;
        esac
        shift
    done
    [[ -n "$LOGFILE" ]] && > "$LOGFILE"
}

ts() { date '+%Y-%m-%d %H:%M:%S'; }

log() {
    local level="$1"; shift
    local msg="$*"
    local timestamp; timestamp=$(ts)

    case "$level" in
        OK)      printf "  ${GREEN}${BOLD}[OK]   ${RESET}   %s\n" "$msg" ;;
        ALERT)   printf "  ${RED}${BOLD}[ALERT]${RESET}   ${RED}%s${RESET}\n" "$msg" ;;
        NEW)     printf "  ${MAGENTA}${BOLD}[NEW]  ${RESET}   ${MAGENTA}%s${RESET}\n" "$msg" ;;
        DELETED) printf "  ${YELLOW}${BOLD}[DEL]  ${RESET}   ${YELLOW}%s${RESET}\n" "$msg" ;;
        INFO)    printf "  ${CYAN}[INFO] ${RESET}   %s\n" "$msg" ;;
        WARN)    printf "  ${YELLOW}[WARN] ${RESET}   %s\n" "$msg" ;;
        SECTION) printf "\n${BOLD}=== %s ===${RESET}\n" "$msg" ;;
    esac

    if [[ "$level" == "ALERT" || "$level" == "NEW" || "$level" == "DELETED" ]]; then
        mkdir -p "$BASELINE_DIR"
        printf "[%s] [%s] %s\n" "$timestamp" "$level" "$msg" >> "$ALERT_LOG"
    fi
    [[ -n "$LOGFILE" ]] && printf "[%s] [%s] %s\n" "$timestamp" "$level" "$msg" >> "$LOGFILE"
}

hash_file() {
    local file="$1"
    [[ ! -f "$file" ]] && { printf "NOFILE"; return 0; }
    [[ ! -r "$file" ]] && { printf "NOPERM"; return 0; }
    case "$HASH_ALGO" in
        sha256) sha256sum "$file" 2>/dev/null | awk '{print $1}' ;;
        sha512) sha512sum "$file" 2>/dev/null | awk '{print $1}' ;;
        md5)    md5sum    "$file" 2>/dev/null | awk '{print $1}' ;;
        *)      sha256sum "$file" 2>/dev/null | awk '{print $1}' ;;
    esac
}

# Expande lista de paths a archivos individuales, imprime uno por línea
expand_paths() {
    local p
    for p in "$@"; do
        [[ -z "$p" ]] && continue
        [[ ! -e "$p" ]] && continue
        if [[ -f "$p" ]]; then
            printf '%s\n' "$p"
        elif [[ -d "$p" ]]; then
            find "$p" -maxdepth 3 -type f 2>/dev/null
        fi
    done
}

load_watch_list() {
    local extra=()
    if [[ -f "$CUSTOM_LIST_FILE" ]]; then
        while IFS= read -r line; do
            [[ "$line" =~ ^# || -z "$line" ]] && continue
            extra+=("$line")
        done < "$CUSTOM_LIST_FILE"
    fi
    expand_paths "${DEFAULT_WATCH_FILES[@]}" "${extra[@]:-}"
}

cmd_init() {
    log SECTION "Generando Baseline"

    if [[ -f "$BASELINE_FILE" ]]; then
        printf "\n${YELLOW}${BOLD}  [!] Ya existe un baseline en %s${RESET}\n" "$BASELINE_FILE"
        printf "  Deseas sobreescribirlo? [s/N]: "
        read -r answer
        if [[ "${answer,,}" != "s" ]]; then
            printf "  Operacion cancelada.\n"
            exit 0
        fi
        mkdir -p "$HISTORY_DIR"
        local ts_str; ts_str=$(date '+%Y%m%d_%H%M%S')
        cp "$BASELINE_FILE" "${HISTORY_DIR}/baseline_${ts_str}.db"
        log INFO "Baseline anterior guardado en ${HISTORY_DIR}/baseline_${ts_str}.db"
    fi

    mkdir -p "$BASELINE_DIR" "$HISTORY_DIR"
    chmod 700 "$BASELINE_DIR"

    {
        printf "# confguardian baseline\n"
        printf "# Generado: %s\n" "$(ts)"
        printf "# Algoritmo: %s\n" "$HASH_ALGO"
        printf "# Host: %s\n" "$(hostname)"
        printf "#\n"
    } > "$BASELINE_FILE"

    local count=0
    local skipped=0

    while IFS= read -r filepath; do
        [[ -z "$filepath" ]] && continue
        local hash; hash=$(hash_file "$filepath")

        if [[ "$hash" == "NOFILE" ]]; then
            skipped=$(( skipped + 1 ))
            continue
        elif [[ "$hash" == "NOPERM" ]]; then
            log WARN "Sin permiso de lectura: $filepath"
            skipped=$(( skipped + 1 ))
            continue
        fi

        local perms; perms=$(stat -c '%a'    "$filepath" 2>/dev/null || echo "?")
        local owner; owner=$(stat -c '%U:%G' "$filepath" 2>/dev/null || echo "?")
        local size;  size=$(stat  -c '%s'    "$filepath" 2>/dev/null || echo "0")
        local mtime; mtime=$(stat -c '%Y'    "$filepath" 2>/dev/null || echo "0")

        printf "%s|%s|%s|%s|%s|%s\n" \
            "$filepath" "$hash" "$perms" "$owner" "$size" "$mtime" \
            >> "$BASELINE_FILE"

        log INFO "  [+] Registrado: $filepath"
        count=$(( count + 1 ))
    done < <(load_watch_list)

    chmod 600 "$BASELINE_FILE"

    printf "\n${GREEN}${BOLD}  [OK] Baseline generado: %d archivos registrados" "$count"
    [[ $skipped -gt 0 ]] && printf "  (%d omitidos)" "$skipped"
    printf "${RESET}\n  ${DIM}Guardado en: %s${RESET}\n\n" "$BASELINE_FILE"
}

cmd_check() {
    local silent="${1:-false}"

    if [[ ! -f "$BASELINE_FILE" ]]; then
        printf "${RED}${BOLD}[X] No existe baseline. Ejecuta primero: sudo $0 init${RESET}\n"
        exit 1
    fi

    [[ "$silent" != "true" ]] && log SECTION "Verificando Integridad"

    # Cargar baseline en arrays asociativos
    declare -A BL_HASH BL_PERMS BL_OWNER

    while IFS='|' read -r filepath hash perms owner size mtime; do
        [[ "$filepath" =~ ^# || -z "$filepath" ]] && continue
        BL_HASH["$filepath"]="$hash"
        BL_PERMS["$filepath"]="$perms"
        BL_OWNER["$filepath"]="$owner"
    done < "$BASELINE_FILE"

    # Fase 1: verificar archivos del baseline
    local fp
    for fp in "${!BL_HASH[@]}"; do
        if [[ ! -e "$fp" ]]; then
            log DELETED "$fp  ->  ARCHIVO ELIMINADO"
            COUNT_DELETED=$(( COUNT_DELETED + 1 ))
            continue
        fi

        local current_hash; current_hash=$(hash_file "$fp")
        local current_perms; current_perms=$(stat -c '%a'    "$fp" 2>/dev/null || echo "?")
        local current_owner; current_owner=$(stat -c '%U:%G' "$fp" 2>/dev/null || echo "?")

        local changed=false
        local change_details=""

        if [[ "$current_hash" != "${BL_HASH[$fp]}" ]]; then
            changed=true
            change_details+="    hash:      ${BL_HASH[$fp]:0:16}...  ->  ${current_hash:0:16}...\n"
        fi
        if [[ "$current_perms" != "${BL_PERMS[$fp]}" ]]; then
            changed=true
            change_details+="    permisos:  ${BL_PERMS[$fp]}  ->  ${current_perms}\n"
        fi
        if [[ "$current_owner" != "${BL_OWNER[$fp]}" ]]; then
            changed=true
            change_details+="    propiet.:  ${BL_OWNER[$fp]}  ->  ${current_owner}\n"
        fi

        if $changed; then
            log ALERT "$fp  ->  MODIFICADO"
            printf "%b" "$change_details"
            COUNT_MODIFIED=$(( COUNT_MODIFIED + 1 ))
        else
            [[ "$silent" != "true" ]] && log OK "$fp"
            COUNT_OK=$(( COUNT_OK + 1 ))
        fi
    done

    # Fase 2: detectar archivos nuevos
    while IFS= read -r filepath; do
        [[ -z "$filepath" ]] && continue
        if [[ -z "${BL_HASH[$filepath]+x}" ]]; then
            log NEW "$filepath  ->  ARCHIVO NUEVO (no estaba en el baseline)"
            COUNT_NEW=$(( COUNT_NEW + 1 ))
        fi
    done < <(load_watch_list)

    [[ "$silent" != "true" ]] && print_check_summary
}

cmd_watch() {
    if [[ ! -f "$BASELINE_FILE" ]]; then
        printf "${RED}${BOLD}[X] No existe baseline. Ejecuta primero: sudo $0 init${RESET}\n"
        exit 1
    fi

    print_banner
    printf "${BOLD}${YELLOW}  Modo WATCH activo — intervalo: %ds${RESET}\n" "$WATCH_INTERVAL"
    printf "${DIM}  Presiona Ctrl+C para detener.${RESET}\n\n"

    local iteration=0
    trap 'printf "\n${DIM}  confguardian watch detenido.${RESET}\n\n"; exit 0' INT TERM

    while true; do
        iteration=$(( iteration + 1 ))
        COUNT_OK=0; COUNT_MODIFIED=0; COUNT_DELETED=0; COUNT_NEW=0

        printf "${DIM}  [%s] Iteracion #%d — verificando...${RESET}" "$(ts)" "$iteration"

        cmd_check "true"

        local total_issues=$(( COUNT_MODIFIED + COUNT_DELETED + COUNT_NEW ))
        if [[ $total_issues -gt 0 ]]; then
            printf "\r${RED}${BOLD}  [%s] [!] %d cambio(s) detectado(s)!                    ${RESET}\n" \
                "$(ts)" "$total_issues"
        else
            printf "\r${GREEN}  [%s] [OK] %d archivos OK — sin cambios.                 ${RESET}\n" \
                "$(ts)" "$COUNT_OK"
        fi
        sleep "$WATCH_INTERVAL"
    done
}

cmd_report() {
    log SECTION "Historial de Alertas"

    if [[ ! -f "$ALERT_LOG" ]]; then
        printf "\n  ${DIM}No hay alertas registradas todavia.${RESET}\n\n"
        return
    fi

    local total_alerts; total_alerts=$(grep -c '^\[' "$ALERT_LOG" 2>/dev/null || echo 0)
    local modified_count; modified_count=$(grep -c '\[MODIFIED\]' "$ALERT_LOG" 2>/dev/null || echo 0)
    local deleted_count;  deleted_count=$(grep -c '\[DELETED\]'  "$ALERT_LOG" 2>/dev/null || echo 0)
    local new_count;      new_count=$(grep -c '\[NEW\]'          "$ALERT_LOG" 2>/dev/null || echo 0)

    printf "\n  ${BOLD}Resumen:${RESET}\n"
    printf "  Total alertas   : %s\n" "$total_alerts"
    printf "  ${YELLOW}Modificaciones  : %s${RESET}\n" "$modified_count"
    printf "  ${RED}Eliminaciones   : %s${RESET}\n" "$deleted_count"
    printf "  ${MAGENTA}Archivos nuevos : %s${RESET}\n\n" "$new_count"

    printf "${BOLD}  Ultimas 20 entradas:${RESET}\n"
    printf "  %s\n" "$(printf -- '-%.0s' {1..60})"
    tail -20 "$ALERT_LOG" | while IFS= read -r line; do
        printf "  %s\n" "$line"
    done
    printf "  %s\n\n" "$(printf -- '-%.0s' {1..60})"
}

cmd_add() {
    local target="${ADD_TARGET:-}"
    if [[ -z "$target" ]]; then
        printf "${RED}[X] Indica una ruta: sudo $0 add <ruta>${RESET}\n"
        exit 1
    fi
    if [[ ! -e "$target" ]]; then
        printf "${RED}[X] La ruta no existe: %s${RESET}\n" "$target"
        exit 1
    fi

    mkdir -p "$BASELINE_DIR"
    touch "$CUSTOM_LIST_FILE"

    if grep -qF "$target" "$CUSTOM_LIST_FILE" 2>/dev/null; then
        printf "${YELLOW}[!] La ruta ya esta en la lista: %s${RESET}\n" "$target"
    else
        printf "%s\n" "$target" >> "$CUSTOM_LIST_FILE"
        log INFO "Ruta anadida a monitorizacion: $target"
    fi

    if [[ -f "$BASELINE_FILE" ]]; then
        local added=0
        while IFS= read -r filepath; do
            [[ -z "$filepath" ]] && continue
            if ! grep -qF "$filepath" "$BASELINE_FILE" 2>/dev/null; then
                local hash; hash=$(hash_file "$filepath")
                [[ "$hash" == "NOFILE" || "$hash" == "NOPERM" ]] && continue
                local perms; perms=$(stat -c '%a'    "$filepath" 2>/dev/null || echo "?")
                local owner; owner=$(stat -c '%U:%G' "$filepath" 2>/dev/null || echo "?")
                local size;  size=$(stat  -c '%s'    "$filepath" 2>/dev/null || echo "0")
                local mtime; mtime=$(stat -c '%Y'    "$filepath" 2>/dev/null || echo "0")
                printf "%s|%s|%s|%s|%s|%s\n" \
                    "$filepath" "$hash" "$perms" "$owner" "$size" "$mtime" \
                    >> "$BASELINE_FILE"
                log INFO "  [+] Anadido al baseline: $filepath"
                added=$(( added + 1 ))
            fi
        done < <(expand_paths "$target")
        printf "${GREEN}${BOLD}  [OK] %d archivo(s) anadido(s) al baseline.${RESET}\n\n" "$added"
    else
        printf "${YELLOW}  [i] No hay baseline activo. Ejecuta 'init' para crearlo.${RESET}\n\n"
    fi
}

cmd_reset() {
    printf "\n${RED}${BOLD}  [!] Esto eliminara el baseline y todo el historial.${RESET}\n"
    printf "  Estas seguro? [s/N]: "
    read -r answer
    if [[ "${answer,,}" != "s" ]]; then
        printf "  Operacion cancelada.\n\n"
        exit 0
    fi
    rm -rf "$BASELINE_DIR"
    printf "${GREEN}${BOLD}  [OK] Baseline e historial eliminados.${RESET}\n\n"
}

print_check_summary() {
    local total=$(( COUNT_OK + COUNT_MODIFIED + COUNT_DELETED + COUNT_NEW ))
    printf "\n${BOLD}================================================${RESET}\n"
    printf "${BOLD}  RESULTADO DE VERIFICACION${RESET}\n"
    printf "${BOLD}================================================${RESET}\n"
    printf "  Archivos verificados : %d\n" "$total"
    printf "  ${GREEN}[OK]  Sin cambios    : %d${RESET}\n" "$COUNT_OK"
    printf "  ${YELLOW}[ALT] Modificados   : %d${RESET}\n" "$COUNT_MODIFIED"
    printf "  ${RED}[DEL] Eliminados    : %d${RESET}\n" "$COUNT_DELETED"
    printf "  ${MAGENTA}[NEW] Nuevos        : %d${RESET}\n" "$COUNT_NEW"
    printf "${BOLD}================================================${RESET}\n"

    local issues=$(( COUNT_MODIFIED + COUNT_DELETED + COUNT_NEW ))
    if [[ $issues -gt 0 ]]; then
        printf "\n${RED}${BOLD}  [!] %d cambio(s) detectado(s). Revisar inmediatamente.${RESET}\n" "$issues"
        printf "${DIM}     Log: %s${RESET}\n\n" "$ALERT_LOG"
    else
        printf "\n${GREEN}${BOLD}  [OK] Integridad confirmada. Ningun archivo modificado.${RESET}\n\n"
    fi
}

print_banner() {
    printf "${BOLD}${BLUE}  confguardian — Monitorizacion de Integridad de Configuracion — v1.0${RESET}\n"
    printf "${DIM}  %s  |  Host: %s  |  Algoritmo: %s${RESET}\n\n" \
        "$(ts)" "$(hostname)" "$HASH_ALGO"
}

check_requirements() {
    if [[ $EUID -ne 0 ]]; then
        printf "${RED}${BOLD}[X] confguardian requiere privilegios de root (sudo).${RESET}\n"
        exit 1
    fi
    case "$HASH_ALGO" in
        sha256) command -v sha256sum &>/dev/null || { printf "${RED}sha256sum no disponible.${RESET}\n"; exit 1; } ;;
        sha512) command -v sha512sum &>/dev/null || { printf "${RED}sha512sum no disponible.${RESET}\n"; exit 1; } ;;
        md5)    command -v md5sum    &>/dev/null || { printf "${RED}md5sum no disponible.${RESET}\n";    exit 1; } ;;
    esac
}

main() {
    parse_args "$@"
    check_requirements
    [[ "$MODE" != "watch" ]] && print_banner

    case "$MODE" in
        init)   cmd_init   ;;
        check)  cmd_check  ;;
        watch)  cmd_watch  ;;
        report) cmd_report ;;
        add)    cmd_add    ;;
        reset)  cmd_reset  ;;
        *)
            printf "${RED}[X] Modo desconocido: '%s'${RESET}\n\n" "$MODE"
            usage ;;
    esac
}

main "$@"
