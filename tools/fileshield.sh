#!/usr/bin/env bash
# ============================================================
#  fileshield — Bastionado Activo de Permisos en Linux
#  Herramienta de bastionado | v1.0
# ============================================================

set -uo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

MODE="audit"
DRY_RUN=true
STRICT=false
LOGFILE=""

ISSUES_FOUND=0
FIXES_APPLIED=0
FIXES_SKIPPED=0

BACKUP_DIR="/var/backups/fileshield_$(date +%Y%m%d_%H%M%S)"

usage() {
    cat << EOF
Uso:
  sudo $0 [--audit | --apply | --strict] [--log <fichero>]

Modos:
  --audit   Solo muestra problemas detectados (sin cambios)  [por defecto]
  --apply   Corrige automaticamente permisos inseguros
  --strict  Endurecimiento agresivo

Opciones:
  --log <f> Guarda el resultado en el fichero indicado
EOF
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --audit)  MODE="audit";  DRY_RUN=true;  STRICT=false ;;
            --apply)  MODE="apply";  DRY_RUN=false; STRICT=false ;;
            --strict) MODE="strict"; DRY_RUN=false; STRICT=true  ;;
            --log)    shift; LOGFILE="${1:-}" ;;
            -h|--help) usage ;;
            *) printf "Opcion desconocida: %s\n" "$1"; usage ;;
        esac
        shift
    done
    [[ -n "$LOGFILE" ]] && > "$LOGFILE"
}

ts() { date '+%Y-%m-%d %H:%M:%S'; }

log() {
    local level="$1"; shift
    local msg="$*"

    case "$level" in
        ISSUE)   printf "  ${YELLOW}${BOLD}[!] ISSUE  ${RESET} ${YELLOW}%s${RESET}\n"  "$msg" ;;
        FIXED)   printf "  ${GREEN}${BOLD}[v] FIXED  ${RESET} ${GREEN}%s${RESET}\n"   "$msg" ;;
        SKIP)    printf "  ${DIM}[-] SKIP   %s${RESET}\n"                              "$msg" ;;
        OK)      printf "  ${GREEN}[OK]       ${RESET} %s\n"                           "$msg" ;;
        INFO)    printf "  ${CYAN}[INFO]     ${RESET} %s\n"                            "$msg" ;;
        STRICT)  printf "  ${MAGENTA}${BOLD}[*] STRICT ${RESET} ${MAGENTA}%s${RESET}\n" "$msg" ;;
        ERROR)   printf "  ${RED}${BOLD}[X] ERROR  ${RESET} ${RED}%s${RESET}\n"       "$msg" ;;
        SECTION) printf "\n${BOLD}=== %s ===${RESET}\n" "$msg" ;;
    esac

    [[ -n "$LOGFILE" ]] && printf "[%s] [%s] %s\n" "$(ts)" "$level" "$msg" >> "$LOGFILE"
}

apply_chmod() {
    local target="$1" expected="$2" description="${3:-}"
    [[ -e "$target" ]] || return 0

    local current; current=$(stat -c '%a' "$target" 2>/dev/null || echo "???")

    if [[ "$current" != "$expected" ]]; then
        log ISSUE "${description:-$target} tiene permisos $current (esperado: $expected)"
        ISSUES_FOUND=$(( ISSUES_FOUND + 1 ))
        if $DRY_RUN; then
            log SKIP  "chmod $expected \"$target\"  [usa --apply para corregir]"
            FIXES_SKIPPED=$(( FIXES_SKIPPED + 1 ))
        else
            if chmod "$expected" "$target" 2>/dev/null; then
                log FIXED "chmod $expected \"$target\""
                FIXES_APPLIED=$(( FIXES_APPLIED + 1 ))
            else
                log ERROR "No se pudo aplicar chmod $expected en \"$target\""
            fi
        fi
    else
        log OK "${description:-$target} — permisos $current"
    fi
}

apply_chown() {
    local target="$1" expected_owner="$2" expected_group="$3" description="${4:-}"
    [[ -e "$target" ]] || return 0

    local current_owner; current_owner=$(stat -c '%U' "$target" 2>/dev/null || echo "?")
    local current_group; current_group=$(stat -c '%G' "$target" 2>/dev/null || echo "?")

    if [[ "$current_owner" != "$expected_owner" || "$current_group" != "$expected_group" ]]; then
        log ISSUE "${description:-$target} — propietario: $current_owner:$current_group (esperado: $expected_owner:$expected_group)"
        ISSUES_FOUND=$(( ISSUES_FOUND + 1 ))
        if $DRY_RUN; then
            log SKIP  "chown $expected_owner:$expected_group \"$target\"  [usa --apply]"
            FIXES_SKIPPED=$(( FIXES_SKIPPED + 1 ))
        else
            if chown "$expected_owner:$expected_group" "$target" 2>/dev/null; then
                log FIXED "chown $expected_owner:$expected_group \"$target\""
                FIXES_APPLIED=$(( FIXES_APPLIED + 1 ))
            else
                log ERROR "No se pudo aplicar chown en \"$target\""
            fi
        fi
    else
        log OK "${description:-$target} — propietario $current_owner:$current_group"
    fi
}

strip_world_perms() {
    local basedir="$1" label="${2:-}"
    [[ -d "$basedir" ]] || return 0
    local found=0
    while IFS= read -r -d '' f; do
        local p; p=$(stat -c '%a' "$f" 2>/dev/null || echo "???")
        log ISSUE "World-writable en $label: $f (permisos: $p)"
        ISSUES_FOUND=$(( ISSUES_FOUND + 1 ))
        found=$(( found + 1 ))
        if ! $DRY_RUN; then
            if chmod o-w "$f" 2>/dev/null; then
                log FIXED "chmod o-w \"$f\""
                FIXES_APPLIED=$(( FIXES_APPLIED + 1 ))
            fi
        else
            log SKIP "chmod o-w \"$f\"  [usa --apply]"
            FIXES_SKIPPED=$(( FIXES_SKIPPED + 1 ))
        fi
    done < <(find "$basedir" -perm -0002 -print0 2>/dev/null)
    [[ $found -eq 0 ]] && log OK "Sin permisos world-writable en $label"
}

harden_critical_files() {
    log SECTION "Archivos criticos del sistema"
    apply_chmod  "/etc/passwd" "644" "/etc/passwd"
    apply_chown  "/etc/passwd" "root" "root" "/etc/passwd"

    local shadow_group="root"
    getent group shadow &>/dev/null && shadow_group="shadow"
    apply_chmod  "/etc/shadow" "640" "/etc/shadow"
    apply_chown  "/etc/shadow" "root" "$shadow_group" "/etc/shadow"

    [[ -f /etc/gshadow ]] && apply_chmod "/etc/gshadow" "640" "/etc/gshadow"
    apply_chmod  "/etc/group"   "644" "/etc/group"
    apply_chown  "/etc/group"   "root" "root" "/etc/group"

    if [[ -f /etc/sudoers ]]; then
        apply_chmod "/etc/sudoers" "440" "/etc/sudoers"
        apply_chown "/etc/sudoers" "root" "root" "/etc/sudoers"
    fi

    if [[ -d /etc/sudoers.d ]]; then
        while IFS= read -r -d '' f; do
            apply_chmod "$f" "440" "sudoers.d/$(basename "$f")"
        done < <(find /etc/sudoers.d -type f -print0 2>/dev/null)
    fi

    for cronpath in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.hourly; do
        [[ -e "$cronpath" ]] || continue
        apply_chmod "$cronpath" "600" "$cronpath"
        apply_chown "$cronpath" "root" "root" "$cronpath"
    done

    for f in /etc/hosts /etc/hostname /etc/resolv.conf; do
        [[ -f "$f" ]] || continue
        apply_chmod "$f" "644" "$f"
        apply_chown "$f" "root" "root" "$f"
    done

    if $STRICT && command -v chattr &>/dev/null; then
        log STRICT "Aplicando chattr +i a /etc/passwd, /etc/shadow, /etc/sudoers"
        if ! $DRY_RUN; then
            chattr +i /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null \
                && log FIXED "chattr +i aplicado" \
                || log ERROR "chattr +i fallo"
        fi
    fi
}

harden_root_home() {
    log SECTION "Directorio /root"
    [[ -d /root ]] || { log INFO "/root no existe."; return; }
    apply_chmod "/root" "700" "/root"
    apply_chown "/root" "root" "root" "/root"

    if $STRICT; then
        for f in /root/.bashrc /root/.bash_profile /root/.profile /root/.bash_history; do
            [[ -f "$f" ]] || continue
            apply_chmod "$f" "600" "$f"
        done
    fi
}

harden_home_dirs() {
    log SECTION "Directorios /home"
    [[ -d /home ]] || { log INFO "/home no existe."; return; }

    local target_perm="750"
    $STRICT && target_perm="700"

    while IFS= read -r -d '' homedir; do
        local owner; owner=$(stat -c '%U' "$homedir" 2>/dev/null || echo "?")
        apply_chmod "$homedir" "$target_perm" "home/$owner"
        apply_chown "$homedir" "$owner" "$owner" "home/$owner"
        strip_world_perms "$homedir" "home/$owner"
    done < <(find /home -maxdepth 1 -mindepth 1 -type d -print0 2>/dev/null)
}

harden_tmp() {
    log SECTION "/tmp y /var/tmp"
    for tmpdir in /tmp /var/tmp; do
        [[ -d "$tmpdir" ]] || continue
        apply_chmod "$tmpdir" "1777" "$tmpdir"
        apply_chown "$tmpdir" "root" "root" "$tmpdir"

        if $STRICT; then
            log STRICT "Buscando ejecutables en $tmpdir..."
            local found=0
            while IFS= read -r -d '' f; do
                log STRICT "Ejecutable en $tmpdir: $f"
                if ! $DRY_RUN; then
                    chmod a-x "$f" 2>/dev/null && {
                        log FIXED "chmod a-x \"$f\""
                        FIXES_APPLIED=$(( FIXES_APPLIED + 1 ))
                    }
                fi
                found=$(( found + 1 ))
            done < <(find "$tmpdir" -maxdepth 3 -type f -perm /111 -print0 2>/dev/null)
            [[ $found -eq 0 ]] && log OK "Sin ejecutables en $tmpdir"
        fi
    done
}

harden_var_www() {
    log SECTION "/var/www"
    [[ -d /var/www ]] || { log INFO "/var/www no existe en este sistema."; return; }

    local web_user="www-data"
    id "$web_user" &>/dev/null || web_user="apache"
    id "$web_user" &>/dev/null || web_user="root"

    apply_chmod "/var/www" "755" "/var/www"
    apply_chown "/var/www" "root" "$web_user" "/var/www"
    strip_world_perms "/var/www" "/var/www"

    if $STRICT && ! $DRY_RUN; then
        log STRICT "Aplicando permisos estrictos en /var/www (archivos: 640, dirs: 750)"
        find /var/www -type f -exec chmod 640 {} \; 2>/dev/null
        find /var/www -type d -exec chmod 750 {} \; 2>/dev/null
        log FIXED "Permisos 640/750 aplicados en /var/www"
        FIXES_APPLIED=$(( FIXES_APPLIED + 1 ))
    elif $STRICT && $DRY_RUN; then
        log SKIP "chmod 640/750 recursivo en /var/www  [usa --strict --apply]"
    fi
}

harden_ssh() {
    log SECTION "Configuracion SSH (~/.ssh)"

    local seen_dirs=()

    while IFS= read -r -d '' hdir; do
        local sshdir="$hdir/.ssh"
        [[ -d "$sshdir" ]] || continue

        # evitar duplicados
        local already=false
        for s in "${seen_dirs[@]:-}"; do [[ "$s" == "$sshdir" ]] && { already=true; break; }; done
        $already && continue
        seen_dirs+=("$sshdir")

        local owner; owner=$(stat -c '%U' "$hdir" 2>/dev/null || echo "root")
        apply_chmod "$sshdir" "700" "$sshdir"
        apply_chown "$sshdir" "$owner" "$owner" "$sshdir"

        while IFS= read -r -d '' sshfile; do
            local fname; fname=$(basename "$sshfile")
            case "$fname" in
                authorized_keys)
                    apply_chmod "$sshfile" "600" "$sshdir/authorized_keys"
                    apply_chown "$sshfile" "$owner" "$owner" "$sshdir/authorized_keys" ;;
                id_rsa|id_ecdsa|id_ed25519|id_dsa)
                    apply_chmod "$sshfile" "600" "$sshdir/$fname"
                    apply_chown "$sshfile" "$owner" "$owner" "$sshdir/$fname" ;;
                *.pub)
                    apply_chmod "$sshfile" "644" "$sshdir/$fname" ;;
                config)
                    apply_chmod "$sshfile" "600" "$sshdir/config" ;;
                known_hosts)
                    apply_chmod "$sshfile" "644" "$sshdir/known_hosts" ;;
            esac
        done < <(find "$sshdir" -maxdepth 1 -type f -print0 2>/dev/null)
    done < <(find /home /root -maxdepth 1 -mindepth 1 -type d -print0 2>/dev/null)

    if [[ -f /etc/ssh/sshd_config ]]; then
        apply_chmod "/etc/ssh/sshd_config" "600" "/etc/ssh/sshd_config"
        apply_chown "/etc/ssh/sshd_config" "root" "root" "/etc/ssh/sshd_config"
    fi
}

make_backup() {
    $DRY_RUN && return
    log INFO "Creando backup de permisos en $BACKUP_DIR ..."
    mkdir -p "$BACKUP_DIR"
    local snap="$BACKUP_DIR/perms_snapshot.txt"
    {
        for f in /etc/passwd /etc/shadow /etc/sudoers /etc/group \
                  /root /tmp /var/tmp /var/www /etc/ssh/sshd_config; do
            [[ -e "$f" ]] && stat -c '%n %a %U %G' "$f" 2>/dev/null
        done
        find /home -maxdepth 2 2>/dev/null | while read -r p; do
            stat -c '%n %a %U %G' "$p" 2>/dev/null
        done
    } > "$snap"
    log INFO "Snapshot guardado en $snap"
}

print_banner() {
    local mode_label mode_color
    case "$MODE" in
        audit)  mode_label="AUDIT  — Solo lectura";    mode_color="$CYAN"    ;;
        apply)  mode_label="APPLY  — Correccion auto"; mode_color="$GREEN"   ;;
        strict) mode_label="STRICT — Hardening total"; mode_color="$MAGENTA" ;;
    esac
    printf "${BOLD}${CYAN}  fileshield — Bastionado Activo de Permisos — v1.0${RESET}\n"
    printf "  Modo: ${mode_color}${BOLD}%s${RESET}\n" "$mode_label"
    printf "${DIM}  %s${RESET}\n\n" "$(date '+%Y-%m-%d %H:%M:%S')"
}

print_summary() {
    printf "\n${BOLD}================================================${RESET}\n"
    printf "${BOLD}  RESUMEN FILESHIELD${RESET}\n"
    printf "${BOLD}================================================${RESET}\n"
    printf "  Modo              : ${BOLD}%s${RESET}\n"           "${MODE^^}"
    printf "  Problemas hallados: ${YELLOW}${BOLD}%d${RESET}\n"  "$ISSUES_FOUND"
    printf "  Correcciones aplic: ${GREEN}${BOLD}%d${RESET}\n"   "$FIXES_APPLIED"
    printf "  Omitidas (dry-run): ${DIM}%d${RESET}\n"            "$FIXES_SKIPPED"
    printf "${BOLD}================================================${RESET}\n"

    if $DRY_RUN && [[ $ISSUES_FOUND -gt 0 ]]; then
        printf "\n${YELLOW}${BOLD}  Ejecuta con --apply para corregir automaticamente.${RESET}\n"
    elif ! $DRY_RUN && [[ $FIXES_APPLIED -gt 0 ]]; then
        printf "\n${GREEN}${BOLD}  %d correccion(es) aplicada(s) correctamente.${RESET}\n" "$FIXES_APPLIED"
    elif [[ $ISSUES_FOUND -eq 0 ]]; then
        printf "\n${GREEN}${BOLD}  Sistema bastionado: no se encontraron problemas.${RESET}\n"
    fi

    [[ -n "$LOGFILE" ]] && printf "${DIM}\n  Log guardado en: %s${RESET}\n" "$LOGFILE"
    printf "\n"
}

check_requirements() {
    if [[ $EUID -ne 0 ]]; then
        printf "${RED}${BOLD}[X] fileshield debe ejecutarse como root (sudo).${RESET}\n"
        exit 1
    fi
}

main() {
    parse_args "$@"
    print_banner
    check_requirements
    make_backup
    harden_critical_files
    harden_root_home
    harden_home_dirs
    harden_tmp
    harden_var_www
    harden_ssh
    print_summary
}

main "$@"
