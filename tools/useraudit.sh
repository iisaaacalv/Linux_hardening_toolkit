#!/usr/bin/env bash
# ============================================================
#  useraudit — Auditoría de Cuentas de Usuario y Privilegios
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

OUTPUT_FORMAT="text"
LOGFILE=""
INACTIVITY_DAYS=90
SHOW_SAFE=false

COUNT_CRITICAL=0
COUNT_WARNING=0
COUNT_INFO=0
COUNT_OK=0

# Acumulador para CSV/JSON — usamos fichero temporal para evitar problemas con arrays+pipelines
FINDINGS_FILE=""

INTERACTIVE_SHELLS=(
    /bin/bash /bin/sh /bin/zsh /bin/ksh /bin/tcsh /bin/csh
    /usr/bin/bash /usr/bin/sh /usr/bin/zsh /usr/bin/ksh
    /usr/bin/fish /usr/bin/tcsh /usr/bin/csh
)

KNOWN_SYSTEM_USERS=(
    root daemon bin sys sync games man lp mail news uucp proxy
    www-data backup list irc gnats nobody systemd-network
    systemd-resolve systemd-timesync messagebus syslog _apt
    tss uuidd tcpdump sshd landscape pollinate fwupd-refresh
    dnsmasq avahi avahi-autoipd cups colord mysql postgres
    mongodb redis rabbitmq elasticsearch nginx apache www caddy
    postfix dovecot chrony ntpd systemd-coredump systemd-oom
    debian-tor _dnscrypt-proxy
)

is_known_system_user() {
    local u="$1"
    for known in "${KNOWN_SYSTEM_USERS[@]}"; do
        [[ "$u" == "$known" ]] && return 0
    done
    return 1
}

is_interactive_shell() {
    local shell="$1"
    for s in "${INTERACTIVE_SHELLS[@]}"; do
        [[ "$shell" == "$s" ]] && return 0
    done
    return 1
}

usage() {
    cat << EOF
Uso:
  sudo $0 [opciones]

Opciones:
  --format <tipo>       text | csv | json  [text]
  --log <fichero>       Guarda el informe en el fichero indicado
  --inactive-days <n>  Dias sin login para marcar inactiva  [90]
  --show-safe           Muestra tambien usuarios sin problemas
EOF
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --format)        shift; OUTPUT_FORMAT="${1:-text}" ;;
            --log)           shift; LOGFILE="${1:-}" ;;
            --inactive-days) shift; INACTIVITY_DAYS="${1:-90}" ;;
            --show-safe)     SHOW_SAFE=true ;;
            -h|--help)       usage ;;
            *) printf "Opcion desconocida: %s\n" "$1"; usage ;;
        esac
        shift
    done
    [[ -n "$LOGFILE" ]] && > "$LOGFILE"
    # Fichero temporal para findings
    FINDINGS_FILE=$(mktemp /tmp/useraudit_findings.XXXXXX)
}

ts() { date '+%Y-%m-%d %H:%M:%S'; }

finding() {
    local level="$1" user="$2" check="$3" detail="$4"

    case "$level" in
        CRITICAL) COUNT_CRITICAL=$(( COUNT_CRITICAL + 1 )) ;;
        WARNING)  COUNT_WARNING=$(( COUNT_WARNING + 1 ))   ;;
        INFO)     COUNT_INFO=$(( COUNT_INFO + 1 ))         ;;
        OK)       COUNT_OK=$(( COUNT_OK + 1 ))             ;;
    esac

    # Guardar en fichero temporal para CSV/JSON
    printf '%s\t%s\t%s\t%s\n' "$level" "$user" "$check" "$detail" >> "$FINDINGS_FILE"

    [[ "$OUTPUT_FORMAT" != "text" ]] && return
    [[ "$level" == "OK" ]] && ! $SHOW_SAFE && return

    [[ -n "$LOGFILE" ]] && printf "[%s] [%s] user=%-20s check=%-30s detail=%s\n" \
        "$(ts)" "$level" "$user" "$check" "$detail" >> "$LOGFILE"

    case "$level" in
        CRITICAL) printf "  ${RED}${BOLD}[CRITICAL]${RESET} ${RED}%-20s${RESET}  %s — %s\n"   "$user" "$check" "$detail" ;;
        WARNING)  printf "  ${YELLOW}${BOLD}[WARNING] ${RESET} ${YELLOW}%-20s${RESET}  %s — %s\n"  "$user" "$check" "$detail" ;;
        INFO)     printf "  ${CYAN}[INFO]    ${RESET} %-20s  %s — %s\n"                            "$user" "$check" "$detail" ;;
        OK)       printf "  ${GREEN}[OK]      ${RESET} %-20s  %s\n"                                "$user" "$check" ;;
    esac
}

section() {
    [[ "$OUTPUT_FORMAT" != "text" ]] && return
    printf "\n${BOLD}=== %s ===${RESET}\n" "$1"
}

# ── Cargar shadow ──────────────────────────────────────────────
declare -A SHADOW_PASS SHADOW_LASTCHG SHADOW_MAX SHADOW_EXPIRE

load_shadow() {
    [[ ! -f /etc/shadow || ! -r /etc/shadow ]] && return
    while IFS=':' read -r user pass lastchg min max warn inactive expire _rest; do
        SHADOW_PASS["$user"]="${pass:-}"
        SHADOW_LASTCHG["$user"]="${lastchg:-0}"
        SHADOW_MAX["$user"]="${max:-}"
        SHADOW_EXPIRE["$user"]="${expire:-}"
    done < /etc/shadow
}

days_since_epoch() { printf "%d" $(( $(date +%s) / 86400 )); }

last_login_days() {
    local user="$1"
    if command -v lastlog &>/dev/null; then
        local raw; raw=$(lastlog -u "$user" 2>/dev/null | tail -1)
        if ! echo "$raw" | grep -qi 'never logged\|**Never'; then
            local date_str; date_str=$(echo "$raw" | awk '{print $4,$5,$6,$7,$8}' 2>/dev/null)
            if [[ -n "$date_str" ]]; then
                local last_ts; last_ts=$(date -d "$date_str" +%s 2>/dev/null || echo "")
                if [[ -n "$last_ts" && "$last_ts" -gt 0 ]]; then
                    printf "%d" $(( ( $(date +%s) - last_ts ) / 86400 ))
                    return
                fi
            fi
        fi
    fi
    printf "%d" -1
}

# ── Módulos ────────────────────────────────────────────────────

audit_uid0() {
    section "Usuarios con UID 0 (privilegios root)"
    while IFS=':' read -r user _pass uid _rest; do
        [[ "$user" =~ ^# || -z "$user" ]] && continue
        if [[ "$uid" == "0" ]]; then
            if [[ "$user" == "root" ]]; then
                finding OK "root" "UID 0" "Cuenta root legitima"
            else
                finding CRITICAL "$user" "UID 0" \
                    "Usuario no-root con UID 0 — acceso completo al sistema"
            fi
        fi
    done < /etc/passwd
}

audit_no_password() {
    section "Cuentas sin contrasena o con hash invalido"
    if [[ ! -r /etc/shadow ]]; then
        finding INFO "sistema" "shadow" "Sin acceso a /etc/shadow — ejecutar como root"
        return
    fi
    while IFS=':' read -r user _pass uid _rest; do
        [[ "$user" =~ ^# || -z "$user" ]] && continue
        # Leer pass directamente de /etc/shadow para este usuario (evita problemas de array)
        local pass
        pass=$(grep -E "^${user}:" /etc/shadow 2>/dev/null | cut -d: -f2 || echo "NOENTRY")
        [[ -z "$pass" ]] && pass="NOENTRY"

        # Determinar si es usuario humano (UID >= 1000) o de sistema
        local is_human=false
        if [[ "$uid" =~ ^[0-9]+$ ]] && [[ "$uid" -ge 1000 ]]; then
            is_human=true
        fi

        case "$pass" in
            "")
                finding CRITICAL "$user" "Sin contrasena" "Campo de hash vacio — acceso libre sin autenticacion"
                ;;
            "!")
                # Un solo ! — useradd sin password en Kali/Arch/algunas distros
                if $is_human; then
                    finding CRITICAL "$user" "Sin contrasena establecida" "! en shadow — usuario humano (UID=$uid) sin contrasena asignada"
                else
                    finding OK "$user" "Cuenta de sistema bloqueada" "! — login deshabilitado (UID=$uid)"
                fi
                ;;
            "!!")
                # Dos !! exactos — useradd sin password en Debian/Ubuntu
                if $is_human; then
                    finding CRITICAL "$user" "Sin contrasena establecida" "!! en shadow — usuario humano (UID=$uid) sin contrasena asignada nunca"
                else
                    finding OK "$user" "Cuenta de sistema sin login" "!! — sin contrasena, bloqueada (UID=$uid)"
                fi
                ;;
            "!!"*)
                # !! con sufijo (timestamp de bloqueo)
                if $is_human; then
                    finding CRITICAL "$user" "Sin contrasena establecida" "!! en shadow — usuario humano (UID=$uid) sin contrasena asignada"
                else
                    finding OK "$user" "Cuenta de sistema bloqueada" "!!... — bloqueada (UID=$uid)"
                fi
                ;;
            "*")
                finding OK "$user" "Sin login" "* — login por contrasena deshabilitado"
                ;;
            "!"*)
                # Cualquier otro patron con ! (ej: !hash) — cuenta con contrasena bloqueada
                if $is_human; then
                    finding WARNING "$user" "Cuenta bloqueada con hash" "!hash en shadow — cuenta humana bloqueada (UID=$uid)"
                else
                    finding OK "$user" "Cuenta de sistema bloqueada" "! prefijo — bloqueada (UID=$uid)"
                fi
                ;;
            \$1\$*|\$2*|\$5\$*|\$6\$*|\$y\$*)
                finding OK "$user" "Contrasena establecida" "hash valido (${pass:0:3}...)"
                ;;
            NOENTRY)
                ;; # usuario sin entrada en shadow, se trata en duplicados
            *)
                finding WARNING "$user" "Hash sospechoso" "Formato no reconocido: '${pass:0:8}...'"
                ;;
        esac
    done < /etc/passwd
}

audit_password_policy() {
    section "Politicas de contrasena (expiracion)"
    [[ ! -r /etc/shadow ]] && return
    local today; today=$(days_since_epoch)

    while IFS=':' read -r user _pass uid _rest; do
        [[ "$user" =~ ^# || -z "$user" ]] && continue
        local pass="${SHADOW_PASS[$user]:-}"
        [[ "$pass" == "!"* || "$pass" == "*" || -z "$pass" ]] && continue

        local maxdays="${SHADOW_MAX[$user]:-}"
        local lastchg="${SHADOW_LASTCHG[$user]:-0}"
        local expire="${SHADOW_EXPIRE[$user]:-}"

        if [[ -z "$maxdays" || "$maxdays" == "99999" || "$maxdays" == "-1" ]]; then
            if ! is_known_system_user "$user"; then
                finding WARNING "$user" "Sin caducidad de contrasena" "MAX_DAYS no configurado"
            fi
        elif [[ -n "$maxdays" && "$lastchg" -gt 0 ]]; then
            local remaining=$(( lastchg + maxdays - today ))
            if [[ $remaining -lt 0 ]]; then
                finding WARNING "$user" "Contrasena expirada" "Expiro hace $(( -remaining )) dias"
            elif [[ $remaining -lt 14 ]]; then
                finding INFO "$user" "Contrasena proxima a expirar" "Expira en ${remaining} dias"
            fi
        fi

        if [[ -n "$expire" && "$expire" -gt 0 ]]; then
            local days_left=$(( expire - today ))
            if [[ $days_left -lt 0 ]]; then
                finding WARNING "$user" "Cuenta expirada" \
                    "Fecha: $(date -d "@$(( expire * 86400 ))" '+%Y-%m-%d' 2>/dev/null || echo 'desconocida')"
            elif [[ $days_left -lt 30 ]]; then
                finding INFO "$user" "Cuenta proxima a expirar" "Expira en ${days_left} dias"
            fi
        fi
    done < /etc/passwd
}

audit_inactive_users() {
    section "Cuentas inactivas (sin login en +${INACTIVITY_DAYS} dias)"
    local inactive_count=0

    while IFS=':' read -r user _pass uid _gid _gecos home shell; do
        [[ "$user" =~ ^# || -z "$user" ]] && continue
        if [[ "$uid" -lt 1000 && "$user" != "root" ]]; then continue; fi

        local pass="${SHADOW_PASS[$user]:-}"
        [[ "$pass" == "!"* || "$pass" == "*" ]] && continue

        local days_since; days_since=$(last_login_days "$user")
        if [[ "$days_since" -eq -1 ]]; then
            finding INFO "$user" "Nunca ha iniciado sesion" "UID=$uid  shell=$shell"
            inactive_count=$(( inactive_count + 1 ))
        elif [[ "$days_since" -gt "$INACTIVITY_DAYS" ]]; then
            finding WARNING "$user" "Cuenta inactiva" "Sin login desde hace ${days_since} dias (umbral: ${INACTIVITY_DAYS}d)"
            inactive_count=$(( inactive_count + 1 ))
        else
            finding OK "$user" "Cuenta activa" "Ultimo login hace ${days_since} dias"
        fi
    done < /etc/passwd

    [[ "$OUTPUT_FORMAT" == "text" && $inactive_count -gt 0 ]] && \
        printf "  ${DIM}  -> %d cuenta(s) inactiva(s)${RESET}\n" "$inactive_count"
}

audit_service_shells() {
    section "Shells interactivas en cuentas de servicio"
    while IFS=':' read -r user _pass uid _gid _gecos home shell; do
        [[ "$user" =~ ^# || -z "$user" ]] && continue
        [[ "$uid" -ge 1000 || "$user" == "root" ]] && continue

        if is_interactive_shell "$shell"; then
            if is_known_system_user "$user"; then
                finding WARNING "$user" "Shell interactiva en cuenta de servicio" \
                    "shell=$shell  UID=$uid"
            else
                finding CRITICAL "$user" "Shell interactiva en cuenta desconocida" \
                    "shell=$shell  UID=$uid"
            fi
        else
            finding OK "$user" "Shell restringida" "shell=${shell:-nologin}  UID=$uid"
        fi
    done < /etc/passwd
}

audit_duplicates() {
    section "Duplicados e inconsistencias"

    local dup_uids; dup_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
    if [[ -n "$dup_uids" ]]; then
        while IFS= read -r uid; do
            local users_with_uid; users_with_uid=$(awk -F: -v u="$uid" '$3==u{print $1}' /etc/passwd | tr '\n' ' ')
            finding CRITICAL "UID=$uid" "UID duplicado" "Compartido por: $users_with_uid"
        done <<< "$dup_uids"
    else
        finding OK "sistema" "UIDs unicos" "Sin UIDs duplicados"
    fi

    local dup_names; dup_names=$(awk -F: '{print $1}' /etc/passwd | sort | uniq -d)
    if [[ -n "$dup_names" ]]; then
        while IFS= read -r uname; do
            finding CRITICAL "$uname" "Nombre de usuario duplicado" "Aparece mas de una vez en /etc/passwd"
        done <<< "$dup_names"
    fi

    if [[ -f /etc/group ]]; then
        local dup_gids; dup_gids=$(awk -F: '{print $3}' /etc/group | sort | uniq -d)
        if [[ -n "$dup_gids" ]]; then
            while IFS= read -r gid; do
                local groups_with_gid; groups_with_gid=$(awk -F: -v g="$gid" '$3==g{print $1}' /etc/group | tr '\n' ' ')
                finding WARNING "GID=$gid" "GID duplicado" "Grupos: $groups_with_gid"
            done <<< "$dup_gids"
        else
            finding OK "sistema" "GIDs unicos" "Sin GIDs duplicados"
        fi
    fi

    if [[ -r /etc/shadow ]]; then
        while IFS=':' read -r suser _rest; do
            [[ "$suser" =~ ^# || -z "$suser" ]] && continue
            if ! grep -qE "^${suser}:" /etc/passwd 2>/dev/null; then
                finding WARNING "$suser" "En shadow pero no en passwd" "Entrada huerfana en /etc/shadow"
            fi
        done < /etc/shadow
    fi
}

audit_sudo_privileges() {
    section "Privilegios sudo y grupos privilegiados"

    if [[ -r /etc/sudoers ]]; then
        while IFS= read -r line; do
            [[ "$line" =~ ^# || -z "$line" ]] && continue
            if echo "$line" | grep -qE '^\s*[^%#][^ ]+\s+ALL\s*='; then
                local sudouser; sudouser=$(echo "$line" | awk '{print $1}')
                if [[ "$sudouser" != "root" ]]; then
                    finding WARNING "$sudouser" "sudo sin restricciones" "Tiene acceso sudo ALL"
                fi
            fi
            if echo "$line" | grep -qE 'NOPASSWD'; then
                local sudouser; sudouser=$(echo "$line" | awk '{print $1}')
                finding WARNING "$sudouser" "sudo NOPASSWD" \
                    "Puede ejecutar sudo sin contrasena"
            fi
        done < /etc/sudoers
    fi

    if [[ -d /etc/sudoers.d ]]; then
        while IFS= read -r -d '' sudofile; do
            [[ -r "$sudofile" ]] || continue
            while IFS= read -r line; do
                [[ "$line" =~ ^# || -z "$line" ]] && continue
                if echo "$line" | grep -qE 'NOPASSWD'; then
                    local sudouser; sudouser=$(echo "$line" | awk '{print $1}')
                    finding WARNING "$sudouser" "sudo NOPASSWD (sudoers.d)" \
                        "En $(basename "$sudofile")"
                fi
            done < "$sudofile"
        done < <(find /etc/sudoers.d -maxdepth 1 -type f -print0 2>/dev/null)
    fi

    local priv_groups=(sudo wheel adm admin docker lxd disk shadow)
    for grp in "${priv_groups[@]}"; do
        if getent group "$grp" &>/dev/null; then
            local members; members=$(getent group "$grp" | awk -F: '{print $4}')
            if [[ -n "$members" ]]; then
                local member_count; member_count=$(echo "$members" | tr ',' '\n' | grep -c '.' || echo 0)
                case "$grp" in
                    docker|lxd|disk) finding WARNING "grupo:$grp" "Grupo con escalada de privilegios" "Miembros ($member_count): $members" ;;
                    shadow)          finding INFO    "grupo:$grp" "Grupo shadow" "Miembros ($member_count): $members" ;;
                    *)               finding INFO    "grupo:$grp" "Grupo privilegiado" "Miembros ($member_count): $members" ;;
                esac
            else
                finding OK "grupo:$grp" "Grupo privilegiado vacio" "Sin miembros directos"
            fi
        fi
    done
}

audit_home_dirs() {
    section "Directorios home de usuarios"
    while IFS=':' read -r user _pass uid _gid _gecos home shell; do
        [[ "$user" =~ ^# || -z "$user" ]] && continue
        [[ "$uid" -lt 1000 && "$user" != "root" ]] && continue
        [[ -z "$home" || "$home" == "/" ]] && continue

        if [[ ! -d "$home" ]]; then
            finding INFO "$user" "Directorio home inexistente" "home=$home (UID=$uid)"
        else
            local perm; perm=$(stat -c '%a' "$home" 2>/dev/null || echo "?")
            local owner; owner=$(stat -c '%U' "$home" 2>/dev/null || echo "?")

            if [[ "$owner" != "$user" && "$user" != "root" ]]; then
                finding WARNING "$user" "Home con propietario incorrecto" \
                    "home=$home propietario=$owner (esperado: $user)"
            fi

            if [[ "${perm: -1}" =~ [2367] ]]; then
                finding WARNING "$user" "Home world-writable" "home=$home permisos=$perm"
            else
                finding OK "$user" "Permisos de home correctos" "home=$home permisos=$perm"
            fi
        fi
    done < /etc/passwd
}

audit_root_remote() {
    section "Acceso remoto de root"
    if [[ -f /etc/ssh/sshd_config ]]; then
        local permit_root; permit_root=$(grep -iE '^\s*PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null \
            | awk '{print $2}' | tail -1)
        case "${permit_root,,}" in
            "no")                  finding OK   "root" "PermitRootLogin" "Deshabilitado correctamente" ;;
            "prohibit-password"|"without-password")
                                   finding INFO "root" "PermitRootLogin" "Solo por clave publica ($permit_root)" ;;
            "yes")                 finding CRITICAL "root" "PermitRootLogin yes" "Login SSH de root habilitado" ;;
            "")                    finding WARNING  "root" "PermitRootLogin" "No configurado — revisar valor por defecto" ;;
            *)                     finding WARNING  "root" "PermitRootLogin valor desconocido" "Valor: '$permit_root'" ;;
        esac
    fi

    if [[ -f /etc/securetty ]]; then
        if grep -qE '^pts/' /etc/securetty 2>/dev/null; then
            finding WARNING "root" "/etc/securetty con pts/" "Root puede loguarse en terminales remotas"
        else
            finding OK "root" "/etc/securetty" "Sin entradas pts/"
        fi
    fi
}

# ── Salida CSV / JSON ──────────────────────────────────────────

output_csv() {
    printf "nivel,usuario,comprobacion,detalle\n"
    [[ -n "$LOGFILE" ]] && printf "nivel,usuario,comprobacion,detalle\n" >> "$LOGFILE"
    while IFS=$'\t' read -r level user check detail; do
        local row; row="\"$level\",\"$user\",\"$check\",\"$detail\""
        printf "%s\n" "$row"
        [[ -n "$LOGFILE" ]] && printf "%s\n" "$row" >> "$LOGFILE"
    done < "$FINDINGS_FILE"
}

output_json() {
    local first=true
    printf '{"scan_date":"%s","host":"%s","findings":[' "$(ts)" "$(hostname)"
    while IFS=$'\t' read -r level user check detail; do
        $first || printf ","
        first=false
        # Escapar comillas en los campos
        local u; u=$(printf '%s' "$user"   | sed 's/"/\\"/g')
        local c; c=$(printf '%s' "$check"  | sed 's/"/\\"/g')
        local d; d=$(printf '%s' "$detail" | sed 's/"/\\"/g')
        printf '{"nivel":"%s","usuario":"%s","comprobacion":"%s","detalle":"%s"}' \
            "$level" "$u" "$c" "$d"
    done < "$FINDINGS_FILE"
    printf ']}\n'
}

# ── Cabecera y resumen ─────────────────────────────────────────

print_banner() {
    [[ "$OUTPUT_FORMAT" != "text" ]] && return
    printf "${BOLD}${MAGENTA}  useraudit — Auditoria de Cuentas de Usuario y Privilegios — v1.0${RESET}\n"
    printf "${DIM}  %s  |  Host: %s  |  Inactividad: +%dd${RESET}\n\n" \
        "$(ts)" "$(hostname)" "$INACTIVITY_DAYS"
}

print_summary() {
    [[ "$OUTPUT_FORMAT" != "text" ]] && return
    local total=$(( COUNT_CRITICAL + COUNT_WARNING + COUNT_INFO + COUNT_OK ))
    printf "\n${BOLD}================================================${RESET}\n"
    printf "${BOLD}  RESUMEN — AUDITORIA DE USUARIOS${RESET}\n"
    printf "${BOLD}================================================${RESET}\n"
    printf "  Total hallazgos  : %d\n"                       "$total"
    printf "  ${RED}${BOLD}CRITICAL         : %d${RESET}\n"  "$COUNT_CRITICAL"
    printf "  ${YELLOW}${BOLD}WARNING          : %d${RESET}\n" "$COUNT_WARNING"
    printf "  ${CYAN}INFO             : %d${RESET}\n"         "$COUNT_INFO"
    printf "  ${GREEN}OK               : %d${RESET}\n"        "$COUNT_OK"
    printf "${BOLD}================================================${RESET}\n"

    if [[ $COUNT_CRITICAL -gt 0 ]]; then
        printf "\n${RED}${BOLD}  [!] %d hallazgo(s) CRITICO(S). Corregir de inmediato.${RESET}\n" "$COUNT_CRITICAL"
    elif [[ $COUNT_WARNING -gt 0 ]]; then
        printf "\n${YELLOW}${BOLD}  [!] %d advertencia(s) detectada(s). Revisar pronto.${RESET}\n" "$COUNT_WARNING"
    else
        printf "\n${GREEN}${BOLD}  [OK] Gestion de usuarios dentro de parametros seguros.${RESET}\n"
    fi
    [[ -n "$LOGFILE" ]] && printf "${DIM}\n  Log guardado en: %s${RESET}\n" "$LOGFILE"
    printf "\n"
}

check_requirements() {
    if [[ $EUID -ne 0 ]]; then
        printf "${RED}${BOLD}[X] useraudit requiere privilegios de root para leer /etc/shadow.${RESET}\n"
        exit 1
    fi
    [[ ! -f /etc/passwd ]] && { printf "${RED}[X] /etc/passwd no encontrado.${RESET}\n"; exit 1; }
}

cleanup() {
    [[ -n "${FINDINGS_FILE:-}" && -f "${FINDINGS_FILE:-}" ]] && rm -f "$FINDINGS_FILE"
}
trap cleanup EXIT

main() {
    parse_args "$@"
    check_requirements
    load_shadow
    print_banner

    audit_uid0
    audit_no_password
    audit_password_policy
    audit_inactive_users
    audit_service_shells
    audit_duplicates
    audit_sudo_privileges
    audit_home_dirs
    audit_root_remote

    case "$OUTPUT_FORMAT" in
        csv)  output_csv  ;;
        json) output_json ;;
    esac

    print_summary
}

main "$@"
