#!/usr/bin/env bash
# ============================================================
#  porthush — Análisis de Superficie de Exposición de Red
#  Herramienta de bastionado | v1.0
# ============================================================

set -uo pipefail

# ── Colores ───────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Opciones ──────────────────────────────────────────────────
OUTPUT_FORMAT="text"   # text | csv | json
LOGFILE=""
SHOW_LOCAL=false       # mostrar también puertos en 127.0.0.1
FILTER_RISK=""         # filtrar por nivel: critical|warning|info

# ── Contadores ────────────────────────────────────────────────
COUNT_CRITICAL=0
COUNT_WARNING=0
COUNT_INFO=0
COUNT_SAFE=0

# ── Herramienta de red disponible ────────────────────────────
NET_TOOL=""

# ─────────────────────────────────────────────────────────────
# Uso
# ─────────────────────────────────────────────────────────────
usage() {
    cat << EOF
${BOLD}Uso:${RESET}
  sudo $0 [opciones]

${BOLD}Opciones:${RESET}
  ${CYAN}--show-local${RESET}          Incluye puertos en 127.0.0.1 en el informe
  ${CYAN}--filter <nivel>${RESET}      Muestra solo: critical | warning | info
  ${CYAN}--format <tipo>${RESET}       Formato de salida: text | csv | json  [por defecto: text]
  ${CYAN}--log <fichero>${RESET}       Guarda el informe en el fichero indicado

${BOLD}Ejemplos:${RESET}
  sudo $0
  sudo $0 --show-local --format csv --log porthush.csv
  sudo $0 --filter critical
EOF
    exit 0
}

# ─────────────────────────────────────────────────────────────
# Parseo de argumentos
# ─────────────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --show-local)   SHOW_LOCAL=true ;;
            --filter)       shift; FILTER_RISK="${1:-}" ;;
            --format)       shift; OUTPUT_FORMAT="${1:-text}" ;;
            --log)          shift; LOGFILE="${1:-}" ;;
            -h|--help)      usage ;;
            *) printf "Opción desconocida: %s\n" "$1"; usage ;;
        esac
        shift
    done
    [[ -n "$LOGFILE" ]] && > "$LOGFILE"
}

# ─────────────────────────────────────────────────────────────
# Base de conocimiento de puertos
# Formato: PUERTO:SERVICIO:RIESGO_SI_EXPUESTO:DESCRIPCION
# Riesgos: CRITICAL | WARNING | INFO | SAFE
# ─────────────────────────────────────────────────────────────
declare -A PORT_DB
PORT_DB=(
    # ── Bases de datos (CRITICAL si expuestas) ──────────────
    [3306]="MySQL|CRITICAL|Base de datos MySQL expuesta al exterior"
    [5432]="PostgreSQL|CRITICAL|Base de datos PostgreSQL expuesta al exterior"
    [6379]="Redis|CRITICAL|Redis sin autenticación típica — NO debe estar expuesto"
    [27017]="MongoDB|CRITICAL|MongoDB expuesto — acceso sin auth por defecto"
    [27018]="MongoDB-shard|CRITICAL|MongoDB shard expuesto"
    [5984]="CouchDB|CRITICAL|CouchDB expuesto al exterior"
    [9200]="Elasticsearch|CRITICAL|Elasticsearch expuesto — sin auth por defecto"
    [9300]="Elasticsearch-cluster|CRITICAL|Puerto de cluster Elasticsearch expuesto"
    [7474]="Neo4j|CRITICAL|Neo4j expuesto al exterior"
    [1521]="Oracle-DB|CRITICAL|Base de datos Oracle expuesta"
    [1433]="MSSQL|CRITICAL|SQL Server expuesto al exterior"
    [5000]="DB2|CRITICAL|IBM DB2 expuesto"
    # ── Servicios de mensajería/caché (CRITICAL) ────────────
    [11211]="Memcached|CRITICAL|Memcached expuesto — sin autenticación"
    [5672]="RabbitMQ|CRITICAL|RabbitMQ AMQP expuesto"
    [15672]="RabbitMQ-mgmt|CRITICAL|Panel de gestión RabbitMQ expuesto"
    [9092]="Kafka|CRITICAL|Apache Kafka expuesto al exterior"
    [2181]="ZooKeeper|CRITICAL|ZooKeeper expuesto — control de cluster"
    # ── Servicios de administración remota (CRITICAL) ────────
    [23]="Telnet|CRITICAL|Telnet activo — protocolo sin cifrado, usar SSH"
    [512]="rexec|CRITICAL|rexec activo — acceso remoto inseguro"
    [513]="rlogin|CRITICAL|rlogin activo — sin cifrado ni autenticación fuerte"
    [514]="rsh|CRITICAL|rsh activo — shell remoto inseguro"
    [2049]="NFS|CRITICAL|NFS expuesto — puede permitir montaje no autorizado"
    [111]="RPCbind|CRITICAL|RPCbind expuesto — vector para ataques NFS/RPC"
    [135]="MS-RPC|CRITICAL|MS-RPC expuesto"
    [445]="SMB|CRITICAL|Samba/SMB expuesto — objetivo frecuente de ataques"
    [139]="NetBIOS|CRITICAL|NetBIOS expuesto"
    # ── Servicios web/proxy (WARNING) ────────────────────────
    [80]="HTTP|WARNING|HTTP en claro — considerar redirigir a HTTPS"
    [8080]="HTTP-alt|WARNING|Puerto alternativo HTTP expuesto"
    [8443]="HTTPS-alt|INFO|Puerto alternativo HTTPS"
    [8888]="HTTP-dev|WARNING|Puerto de desarrollo HTTP expuesto"
    [3000]="HTTP-dev-alt|WARNING|Servidor de desarrollo expuesto (Node/Rails/etc)"
    [4200]="Angular-dev|WARNING|Servidor de desarrollo Angular expuesto"
    [5000]="Flask-dev|WARNING|Servidor de desarrollo Flask/Python expuesto"
    [8000]="HTTP-dev2|WARNING|Servidor de desarrollo expuesto"
    [9090]="Prometheus|WARNING|Prometheus expuesto — métricas del sistema accesibles"
    [3128]="Squid-proxy|WARNING|Proxy Squid expuesto"
    [8118]="Privoxy|WARNING|Privoxy expuesto"
    # ── Paneles de administración web (WARNING) ──────────────
    [10000]="Webmin|WARNING|Webmin expuesto — panel de administración web"
    [8834]="Nessus|WARNING|Nessus expuesto"
    [9000]="Portainer/PHP-FPM|WARNING|Portainer o PHP-FPM expuesto"
    [2375]="Docker|CRITICAL|API Docker sin TLS expuesta — control total del host"
    [2376]="Docker-TLS|WARNING|API Docker con TLS expuesta — revisar acceso"
    [4243]="Docker-alt|CRITICAL|API Docker alternativa expuesta"
    # ── Servicios de correo (WARNING/INFO) ───────────────────
    [25]="SMTP|WARNING|SMTP expuesto — puede ser relay abierto"
    [465]="SMTPS|INFO|SMTP seguro"
    [587]="SMTP-submission|INFO|SMTP submission"
    [110]="POP3|WARNING|POP3 en claro — usar POP3S"
    [995]="POP3S|INFO|POP3 seguro"
    [143]="IMAP|WARNING|IMAP en claro — usar IMAPS"
    [993]="IMAPS|INFO|IMAP seguro"
    # ── Servicios de infraestructura (INFO/WARNING) ──────────
    [22]="SSH|INFO|SSH — revisar configuración (PermitRootLogin, auth)"
    [443]="HTTPS|SAFE|HTTPS estándar"
    [53]="DNS|WARNING|DNS expuesto — verificar si es recursivo abierto"
    [67]="DHCP|INFO|Servidor DHCP activo"
    [68]="DHCP-client|INFO|Cliente DHCP"
    [123]="NTP|INFO|NTP activo"
    [161]="SNMP|WARNING|SNMP expuesto — community strings por defecto"
    [162]="SNMP-trap|WARNING|SNMP trap expuesto"
    [389]="LDAP|WARNING|LDAP en claro expuesto"
    [636]="LDAPS|INFO|LDAP seguro"
    [88]="Kerberos|INFO|Kerberos activo"
    [5900]="VNC|CRITICAL|VNC expuesto — acceso gráfico remoto sin VPN"
    [5901]="VNC-1|CRITICAL|VNC (display 1) expuesto"
    [3389]="RDP|CRITICAL|RDP expuesto — objetivo frecuente de ataques de fuerza bruta"
    # ── Monitorización/métricas (INFO) ───────────────────────
    [4369]="Erlang-epmd|WARNING|Erlang Port Mapper expuesto (RabbitMQ/CouchDB)"
    [8086]="InfluxDB|WARNING|InfluxDB expuesto"
    [3001]="Grafana|INFO|Grafana expuesto"
    [9100]="Node-exporter|WARNING|Prometheus node exporter expuesto"
    # ── Kubernetes / contenedores (CRITICAL) ────────────────
    [6443]="K8s-API|CRITICAL|API de Kubernetes expuesta"
    [2379]="etcd|CRITICAL|etcd expuesto — datos de cluster Kubernetes"
    [2380]="etcd-peer|CRITICAL|etcd peer expuesto"
    [10250]="Kubelet|CRITICAL|Kubelet API expuesta"
    [10255]="Kubelet-ro|WARNING|Kubelet read-only expuesto"
)

# ─────────────────────────────────────────────────────────────
# Colores por nivel de riesgo
# ─────────────────────────────────────────────────────────────
risk_color() {
    case "$1" in
        CRITICAL) printf "%s" "${RED}${BOLD}" ;;
        WARNING)  printf "%s" "${YELLOW}${BOLD}" ;;
        INFO)     printf "%s" "${CYAN}" ;;
        SAFE)     printf "%s" "${GREEN}" ;;
        UNKNOWN)  printf "%s" "${DIM}" ;;
    esac
}

# ─────────────────────────────────────────────────────────────
# Determinar herramienta de red
# ─────────────────────────────────────────────────────────────
detect_net_tool() {
    if command -v ss &>/dev/null; then
        NET_TOOL="ss"
    elif command -v netstat &>/dev/null; then
        NET_TOOL="netstat"
    else
        printf "${RED}${BOLD}[✗] No se encontró 'ss' ni 'netstat'. Instala iproute2 o net-tools.${RESET}\n"
        exit 1
    fi
    log_raw "INFO" "Herramienta de red: $NET_TOOL"
}

# ─────────────────────────────────────────────────────────────
# Logging interno
# ─────────────────────────────────────────────────────────────
log_raw() {
    local level="$1"; shift
    [[ -n "$LOGFILE" ]] && printf "[%s] [%s] %s\n" "$(date '+%H:%M:%S')" "$level" "$*" >> "$LOGFILE"
}

# ─────────────────────────────────────────────────────────────
# Obtener proceso asociado a un puerto
# ─────────────────────────────────────────────────────────────
get_process() {
    local port="$1"
    local proto="${2:-tcp}"
    local proc=""

    if [[ "$NET_TOOL" == "ss" ]]; then
        proc=$(ss -tlnp 2>/dev/null | awk -v p=":$port " '$0 ~ p {match($0,/users:\(\("[^"]+"/); print substr($0,RSTART+9,RLENGTH-10)}' | head -1)
    fi

    # Fallback con lsof
    if [[ -z "$proc" ]] && command -v lsof &>/dev/null; then
        proc=$(lsof -i "${proto}:${port}" -sTCP:LISTEN -n -P 2>/dev/null | awk 'NR==2{print $1"(PID:"$2")"}' | head -1)
    fi

    # Fallback con fuser
    if [[ -z "$proc" ]] && command -v fuser &>/dev/null; then
        local pid
        pid=$(fuser "${port}/${proto}" 2>/dev/null | tr -d ' ' | head -1)
        if [[ -n "$pid" ]]; then
            local pname
            pname=$(ps -p "$pid" -o comm= 2>/dev/null || echo "?")
            proc="${pname}(PID:${pid})"
        fi
    fi

    [[ -z "$proc" ]] && proc="desconocido"
    printf "%s" "$proc"
}

# ─────────────────────────────────────────────────────────────
# Recoger puertos activos
# ─────────────────────────────────────────────────────────────
# Devuelve líneas: PROTO|ADDR|PORT
collect_ports() {
    local raw=""

    if [[ "$NET_TOOL" == "ss" ]]; then
        # TCP escuchando
        while IFS= read -r line; do
            local addr port proto="tcp"
            addr=$(echo "$line" | awk '{print $4}' | sed 's/:[^:]*$//')
            port=$(echo "$line" | awk '{print $4}' | grep -oE '[0-9]+$')
            [[ -n "$port" ]] && printf "tcp|%s|%s\n" "$addr" "$port"
        done < <(ss -tlnH 2>/dev/null)

        # UDP
        while IFS= read -r line; do
            local addr port
            addr=$(echo "$line" | awk '{print $4}' | sed 's/:[^:]*$//')
            port=$(echo "$line" | awk '{print $4}' | grep -oE '[0-9]+$')
            [[ -n "$port" ]] && printf "udp|%s|%s\n" "$addr" "$port"
        done < <(ss -ulnH 2>/dev/null)

    else
        # netstat fallback
        while IFS= read -r line; do
            local proto addr port
            proto=$(echo "$line" | awk '{print $1}')
            addr=$(echo "$line"  | awk '{print $4}' | sed 's/:[^:]*$//')
            port=$(echo "$line"  | awk '{print $4}' | grep -oE '[0-9]+$')
            [[ -n "$port" ]] && printf "%s|%s|%s\n" "$proto" "$addr" "$port"
        done < <(netstat -tlunp 2>/dev/null | grep -E 'LISTEN|udp' | grep -v '^Proto')
    fi
}

# ─────────────────────────────────────────────────────────────
# Clasificar dirección de escucha
# ─────────────────────────────────────────────────────────────
classify_addr() {
    local addr="$1"
    case "$addr" in
        "127.0.0.1"|"::1"|"[::1]")
            printf "local" ;;
        "0.0.0.0"|"*"|"[::]"|"[::0]"|"")
            printf "exposed" ;;
        *)
            # IP específica no loopback → expuesta
            printf "exposed" ;;
    esac
}

# ─────────────────────────────────────────────────────────────
# Obtener info del puerto desde la base de conocimiento
# ─────────────────────────────────────────────────────────────
lookup_port() {
    local port="$1"
    local exposure="$2"   # local | exposed

    if [[ -n "${PORT_DB[$port]+_}" ]]; then
        local info="${PORT_DB[$port]}"
        local svc risk desc
        IFS='|' read -r svc risk desc <<< "$info"

        # Si está en local, bajar riesgo (excepto critical)
        if [[ "$exposure" == "local" ]]; then
            case "$risk" in
                CRITICAL) risk="WARNING" ;;
                WARNING)  risk="INFO"    ;;
                INFO)     risk="SAFE"    ;;
                SAFE)     risk="SAFE"    ;;
            esac
            desc="(local) $desc"
        fi
        printf "%s|%s|%s" "$svc" "$risk" "$desc"
    else
        local risk="UNKNOWN"
        [[ "$exposure" == "exposed" ]] && risk="WARNING"
        printf "Desconocido|%s|Puerto no catalogado — revisar manualmente" "$risk"
    fi
}

# ─────────────────────────────────────────────────────────────
# Imprimir fila — texto
# ─────────────────────────────────────────────────────────────
print_row_text() {
    local proto="$1" addr="$2" port="$3" svc="$4" risk="$5" desc="$6" proc="$7"

    local color; color=$(risk_color "$risk")
    local exposure_icon
    [[ $(classify_addr "$addr") == "exposed" ]] && exposure_icon="${RED}⬤${RESET}" || exposure_icon="${GREEN}⬤${RESET}"

    printf "  %b %-7s  %-6s  %-18s  %b%-10s%b  %s\n" \
        "$exposure_icon" \
        "$proto" \
        "$port" \
        "${svc:0:18}" \
        "$color" "$risk" "$RESET" \
        "$desc"

    printf "        ${DIM}Proceso: %-30s  Addr: %s${RESET}\n" "$proc" "$addr"
}

# ─────────────────────────────────────────────────────────────
# Acumular salida CSV / JSON
# ─────────────────────────────────────────────────────────────
CSV_ROWS=""
JSON_ROWS=""

append_csv() {
    CSV_ROWS+="$1\n"
}

append_json() {
    JSON_ROWS+="$1,"
}

# ─────────────────────────────────────────────────────────────
# Cabecera tabla texto
# ─────────────────────────────────────────────────────────────
print_table_header() {
    printf "\n  ${BOLD}%-3s  %-7s  %-6s  %-18s  %-10s  %s${RESET}\n" \
        "EXP" "PROTO" "PUERTO" "SERVICIO" "RIESGO" "DESCRIPCIÓN"
    printf "  %s\n" "$(printf '─%.0s' {1..90})"
}

# ─────────────────────────────────────────────────────────────
# Cabecera
# ─────────────────────────────────────────────────────────────
print_banner() {
    printf "${BOLD}${BLUE}  porthush — Analisis de Superficie de Exposicion de Red — v1.0${RESET}\n"
    printf "${DIM}  %s${RESET}\n\n" "$(date '+%Y-%m-%d %H:%M:%S')"
}

# ─────────────────────────────────────────────────────────────
# ANÁLISIS PRINCIPAL
# ─────────────────────────────────────────────────────────────
run_analysis() {
    log_raw "START" "Iniciando análisis porthush"

    # Cabecera CSV
    [[ "$OUTPUT_FORMAT" == "csv" ]] && {
        local csv_header="proto,addr,port,servicio,riesgo,descripcion,proceso"
        printf "%s\n" "$csv_header"
        [[ -n "$LOGFILE" ]] && printf "%s\n" "$csv_header" >> "$LOGFILE"
    }

    # Cabecera JSON
    [[ "$OUTPUT_FORMAT" == "json" ]] && printf '{"scan_date":"%s","results":[' "$(date '+%Y-%m-%dT%H:%M:%S')"

    # Cabecera tabla texto
    [[ "$OUTPUT_FORMAT" == "text" ]] && print_table_header

    # Conjunto para deduplicar proto+port+addr
    declare -A seen_ports

    while IFS='|' read -r proto addr port; do
        [[ -z "$port" || -z "$proto" ]] && continue

        local dedup_key="${proto}|${addr}|${port}"
        [[ "${seen_ports[$dedup_key]+_}" ]] && continue
        seen_ports[$dedup_key]=1

        local exposure; exposure=$(classify_addr "$addr")

        # Filtrar puertos locales si no se pidió --show-local
        if [[ "$exposure" == "local" ]] && ! $SHOW_LOCAL; then
            log_raw "SKIP" "Puerto local ignorado: $proto/$port en $addr"
            continue
        fi

        # Lookup en base de conocimiento
        local lookup; lookup=$(lookup_port "$port" "$exposure")
        local svc risk desc
        IFS='|' read -r svc risk desc <<< "$lookup"

        # Filtro por nivel de riesgo
        if [[ -n "$FILTER_RISK" && "${risk,,}" != "${FILTER_RISK,,}" ]]; then
            continue
        fi

        # Obtener proceso (solo para expuestos o si --show-local)
        local proc; proc=$(get_process "$port" "$proto")

        # Contadores
        case "$risk" in
            CRITICAL) (( COUNT_CRITICAL++ )) || true ;;
            WARNING)  (( COUNT_WARNING++  )) || true ;;
            INFO)     (( COUNT_INFO++     )) || true ;;
            SAFE)     (( COUNT_SAFE++     )) || true ;;
            UNKNOWN)  (( COUNT_WARNING++  )) || true ;;
        esac

        # Salida según formato
        case "$OUTPUT_FORMAT" in
            text)
                print_row_text "$proto" "$addr" "$port" "$svc" "$risk" "$desc" "$proc"
                ;;
            csv)
                local row; row="\"$proto\",\"$addr\",\"$port\",\"$svc\",\"$risk\",\"$desc\",\"$proc\""
                printf "%s\n" "$row"
                [[ -n "$LOGFILE" ]] && printf "%s\n" "$row" >> "$LOGFILE"
                ;;
            json)
                local json_obj
                json_obj=$(printf '{"proto":"%s","addr":"%s","port":%s,"servicio":"%s","riesgo":"%s","descripcion":"%s","proceso":"%s"}' \
                    "$proto" "$addr" "$port" "$svc" "$risk" \
                    "$(echo "$desc" | sed 's/"/\\"/g')" \
                    "$(echo "$proc" | sed 's/"/\\"/g')")
                printf "%s," "$json_obj"
                [[ -n "$LOGFILE" ]] && printf "%s\n" "$json_obj" >> "$LOGFILE"
                ;;
        esac

    done < <(collect_ports | sort -t'|' -k3 -n | uniq)

    # Cierre JSON
    [[ "$OUTPUT_FORMAT" == "json" ]] && printf '"_end":null]}\n'
}

# ─────────────────────────────────────────────────────────────
# Detección avanzada — servicios críticos expuestos
# ─────────────────────────────────────────────────────────────
advanced_detection() {
    [[ "$OUTPUT_FORMAT" != "text" ]] && return

    printf "\n${BOLD}┌─ Detección Avanzada ─────────────────────────────────────────────────────┐${RESET}\n"

    local found=0

    # Docker socket expuesto
    if [[ -S /var/run/docker.sock ]]; then
        local dperm; dperm=$(stat -c '%a' /var/run/docker.sock 2>/dev/null)
        local downer; downer=$(stat -c '%U:%G' /var/run/docker.sock 2>/dev/null)
        if [[ "$dperm" =~ [67][67][67]$ ]] || stat -c '%G' /var/run/docker.sock 2>/dev/null | grep -qv 'docker'; then
            printf "  ${RED}${BOLD}[!] Docker socket accesible de forma permisiva: /var/run/docker.sock (%s, %s)${RESET}\n" "$dperm" "$downer"
            printf "      ${DIM}↳ chown root:docker /var/run/docker.sock && chmod 660 /var/run/docker.sock${RESET}\n"
            (( found++ )) || true
        else
            printf "  ${GREEN}[✓] Docker socket con permisos correctos (%s, %s)${RESET}\n" "$dperm" "$downer"
        fi
    fi

    # Redis expuesto en interfaz publica (verificacion por puerto, sin conexion real)
    local redis_exposed; redis_exposed=$(ss -tlnH 2>/dev/null | awk '{print $4}' \
        | grep -E ':6379$' | grep -v '127\.0\.0\.1\|::1' || true)
    if [[ -n "$redis_exposed" ]]; then
        printf "  ${RED}${BOLD}[!] Redis (6379) expuesto en interfaz publica: %s${RESET}\n" "$redis_exposed"
        printf "      ${DIM}-> Limitar bind a 127.0.0.1 en /etc/redis/redis.conf${RESET}\n"
        (( found++ )) || true
    fi

    # MongoDB expuesto en interfaz publica (verificacion por puerto, sin conexion real)
    local mongo_exposed; mongo_exposed=$(ss -tlnH 2>/dev/null | awk '{print $4}' \
        | grep -E ':27017$' | grep -v '127\.0\.0\.1\|::1' || true)
    if [[ -n "$mongo_exposed" ]]; then
        printf "  ${RED}${BOLD}[!] MongoDB (27017) expuesto en interfaz publica: %s${RESET}\n" "$mongo_exposed"
        printf "      ${DIM}-> Limitar bindIp a 127.0.0.1 en mongod.conf${RESET}\n"
        (( found++ )) || true
    fi

    # Interfaces en modo promiscuo
    if command -v ip &>/dev/null; then
        while IFS= read -r iface; do
            printf "  ${YELLOW}${BOLD}[!] Interfaz en modo promiscuo: %s${RESET}\n" "$iface"
            printf "      ${DIM}↳ ip link set %s promisc off${RESET}\n" "$iface"
            (( found++ )) || true
        done < <(ip link show 2>/dev/null | grep -i promisc | awk -F': ' '{print $2}')
    fi

    # IPv6 habilitado pero sin firewall ip6tables
    if [[ -f /proc/net/if_inet6 ]] && cat /proc/net/if_inet6 2>/dev/null | grep -qv 'lo'; then
        if command -v ip6tables &>/dev/null; then
            local ip6_rules; ip6_rules=$(ip6tables -L 2>/dev/null | grep -c 'ACCEPT\|DROP\|REJECT' || echo 0)
            if [[ "$ip6_rules" -lt 2 ]]; then
                printf "  ${YELLOW}${BOLD}[!] IPv6 activo pero ip6tables sin reglas definidas${RESET}\n"
                printf "      ${DIM}↳ Configurar reglas ip6tables o deshabilitar IPv6 si no se usa${RESET}\n"
                (( found++ )) || true
            else
                printf "  ${GREEN}[✓] IPv6 activo con reglas ip6tables presentes${RESET}\n"
            fi
        fi
    fi

    # Firewall activo
    printf "\n  ${BOLD}Estado del firewall:${RESET}\n"
    local fw_found=false
    if command -v ufw &>/dev/null; then
        local ufw_status; ufw_status=$(ufw status 2>/dev/null | head -1)
        if echo "$ufw_status" | grep -qi "active"; then
            printf "  ${GREEN}  [✓] UFW activo: %s${RESET}\n" "$ufw_status"
        else
            printf "  ${YELLOW}  [!] UFW instalado pero inactivo${RESET}\n"
        fi
        fw_found=true
    fi
    if command -v firewall-cmd &>/dev/null; then
        local fwd_status; fwd_status=$(firewall-cmd --state 2>/dev/null || echo "unknown")
        if [[ "$fwd_status" == "running" ]]; then
            printf "  ${GREEN}  [✓] firewalld activo${RESET}\n"
        else
            printf "  ${YELLOW}  [!] firewalld instalado pero no activo: %s${RESET}\n" "$fwd_status"
        fi
        fw_found=true
    fi
    if command -v iptables &>/dev/null; then
        local ipt_rules; ipt_rules=$(iptables -L 2>/dev/null | grep -c 'ACCEPT\|DROP\|REJECT' || echo 0)
        if [[ "$ipt_rules" -gt 3 ]]; then
            printf "  ${GREEN}  [✓] iptables con %d reglas activas${RESET}\n" "$ipt_rules"
        else
            printf "  ${YELLOW}  [!] iptables sin reglas sustantivas (%d reglas)${RESET}\n" "$ipt_rules"
        fi
        fw_found=true
    fi
    $fw_found || printf "  ${RED}${BOLD}  [!] No se detectó ningún firewall activo${RESET}\n"

    printf "${BOLD}└──────────────────────────────────────────────────────────────────────────┘${RESET}\n"

    [[ $found -eq 0 ]] && printf "  ${GREEN}Sin hallazgos adicionales en detección avanzada.${RESET}\n"
}

# ─────────────────────────────────────────────────────────────
# Resumen
# ─────────────────────────────────────────────────────────────
print_summary() {
    [[ "$OUTPUT_FORMAT" != "text" ]] && return

    local total=$(( COUNT_CRITICAL + COUNT_WARNING + COUNT_INFO + COUNT_SAFE ))

    printf "\n${BOLD}┌─────────────────────────────────────────────────────┐${RESET}\n"
    printf "${BOLD}│  RESUMEN — SUPERFICIE DE EXPOSICIÓN                 │${RESET}\n"
    printf "${BOLD}├─────────────────────────────────────────────────────┤${RESET}\n"
    printf "${BOLD}│${RESET}  Total de puertos analizados : ${BOLD}%-23s${RESET}${BOLD}│${RESET}\n" "$total"
    printf "${BOLD}│${RESET}  ${RED}${BOLD}CRITICAL${RESET}                    : ${RED}${BOLD}%-23s${RESET}${BOLD}│${RESET}\n" "$COUNT_CRITICAL"
    printf "${BOLD}│${RESET}  ${YELLOW}${BOLD}WARNING ${RESET}                    : ${YELLOW}${BOLD}%-23s${RESET}${BOLD}│${RESET}\n" "$COUNT_WARNING"
    printf "${BOLD}│${RESET}  ${CYAN}INFO    ${RESET}                    : ${CYAN}%-23s${RESET}${BOLD}│${RESET}\n" "$COUNT_INFO"
    printf "${BOLD}│${RESET}  ${GREEN}SAFE    ${RESET}                    : ${GREEN}%-23s${RESET}${BOLD}│${RESET}\n" "$COUNT_SAFE"
    printf "${BOLD}└─────────────────────────────────────────────────────┘${RESET}\n"

    if [[ $COUNT_CRITICAL -gt 0 ]]; then
        printf "\n${RED}${BOLD}  ⛔  %d servicio(s) CRÍTICO(S) expuesto(s). Acción inmediata requerida.${RESET}\n" "$COUNT_CRITICAL"
    elif [[ $COUNT_WARNING -gt 0 ]]; then
        printf "\n${YELLOW}${BOLD}  ⚠   %d advertencia(s) de exposición. Revisar pronto.${RESET}\n" "$COUNT_WARNING"
    else
        printf "\n${GREEN}${BOLD}  ✔   Superficie de exposición dentro de parámetros seguros.${RESET}\n"
    fi

    [[ -n "$LOGFILE" ]] && printf "${DIM}\n  Log guardado en: %s${RESET}\n" "$LOGFILE"
    printf "\n"
}

# ─────────────────────────────────────────────────────────────
# Comprobaciones previas
# ─────────────────────────────────────────────────────────────
check_requirements() {
    if [[ $EUID -ne 0 ]]; then
        printf "${YELLOW}${BOLD}⚠  Sin root algunos procesos asociados a puertos no serán visibles.${RESET}\n\n"
    fi
}

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    [[ "$OUTPUT_FORMAT" == "text" ]] && print_banner
    check_requirements
    detect_net_tool
    run_analysis
    [[ "$OUTPUT_FORMAT" == "text" ]] && advanced_detection
    print_summary
}

main "$@"
