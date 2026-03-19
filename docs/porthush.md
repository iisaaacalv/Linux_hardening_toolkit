# porthush — Análisis de Superficie de Exposición de Red

## Descripción

`porthush` analiza qué servicios están escuchando en el sistema y determina si su nivel de exposición es adecuado. Aplica el principio de **mínima exposición**, identificando servicios innecesariamente accesibles desde el exterior que amplían la superficie de ataque.

## Uso

```bash
sudo ./porthush.sh [opciones]
```

### Opciones

| Opción | Descripción |
|--------|-------------|
| `--show-local` | Incluye también puertos en `127.0.0.1` en el informe |
| `--filter <nivel>` | Muestra solo hallazgos de ese nivel: `critical`, `warning`, `info` |
| `--format <tipo>` | Formato de salida: `text` (por defecto), `csv`, `json` |
| `--log <fichero>` | Guarda el informe en el fichero indicado |

### Ejemplos

```bash
# Análisis completo por pantalla
sudo ./porthush.sh

# Ver solo puertos críticos
sudo ./porthush.sh --filter critical

# Incluir puertos locales (127.0.0.1)
sudo ./porthush.sh --show-local

# Exportar a CSV
sudo ./porthush.sh --format csv --log /tmp/puertos.csv

# Exportar a JSON
sudo ./porthush.sh --format json --log /tmp/puertos.json
```

## Cómo interpreta los resultados

Cada puerto detectado se evalúa en función de **quién puede acceder a él**:

| Dirección de escucha | Interpretación |
|----------------------|----------------|
| `127.0.0.1` / `::1` | Solo accesible localmente — riesgo reducido |
| `0.0.0.0` / `[::]` | Expuesto a todas las interfaces — riesgo según servicio |
| IP específica | Expuesto en esa interfaz concreta |

Un servicio como Redis escuchando en `127.0.0.1` se clasifica como `WARNING`, pero el mismo servicio en `0.0.0.0` se convierte en `CRITICAL`.

## Base de conocimiento de servicios

La herramienta incluye una base con más de 60 servicios catalogados:

### 🔴 CRITICAL (si expuestos al exterior)
Bases de datos, caches y servicios de infraestructura que no deben estar accesibles desde fuera:

| Puerto | Servicio |
|--------|---------|
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 27017 | MongoDB |
| 9200 | Elasticsearch |
| 2375 | Docker API (sin TLS) |
| 5900/5901 | VNC |
| 3389 | RDP |
| 23 | Telnet |
| 445 | SMB / Samba |
| 2049 | NFS |
| 6443 | Kubernetes API |
| 2379 | etcd |

### 🟡 WARNING
Servicios con riesgo según configuración:

| Puerto | Servicio |
|--------|---------|
| 80 | HTTP en claro |
| 8080, 8888, 3000 | Servidores de desarrollo |
| 25 | SMTP (posible relay abierto) |
| 161 | SNMP (community strings) |
| 53 | DNS (recursivo abierto) |
| 9090 | Prometheus (métricas expuestas) |
| 10000 | Webmin |

### 🔵 INFO / 🟢 SAFE
Servicios generalmente aceptables:

| Puerto | Servicio |
|--------|---------|
| 22 | SSH (revisar configuración) |
| 443 | HTTPS |
| 993 | IMAPS |
| 465 | SMTPS |

## Detección avanzada

Además del escaneo de puertos, `porthush` realiza comprobaciones adicionales:

**Docker socket:** verifica si `/var/run/docker.sock` tiene permisos excesivos. Un socket de Docker accesible equivale a acceso root al sistema.

**Redis sin autenticación:** si `redis-cli` está disponible, intenta una conexión real a `127.0.0.1` y comprueba si responde sin contraseña.

**MongoDB sin autenticación:** comprueba si `mongosh` / `mongo` puede conectarse localmente sin credenciales.

**Interfaces en modo promiscuo:** detecta interfaces de red capturando todo el tráfico, lo que puede indicar un sniffer activo.

**IPv6 sin firewall:** si hay interfaces IPv6 activas pero no hay reglas `ip6tables`, los servicios pueden estar expuestos por IPv6 aunque estén protegidos por IPv4.

**Estado del firewall:** comprueba si UFW, firewalld o iptables están activos y con reglas definidas.

## Ejemplo de salida

```
  ⬤ tcp     3306    MySQL              CRITICAL   Base de datos MySQL expuesta al exterior
        Proceso: mysqld(PID:1234)              Addr: 0.0.0.0

  ⬤ tcp     22      SSH                INFO       SSH — revisar configuración
        Proceso: sshd(PID:567)                 Addr: 0.0.0.0

  ⬤ tcp     6379    Redis              CRITICAL   Redis sin autenticación — NO debe estar expuesto
        Proceso: redis-server(PID:890)         Addr: 0.0.0.0
```

El indicador `⬤` es **rojo** si el puerto está expuesto al exterior y **verde** si solo escucha en localhost.

## Notas

- Sin `root`, los procesos asociados a algunos puertos pueden aparecer como `desconocido`.
- La herramienta usa `ss` si está disponible; si no, cae back a `netstat`.
- Para obtener el proceso asociado usa `ss`, `lsof` y `fuser` en ese orden.

## Ejemplo de log (CSV)
```
proto,addr,port,servicio,riesgo,descripcion,proceso
"tcp","0.0.0.0","6379","Redis","CRITICAL","Redis sin autenticacion tipica — NO debe estar expuesto","nc"
"tcp","0.0.0.0","53","DNS","WARNING","DNS expuesto — verificar si es recursivo abierto","dnsmasq"
"udp","0.0.0.0","53","DNS","WARNING","DNS expuesto — verificar si es recursivo abierto","dnsmasq"
"tcp","0.0.0.0","22","SSH","INFO","SSH — revisar configuracion (PermitRootLogin, auth)","sshd"
```
