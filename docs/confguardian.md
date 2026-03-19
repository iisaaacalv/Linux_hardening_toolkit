# confguardian — Monitorización de Integridad de Configuración

## Descripción

`confguardian` genera un **baseline** (estado de referencia) de los archivos de configuración críticos del sistema y detecta cualquier modificación posterior. Permite identificar cambios no autorizados, manipulaciones maliciosas o errores administrativos sobre ficheros clave.

## Uso

```bash
sudo ./confguardian.sh <modo> [opciones]
```

### Modos disponibles

| Modo | Descripción |
|------|-------------|
| `init` | Genera el baseline inicial — **primera ejecución obligatoria** |
| `check` | Verifica la integridad comparando contra el baseline |
| `watch` | Monitorización continua en bucle |
| `report` | Muestra el historial de alertas registradas |
| `add <ruta>` | Añade un archivo o directorio al baseline activo |
| `reset` | Elimina el baseline y todo el historial |

### Opciones

| Opción | Descripción |
|--------|-------------|
| `--interval <segundos>` | Intervalo entre verificaciones en modo `watch` (por defecto: `60`) |
| `--algo <algoritmo>` | Algoritmo de hash: `sha256` (por defecto), `sha512`, `md5` |
| `--log <fichero>` | Guarda la salida en el fichero indicado |
| `--email <dirección>` | Envía alertas por correo (requiere `mail` o `sendmail`) |

## Flujo de trabajo recomendado

```bash
# 1. Primera vez: generar el baseline sobre un sistema limpio y conocido
sudo ./confguardian.sh init

# 2. Verificar integridad cuando sea necesario
sudo ./confguardian.sh check

# 3. Activar monitorización continua (cada 60 segundos)
sudo ./confguardian.sh watch

# 4. Si se instala un nuevo servicio, añadirlo al baseline
sudo ./confguardian.sh add /etc/nginx/nginx.conf

# 5. Consultar el historial de alertas
sudo ./confguardian.sh report
```

## Archivos monitorizados por defecto

### Identidad y autenticación
`/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/sudoers`, `/etc/sudoers.d/*`, `/etc/security/limits.conf`

### SSH
`/etc/ssh/sshd_config`, `/etc/ssh/ssh_config`

### Arranque y sistema de archivos
`/etc/fstab`, `/etc/crypttab`, `/boot/grub/grub.cfg`

### Red
`/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`, `/etc/hostname`, `/etc/network/interfaces`, `/etc/netplan/*`

### PAM
`/etc/pam.conf`, `/etc/pam.d/common-auth`, `/etc/pam.d/common-account`, `/etc/pam.d/sshd`, `/etc/pam.d/sudo`

### Servicios y sistema
`/etc/crontab`, `/etc/sysctl.conf`, `/etc/sysctl.d/*`, `/etc/modprobe.d/*`, `/etc/ld.so.conf`

### Logs y auditoría
`/etc/audit/auditd.conf`, `/etc/audit/rules.d/*`, `/etc/rsyslog.conf`, `/etc/logrotate.conf`

Se pueden añadir rutas adicionales con `confguardian.sh add <ruta>` o editando directamente `/var/lib/confguardian/custom_paths.conf`.

## Qué registra el baseline

Por cada archivo monitorizado se almacenan:

| Campo | Descripción |
|-------|-------------|
| Hash | Contenido del archivo (SHA-256 por defecto) |
| Permisos | Octal (`644`, `600`...) |
| Propietario | Usuario y grupo (`root:root`) |
| Tamaño | En bytes |
| mtime | Timestamp de última modificación |

## Qué detecta en cada verificación

```
[OK]      /etc/passwd — sin cambios
[ALERT]   /etc/sudoers → MODIFICADO
            hash: a3f1c2d4… → 9b8e7f12…
            permisos: 440 → 644
[DEL]     /etc/hosts → ARCHIVO ELIMINADO
[NEW]     /etc/cron.d/tarea-nueva → ARCHIVO NUEVO
```

| Indicador | Significado |
|-----------|-------------|
| `[OK]` | El archivo no ha cambiado |
| `[ALERT]` | El contenido, permisos o propietario han cambiado |
| `[DEL]` | El archivo ha sido eliminado del sistema |
| `[NEW]` | Existe un archivo nuevo en rutas vigiladas |

## Almacenamiento

Todo se guarda en `/var/lib/confguardian/` con permisos `600`:

```
/var/lib/confguardian/
├── baseline.db          ← baseline activo
├── alerts.log           ← historial de todas las alertas
├── custom_paths.conf    ← rutas añadidas con 'add'
└── history/
    ├── baseline_20250310_120000.db
    └── baseline_20250315_093000.db
```

Cada vez que se ejecuta `init` sobre un baseline existente, el anterior se archiva automáticamente en `history/` con timestamp.

## Modo watch

```bash
sudo ./confguardian.sh watch --interval 30
```

Ejecuta un `check` cada N segundos. Muestra en pantalla:
- `✓ X archivos OK` si no hay cambios
- `⚠ N cambio(s) detectado(s)` si hay alertas, con el detalle completo

Para detener: `Ctrl+C`.

> Para uso permanente en un servidor, se recomienda convertirlo en un servicio systemd.

## Notificaciones por email

```bash
sudo ./confguardian.sh check --email admin@empresa.com
sudo ./confguardian.sh watch --interval 60 --email admin@empresa.com
```

Requiere que `mail` o `sendmail` estén configurados en el sistema. Envía un correo por cada hallazgo `ALERT`, `DEL` o `NEW`.

## Notas

- El `init` debe realizarse sobre un sistema en **estado conocido y limpio**. Un baseline generado sobre un sistema ya comprometido no tendrá valor.
- Requiere ejecutarse como `root` para leer `/etc/shadow` y otros archivos protegidos.
- El algoritmo `md5` no se recomienda para uso en producción por sus vulnerabilidades conocidas.
