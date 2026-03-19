# fileshield — Bastionado Activo de Permisos

## Descripción

`fileshield` es la herramienta de acción del toolkit: aplica políticas seguras de permisos sobre archivos y directorios críticos, corrigiendo las configuraciones inseguras detectadas. Complementa a [`permwatch`](permwatch.md), convirtiendo la auditoría en hardening real y automatizado.

## Uso

```bash
sudo ./fileshield.sh [--audit | --apply | --strict] [--log <fichero>]
```

### Opciones

| Opción | Descripción |
|--------|-------------|
| `--audit` | Solo muestra problemas detectados, **sin realizar cambios** (por defecto) |
| `--apply` | Corrige automáticamente todos los permisos inseguros detectados |
| `--strict` | Hardening agresivo: aplica restricciones máximas |
| `--log <fichero>` | Guarda la salida en el fichero indicado |

### Ejemplos

```bash
# Ver qué se va a cambiar antes de tocar nada (recomendado siempre primero)
sudo ./fileshield.sh --audit

# Aplicar correcciones automáticas
sudo ./fileshield.sh --apply

# Hardening agresivo con log
sudo ./fileshield.sh --strict --log /tmp/fileshield.log

# Auditoría con exportación a fichero
sudo ./fileshield.sh --audit --log revision.log
```

## Modos de ejecución en detalle

### `--audit` (solo lectura)
Recorre todos los módulos y reporta cada problema encontrado junto con el comando que se aplicaría para corregirlo. **No modifica nada.** Ideal para revisar el estado del sistema antes de intervenir.

```
[!] ISSUE   /etc/shadow tiene permisos 644 (esperado: 640)
[-] SKIP    chmod 640 "/etc/shadow"  [--apply para corregir]
```

### `--apply` (corrección automática)
Aplica `chmod` y `chown` correctivos sobre cada elemento problemático. Antes de realizar cambios, genera un **snapshot de permisos** en `/var/backups/fileshield_YYYYMMDD_HHMMSS/` como respaldo.

```
[✔] FIXED   chmod 640 "/etc/shadow"
[✔] FIXED   chown root:shadow "/etc/shadow"
```

### `--strict` (hardening agresivo)
Incluye todo lo de `--apply` y además:
- Aplica `chattr +i` (flag inmutable) a `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
- Restringe homes a `700` en lugar de `750`
- Aplica `640/750` recursivamente en `/var/www`
- Elimina el bit de ejecución de archivos en `/tmp`
- Verifica directivas clave de `sshd_config` (`PermitRootLogin no`, `PasswordAuthentication no`...)

> ⚠️ Usar `--strict` con precaución en sistemas en producción. El flag `chattr +i` impide modificar los archivos incluso como root hasta que se revierta con `chattr -i`.

## Qué módulos ejecuta

### Archivos críticos del sistema
Permisos y propietarios aplicados:

| Archivo | Permisos | Propietario |
|---------|----------|-------------|
| `/etc/passwd` | `644` | `root:root` |
| `/etc/shadow` | `640` | `root:shadow` |
| `/etc/gshadow` | `640` | `root:shadow` |
| `/etc/group` | `644` | `root:root` |
| `/etc/sudoers` | `440` | `root:root` |
| `/etc/sudoers.d/*` | `440` | `root:root` |
| `/etc/crontab` | `600` | `root:root` |
| `/etc/cron.d`, `cron.daily`... | `600` | `root:root` |
| `/etc/hosts`, `/etc/hostname` | `644` | `root:root` |

### Directorio `/root`
Permisos `700`, propietario `root:root`. En modo `--strict` también restringe `.bashrc`, `.bash_history` y `.profile` a `600`.

### Directorios `/home`
Aplica `750` (o `700` en `--strict`) a cada directorio personal y elimina permisos world-write recursivamente.

### `/tmp` y `/var/tmp`
Fuerza permisos `1777` (sticky bit). En modo `--strict` elimina el bit de ejecución de cualquier archivo encontrado dentro.

### `/var/www`
Propietario `root:www-data`, elimina world-write. En `--strict` aplica `640` a archivos y `750` a directorios de forma recursiva.

### Configuración SSH
| Ruta | Permisos | Propietario |
|------|----------|-------------|
| `~/.ssh/` | `700` | usuario:usuario |
| `authorized_keys` | `600` | usuario:usuario |
| Claves privadas | `600` | usuario:usuario |
| Claves públicas (`*.pub`) | `644` | usuario:usuario |
| `~/.ssh/config` | `600` | usuario:usuario |
| `/etc/ssh/sshd_config` | `600` | `root:root` |

## Backup automático

En los modos `--apply` y `--strict`, antes de realizar cualquier cambio se genera un snapshot con los permisos y propietarios actuales de todas las rutas críticas:

```
/var/backups/fileshield_20250315_143022/
└── perms_snapshot.txt
```

Este fichero permite auditar el estado previo o revertir manualmente si fuera necesario.

## Notas

- Requiere ejecutarse como `root`.
- Se recomienda ejecutar siempre `--audit` antes de `--apply` en un sistema desconocido.
