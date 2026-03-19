# useraudit — Auditoría de Usuarios y Privilegios

## Descripción

`useraudit` analiza las cuentas del sistema para detectar configuraciones inseguras relacionadas con identidades, contraseñas y privilegios. Cubre uno de los vectores más críticos en bastionado: la gestión de accesos.

## Uso

```bash
sudo ./useraudit.sh [opciones]
```

### Opciones

| Opción | Descripción |
|--------|-------------|
| `--inactive-days <n>` | Días sin login para considerar una cuenta inactiva (por defecto: `90`) |
| `--show-safe` | Incluye también en la salida los usuarios sin problemas (`[OK]`) |
| `--format <tipo>` | Formato de salida: `text` (por defecto), `csv`, `json` |
| `--log <fichero>` | Guarda el informe en el fichero indicado |

### Ejemplos

```bash
# Auditoría completa por pantalla
sudo ./useraudit.sh

# Marcar como inactivas cuentas sin login en más de 30 días
sudo ./useraudit.sh --inactive-days 30

# Ver también los usuarios con configuración correcta
sudo ./useraudit.sh --show-safe

# Exportar a CSV
sudo ./useraudit.sh --format csv --log /tmp/usuarios.csv

# Exportar a JSON
sudo ./useraudit.sh --format json --log /tmp/usuarios.json
```

## Módulos de análisis

### 1. Usuarios con UID 0
Solo la cuenta `root` debe tener UID 0. Cualquier otro usuario con ese identificador tiene privilegios equivalentes a root y se reporta como `CRITICAL`.

```
[CRITICAL] backup               UID 0 — Usuario no-root con UID 0 — acceso completo al sistema
```

### 2. Cuentas sin contraseña o hash inválido
Lee `/etc/shadow` y examina el campo de contraseña de cada cuenta:

| Campo en shadow | Significado | Nivel |
|-----------------|-------------|-------|
| (vacío) | Sin contraseña — acceso libre | `CRITICAL` |
| `!` | Cuenta bloqueada | `OK` |
| `!!` | Sin contraseña asignada, bloqueada | `OK` |
| `*` | Login por contraseña deshabilitado | `OK` |
| `$6$...` | Hash SHA-512 válido | `OK` |
| Valor desconocido | Formato no reconocido | `WARNING` |

### 3. Políticas de contraseña (caducidad)
Analiza los campos de expiración en `/etc/shadow`:

```
[WARNING] developer    Sin caducidad de contraseña — MAX_DAYS no configurado
[WARNING] olduser      Contraseña expirada — Expiró hace 45 días
[INFO]    alice        Contraseña próxima a expirar — Expira en 8 días
```

### 4. Cuentas inactivas
Consulta `lastlog` y `last` para determinar el último acceso de cada usuario con UID ≥ 1000. Las cuentas que superen el umbral configurado (por defecto 90 días) se reportan.

```
[WARNING] test         Cuenta inactiva — Sin login desde hace 120 días (umbral: 90d)
[INFO]    deploy       Nunca ha iniciado sesión — UID=1002
```

> Las cuentas bloqueadas (`!` en shadow) se omiten en esta comprobación.

### 5. Shells interactivas en cuentas de servicio
Las cuentas de sistema (UID < 1000) no deberían tener acceso interactivo. Detecta cuentas de servicio con shells como `/bin/bash` o `/bin/sh`.

```
[CRITICAL] www-data    Shell interactiva en cuenta desconocida — shell=/bin/bash UID=33
[WARNING]  nobody      Shell interactiva en cuenta de servicio — shell=/bin/sh UID=65534
```

Shells seguras aceptadas: `/usr/sbin/nologin`, `/sbin/nologin`, `/bin/false`, `/dev/null`.

### 6. Duplicados e inconsistencias

Comprueba la coherencia de `/etc/passwd`, `/etc/shadow` y `/etc/group`:

- **UIDs duplicados:** dos usuarios compartiendo el mismo UID
- **Nombres duplicados:** usuario que aparece más de una vez en `/etc/passwd`
- **GIDs duplicados:** en `/etc/group`
- **Entradas huérfanas:** usuario en `/etc/shadow` sin entrada en `/etc/passwd` (o viceversa)

```
[CRITICAL] UID=1001    UID duplicado — Compartido por: alice bob
[WARNING]  ghost       En shadow pero no en passwd — Entrada huérfana en /etc/shadow
```

### 7. Privilegios sudo

Analiza `/etc/sudoers` y todos los archivos en `/etc/sudoers.d/`:

```
[WARNING] developer    sudo sin restricciones — Tiene acceso sudo ALL=(ALL) ALL
[WARNING] deploy       sudo NOPASSWD — Puede ejecutar sudo sin contraseña
```

También inspecciona los grupos con capacidad de escalada de privilegios:

| Grupo | Riesgo | Motivo |
|-------|--------|--------|
| `sudo`, `wheel`, `adm` | `INFO` | Acceso a privilegios de sistema |
| `docker`, `lxd`, `disk` | `WARNING` | Permiten escalada de privilegios a root |
| `shadow` | `INFO` | Acceso a hashes de contraseñas |

### 8. Directorios home

Para cada usuario con UID ≥ 1000:

```
[WARNING] alice        Home world-writable — home=/home/alice permisos=777
[WARNING] bob          Home con propietario incorrecto — propietario=root (esperado: bob)
[INFO]    carol        Directorio home inexistente — home=/home/carol
```

### 9. Acceso root remoto

Comprueba la directiva `PermitRootLogin` en `/etc/ssh/sshd_config`:

| Valor | Nivel | Descripción |
|-------|-------|-------------|
| `no` | `OK` | Correctamente deshabilitado |
| `prohibit-password` | `INFO` | Solo por clave pública |
| `yes` | `CRITICAL` | Login SSH de root habilitado |
| (no configurado) | `WARNING` | Valor por defecto del sistema |

También comprueba si `/etc/securetty` contiene entradas `pts/` que permitan login de root en terminales remotas.

## Formato de salida

```
[CRITICAL] usuario              descripción del módulo — detalle
[WARNING]  usuario              descripción del módulo — detalle
[INFO]     usuario              descripción del módulo — detalle
[OK]       usuario              descripción del módulo
```

Al finalizar se muestra un resumen con el total de hallazgos por nivel.

## Exportación de resultados

```bash
# CSV — apto para importar en Excel o Google Sheets
sudo ./useraudit.sh --format csv --log usuarios.csv

# JSON — apto para integración con otras herramientas
sudo ./useraudit.sh --format json --log usuarios.json
```

Estructura del CSV:
```
nivel,usuario,comprobacion,detalle
CRITICAL,backup,UID 0,Usuario no-root con UID 0 — acceso completo al sistema
WARNING,developer,sudo sin restricciones,Tiene acceso sudo ALL=(ALL) ALL
```

## Notas

- Requiere ejecutarse como `root` para leer `/etc/shadow`.
- La detección de inactividad depende de que los logs de `lastlog` / `wtmp` estén disponibles y no hayan sido rotados.
- Los usuarios de sistema conocidos (mysql, postgres, www-data, redis...) tienen su propia lista blanca para reducir falsos positivos en el módulo de shells.

## Ejemplo de log
```
[2026-03-19 14:47:05] [CRITICAL] user=usuarioprueba  check=Sin contrasena establecida    detail=! en shadow — usuario humano (UID=1001) sin contrasena asignada
[2026-03-19 14:47:05] [WARNING]  user=isaac          check=Sin caducidad de contrasena   detail=MAX_DAYS no configurado
[2026-03-19 14:47:05] [WARNING]  user=postgres       check=Shell interactiva en servicio detail=shell=/bin/bash  UID=114
[2026-03-19 14:47:05] [WARNING]  user=root           check=PermitRootLogin               detail=No configurado — revisar valor por defecto
[2026-03-19 14:47:06] [INFO]     user=isaac          check=Nunca ha iniciado sesion      detail=UID=1000  shell=/usr/bin/zsh
```
