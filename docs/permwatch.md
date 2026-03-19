# permwatch — Auditoría de Permisos Inseguros

## Descripción

`permwatch` es una herramienta de auditoría que analiza el sistema de archivos en busca de permisos inseguros o configuraciones peligrosas que puedan comprometer la integridad del sistema. Clasifica cada hallazgo por nivel de riesgo e incluye recomendaciones de corrección.

## Uso

```bash
sudo ./permwatch.sh [--log <fichero>]
```

### Opciones

| Opción | Descripción |
|--------|-------------|
| `--log <fichero>` | Guarda la salida en el fichero indicado |

### Ejemplos

```bash
# Auditoría básica por pantalla
sudo ./permwatch.sh

# Auditoría guardando el resultado en un fichero
sudo ./permwatch.sh --log /tmp/permwatch-$(date +%F).log
```

## Qué analiza

### Archivos world-writable (`o+w`)
Busca en `/home`, `/var/www`, `/tmp`, `/var/tmp`, `/opt`, `/etc` archivos con permisos de escritura para cualquier usuario del sistema.

```
[CRITICAL] Archivo world-writable: /var/www/html/upload/config.php
           ↳ Recomendación: chmod o-w "/var/www/html/upload/config.php"
```

### Directorios world-writable sin sticky bit
Un directorio escribible por todos sin sticky bit permite que cualquier usuario elimine ficheros de otros.

```
[CRITICAL] Directorio world-writable sin sticky bit: /opt/shared
           ↳ Recomendación: chmod o-w "/opt/shared"
```

### Binarios SUID / SGID
Lista todos los binarios con bit SUID o SGID activo. Compara contra una lista blanca de binarios legítimos conocidos (`sudo`, `passwd`, `ping`...). Todo binario fuera de la lista blanca se reporta como `CRITICAL`.

```
[CRITICAL] SUID NO reconocido: /opt/app/helper
           ↳ Recomendación: chmod u-s "/opt/app/helper"

[INFO]     SUID (conocido/esperado): /usr/bin/sudo
```

### Permisos en `/home`
Cada directorio personal debe tener permisos máximos de `750`. Permisos más abiertos se reportan.

```
[WARNING] /home/usuario tiene permisos 755 (lectura por todos)
          ↳ Recomendación: chmod 750 "/home/usuario"
```

### Directorios `.ssh`
Verifica los permisos requeridos por SSH para aceptar autenticación por clave pública.

| Ruta | Permisos requeridos |
|------|---------------------|
| `~/.ssh/` | `700` |
| `authorized_keys` | `600` |
| Claves privadas (`id_rsa`, `id_ed25519`...) | `600` |
| Claves públicas (`*.pub`) | `644` |

### `/var/www`
Detecta archivos y directorios escribibles por cualquier usuario en el webroot. Un archivo escribible en el webroot puede permitir la inyección de código malicioso.

### `/tmp` y `/var/tmp`
Verifica que ambos directorios tengan el sticky bit activo (`1777`) y comprueba si `/tmp` está montado con la opción `noexec`.

### Archivos huérfanos
Busca en todo el sistema archivos sin propietario válido (`-nouser` / `-nogroup`), que pueden indicar cuentas eliminadas con ficheros residuales.

## Formato de salida

```
[CRITICAL] descripción del problema
  ↳ Recomendación: comando de corrección

[WARNING]  descripción del problema
  ↳ Recomendación: comando de corrección

[INFO]     descripción informativa
```

Al finalizar se muestra un resumen con el total de hallazgos por nivel.

## Notas

- Sin `root` algunos análisis (SUID global, `/root`) pueden estar limitados.
- Para corregir automáticamente los permisos detectados, usar [`fileshield`](fileshield.md).

## Ejemplo de log
```
[2026-03-19 14:41:22] [SECTION]  Archivos world-writable (777 / o+w)
[2026-03-19 14:41:22] [CRITICAL] Archivo world-writable: /tmp/archivo-peligroso.conf
[2026-03-19 14:41:22] [FIX]      chmod o-w "/tmp/archivo-peligroso.conf"
[2026-03-19 14:41:23] [CRITICAL] SUID NO reconocido: /opt/mi-herramienta-suid
[2026-03-19 14:41:23] [FIX]      chmod u-s "/opt/mi-herramienta-suid"
```

