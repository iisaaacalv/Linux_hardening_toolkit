# 🛡️ Linux Hardening Toolkit

Conjunto de herramientas de bastionado para sistemas Linux, desarrolladas como proyecto de seguridad de sistemas. Cada herramienta aborda un vector de riesgo diferente y puede usarse de forma independiente o combinada.

> **Entorno:** Linux (Ubuntu / Debian / RHEL / CentOS)  
> **Requisitos:** Bash 4+, ejecutar como `root` o con `sudo`  
> **Licencia:** MIT

---

## 📁 Estructura del repositorio

```
linux-hardening-toolkit/
│
├── README.md                  ← Este fichero
│
├── tools/                     ← Las 5 herramientas principales
│   ├── permwatch.sh
│   ├── fileshield.sh
│   ├── porthush.sh
│   ├── confguardian.sh
│   └── useraudit.sh
│
└── docs/                      ← Documentación extendida por herramienta
    ├── permwatch.md
    ├── fileshield.md
    ├── porthush.md
    ├── confguardian.md
    └── useraudit.md
```

---

## 🚀 Inicio rápido

```bash
# 1. Clonar el repositorio
git clone https://github.com/tu-usuario/linux-hardening-toolkit.git
cd linux-hardening-toolkit

# 2. Dar permisos de ejecución
chmod +x tools/*.sh

# 3. Auditoría inicial completa (recomendado empezar aquí)
sudo ./tools/permwatch.sh
sudo ./tools/porthush.sh
sudo ./tools/useraudit.sh

# 4. Generar baseline de integridad
sudo ./tools/confguardian.sh init

# 5. Aplicar bastionado activo (revisar antes con --audit)
sudo ./tools/fileshield.sh --audit
sudo ./tools/fileshield.sh --apply
```

---

## 🔧 Herramientas

### 1. `permwatch` — Auditoría de permisos inseguros

Recorre rutas críticas del sistema en busca de permisos peligrosos que puedan facilitar escaladas de privilegios o acceso no autorizado.

**Detecta:**
- Archivos y directorios con permisos `777` / `o+w`
- Binarios con bits **SUID/SGID** (con lista blanca de legítimos)
- Directorios world-writable sin sticky bit
- Permisos incorrectos en `/home`, `.ssh`, `/var/www`, `/tmp`
- Archivos sin propietario válido (orphaned)

**Uso básico:**
```bash
sudo ./tools/permwatch.sh
sudo ./tools/permwatch.sh --log audit.log
```

📄 [Documentación completa → docs/permwatch.md](docs/permwatch.md)

---

### 2. `fileshield` — Bastionado activo de permisos

Complemento de `permwatch`: en lugar de solo reportar, **corrige** los permisos inseguros. Dispone de tres modos de operación con distinta agresividad.

**Actúa sobre:** `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/root`, `/home/*`, `/tmp`, `/var/www`, `~/.ssh`

**Modos:**

| Flag | Comportamiento |
|------|---------------|
| `--audit` | Solo muestra problemas, sin cambios |
| `--apply` | Corrige automáticamente permisos inseguros |
| `--strict` | Hardening agresivo: `chattr +i`, `700` en homes, elimina ejecutables en `/tmp` |

**Uso básico:**
```bash
sudo ./tools/fileshield.sh --audit
sudo ./tools/fileshield.sh --apply
sudo ./tools/fileshield.sh --strict
```

📄 [Documentación completa → docs/fileshield.md](docs/fileshield.md)

---

### 3. `porthush` — Análisis de superficie de red

Evalúa qué servicios están escuchando en el sistema y determina si su exposición es adecuada, aplicando el principio de **mínima exposición**.

**Detecta:** +60 servicios catalogados por riesgo (Redis, MongoDB, Docker API, VNC, Telnet, RDP, SMB...), estado del firewall, interfaces en modo promiscuo, IPv6 sin reglas.

**Uso básico:**
```bash
sudo ./tools/porthush.sh
sudo ./tools/porthush.sh --filter critical
sudo ./tools/porthush.sh --format csv --log puertos.csv
```

📄 [Documentación completa → docs/porthush.md](docs/porthush.md)

---

### 4. `confguardian` — Monitorización de integridad

Genera un **baseline** de los archivos de configuración críticos y detecta cualquier modificación posterior, sea accidental o maliciosa.

**Monitoriza:** `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `sshd_config`, `/etc/fstab`, archivos PAM, crontab, sysctl, y más (+30 por defecto).

**Uso básico:**
```bash
sudo ./tools/confguardian.sh init     # primera vez
sudo ./tools/confguardian.sh check    # verificar integridad
sudo ./tools/confguardian.sh watch    # monitorización continua
```

📄 [Documentación completa → docs/confguardian.md](docs/confguardian.md)

---

### 5. `useraudit` — Auditoría de usuarios y privilegios

Analiza las cuentas del sistema para detectar configuraciones inseguras en identidades, contraseñas y privilegios.

**Detecta:** usuarios con UID 0, cuentas sin contraseña, políticas de caducidad, cuentas inactivas, shells en servicios, duplicados, privilegios sudo peligrosos, acceso root remoto.

**Uso básico:**
```bash
sudo ./tools/useraudit.sh
sudo ./tools/useraudit.sh --inactive-days 30
sudo ./tools/useraudit.sh --format csv --log users.csv
```

📄 [Documentación completa → docs/useraudit.md](docs/useraudit.md)

---

## 📊 Niveles de riesgo

Todas las herramientas utilizan una nomenclatura consistente:

| Nivel | Significado | Acción recomendada |
|-------|-------------|-------------------|
| 🔴 `CRITICAL` | Riesgo inmediato de compromiso | Corregir de inmediato |
| 🟡 `WARNING` | Configuración insegura o subóptima | Revisar y corregir pronto |
| 🔵 `INFO` | Información relevante, riesgo bajo | Evaluar según contexto |
| 🟢 `OK / SAFE` | Configuración correcta | Sin acción necesaria |

---

## 📋 Dependencias

Las herramientas usan exclusivamente utilidades estándar de Linux:

| Utilidad | Uso | Paquete |
|----------|-----|---------|
| `ss` / `netstat` | Análisis de red | `iproute2` / `net-tools` |
| `find`, `stat`, `chmod`, `chown` | Gestión de permisos | coreutils |
| `sha256sum` / `sha512sum` | Hashing de integridad | coreutils |
| `lastlog`, `last` | Actividad de usuarios | util-linux |
| `lsof` | Procesos por puerto | `lsof` |
| `chattr` | Flag inmutable (fileshield strict) | `e2fsprogs` |

```bash
# Ubuntu / Debian
sudo apt install iproute2 lsof e2fsprogs util-linux

# RHEL / CentOS
sudo dnf install iproute lsof e2fsprogs util-linux
```

---

## ⚠️ Advertencias

- Todas las herramientas requieren **privilegios de root** para acceder a `/etc/shadow` y realizar cambios en el sistema.
- `fileshield --strict` aplica cambios agresivos. **Revisar siempre con `--audit` antes** de usar `--apply` o `--strict` en sistemas en producción.
- `confguardian watch` es un proceso en primer plano. Para uso continuado, considerarlo como servicio systemd.

---

## 👨‍💻 Autor

Desarrollado como proyecto de la asignatura de **Seguridad en Sistemas** · Curso 2024-2025
