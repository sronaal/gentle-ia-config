# Gentle AI — Config Backup & Restore

Backup completo del orchestrator SDD + skills + dotfiles para disaster recovery.
Podés restaurar todo desde cero en una máquina limpia con un solo comando.

---

## 📦 ¿Qué incluye?

| Componente | Path | Tamaño | Descripción |
|---|---|---|---|
| OpenCode Config | `opencode-config/` | ~600KB | Config del orchestrator (`opencode.json`), skills SDD (22 skills), prompts de fases, plugins, comandos |
| Agent Skills | `agents-skills/` | ~2.9MB | Skills de diseño/UX/imagen (~26 skills: impeccable, brandkit, layers, etc.) |
| Dotfiles | `dotfiles/` | ~50KB | `.zshrc`, `.gitconfig`, `.p10k.zsh`, `.bashrc`, `.profile` |
| Skill Registry | `atl/` | ~24KB | Índice completo de skills con triggers y paths |
| Engram | `engram/BACKUP.md` | — | Instrucciones para backup/restore de la base de memoria persistente |

---

## 🆕 Instalación desde cero (máquina limpia)

Seguí estos pasos en una máquina recién instalada.

### Paso 1: Prerequisitos

```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar git
sudo apt install git -y

# Instalar Node.js (v18+)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install nodejs -y

# Instalar rsync (para backup.sh)
sudo apt install rsync -y

# Verificar
git --version      # → git 2.x
node --version     # → v20.x
npm --version      # → 10.x
```

### Paso 2: Instalar OpenCode

```bash
npm install -g @opencode/opencode
opencode --version  # → 1.x
```

Si no querés instalación global, podés instalarlo local:

```bash
mkdir -p ~/.opencode && cd ~/.opencode
npm init -y
npm install @opencode/opencode
# El binario queda en ~/.opencode/bin/opencode
```

### Paso 3: Configurar Git

```bash
git config --global user.name "Tu Nombre"
git config --global user.email "tu@email.com"
```

### Paso 4: Clonar este repositorio

```bash
# Si está en GitHub:
git clone <repo-url> ~/.config-backup

# O si es local (desde USB/backup externo):
cp -r /media/backup/gentle-ai-config ~/.config-backup
```

### Paso 5: Restaurar todo

```bash
cd ~/.config-backup
chmod +x install.sh
./install.sh --apply
```

Esto restaura automáticamente:
- ✅ Dotfiles (.zshrc, .gitconfig, .p10k.zsh, .bashrc, .profile)
- ✅ OpenCode config (opencode.json, skills, prompts, plugins, comandos)
- ✅ Agent skills (diseño/UX)
- ✅ Skill registry
- ✅ Engram (memoria persistente, si hay backup)

### Paso 6: Recargar terminal y verificar

```bash
# Cerrar y abrir terminal, o:
source ~/.zshrc

# Verificar que OpenCode tiene todo:
opencode --version

# Opcional: abrir OpenCode y probar
opencode
```

### Paso 7: Verificar que el orchestrator está vivo

Dentro de OpenCode, probar que responde:

```
/sdd-status
```

Debería mostrar que no hay cambios activos pero que el sistema responde.

---

## 📤 Cómo mantener el backup actualizado

Después de cambios importantes en el orchestrator (nuevas features, skills, config), actualizar el backup:

```bash
cd ~/.config-backup
./backup.sh                      # Copia configs actuales
git add -A
git commit -m "backup: $(date +%Y-%m-%d) — descripción del cambio"
git push
```

> **Importante**: el orchestrador está programado para recordar esto. Cuando termines un cambio grande, él mismo va a ejecutar el backup.

### Backup automático (cron)

Para backup semanal automático:

```bash
crontab -e
# Agregar:
0 9 * * 1 cd ~/.config-backup && ./backup.sh && git add -A && git commit -m "backup semanal $(date +%Y-%m-%d)" && git push
```

---

## 🔄 Cómo funciona el restore (`install.sh`)

El script tiene dos modos:

| Modo | Comando | Qué hace |
|------|---------|----------|
| Interactivo | `./install.sh` | Pregunta antes de cada paso |
| Automático | `./install.sh --apply` | Ejecuta todo sin preguntar |

Lo que hace exactamente:

1. **Prerequisitos**: verifica que git, node, npm, rsync existen
2. **Dotfiles**: copia `.zshrc`, `.gitconfig`, `.p10k.zsh`, `.bashrc`, `.profile` al `$HOME`
3. **OpenCode**: si no está instalado, lo instala vía npm
4. **Config**: copia `opencode-config/` a `~/.config/opencode/` y corre `npm install`
5. **Skills**: copia `agents-skills/` a `~/.agents/skills/`
6. **Registry**: copia `atl/skill-registry.md` a `~/.atl/`
7. **Engram**: restaura la DB de memoria si hay backup disponible

---

## 🔐 Lo que NO incluye (y cómo protegerlo)

| Componente | Excluido porque | Cómo respaldarlo |
|---|---|---|
| `~/.ssh/` | Claves privadas, secretos | Backup aparte con encriptación (ej: `tar czf ssh-backup.tar.gz ~/.ssh/` y guardar en lugar seguro) |
| `~/.env` / `*.pem` | Secretos de API, tokens | Usar un gestor de contraseñas (Bitwarden, 1Password) |
| `node_modules/` | Reinstalable | `npm install` lo regenera |
| `~/.opencode/bin/` | Reinstalable | `npm install -g @opencode/opencode` lo regenera |

---

## 💾 Engram — Backup de memoria persistente

Engram es la base SQLite donde el orchestrator guarda decisiones, bugs, discoveries, y artifacts SDD.
Si perdés Engram, perdés la memoria cross-session.

Ver `engram/BACKUP.md` para instrucciones detalladas.

**Backup manual**:
```bash
sqlite3 ~/.engram/engram.db ".backup 'engram-backup.db'"
```

**Restore**:
```bash
pkill engram 2>/dev/null; sleep 1
cp engram-backup.db ~/.engram/engram.db
```

---

## 🧠 Feature flags del orchestrator

Este backup incluye el orchestrator con estas features activas:

| Feature | Descripción | Estado |
|---|---|---|
| **F1: Prompt-Aware Routing** | Clasifica cambios en tiny/standard/war y ajusta el pipeline | ✅ Activo |
| **F2: Context Compression** | Comprime resultados de fases a ~500 tokens | ✅ Activo |
| **F3: Self-Healing** | Valida y repara envelopes Sección D automáticamente | ✅ Activo |
| **sdd-heal sub-agent** | Agente de reparación para envelopes fallidos | ✅ Activo |

---

## 🛟 Troubleshooting

### "opencode: command not found"
- Si instalaste global: `npm install -g @opencode/opencode`
- Si instalaste local: `export PATH=$PATH:~/.opencode/bin/` (agregar a `.zshrc`)

### "git no está instalado"
- `sudo apt install git -y`

### El restore no copió mis configs
- Verificá que corriste `./install.sh` desde `~/.config-backup/`
- Probá modo interactivo para ver dónde falla: `./install.sh`

### Engram no restaura las memorias
- Asegurate de tener el archivo `engram/engram-backup.db`
- Si Engram está corriendo, detenelo primero: `pkill engram`

---

## 📝 Notas finales

- Los paths asumen usuario `sronaalz`. Si tu usuario es diferente, editá `install.sh` y `backup.sh`
- El repo está diseñado para ser multiplataforma (Linux, macOS)
- Para contribuir o reportar issues, abrí un issue en el repo de GitHub
