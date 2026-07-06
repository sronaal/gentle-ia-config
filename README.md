# Gentle AI — Config Backup

Backup del orchestrator SDD + skills + dotfiles para restauración en caso de disaster recovery.

## ¿Qué incluye?

| Componente | Path de backup | Tamaño aprox | Descripción |
|---|---|---|---|
| OpenCode Config | `opencode-config/` | ~600KB | Config principal, skills SDD, prompts, plugins |
| Agent Skills | `agents-skills/` | ~2.9MB | Skills de diseño/UX (~26 skills) |
| Dotfiles | `dotfiles/` | ~50KB | .zshrc, .gitconfig, .p10k.zsh, .bashrc, .profile |
| Skill Registry | `atl/skill-registry.md` | ~24KB | Índice de skills disponibles |
| Engram DB | `engram/BACKUP.md` | ~5.7MB | Instrucciones para backup/restore de memoria persistente |

## Restauración completa (fresh install)

```bash
# 1. Clonar el repo
git clone <repo-url> ~/.config-backup
cd ~/.config-backup

# 2. Ejecutar instalación
chmod +x install.sh
./install.sh
```

El script `install.sh` instala todo automaticamente.

## Backup manual

```bash
cd ~/.config-backup
./backup.sh
git add -A && git commit -m "backup: $(date +%Y-%m-%d)"
git push
```

## Notas importantes

- **No incluye claves SSH ni secrets** — `.ssh/`, `.env`, `*.pem` están en `.gitignore`
- **node_modules no se incluye** — se reinstala con `npm install` en install.sh
- **Engram no se incluye directamente** — la base de datos SQLite puede corromperse si se copia en caliente. Ver `engram/BACKUP.md` para instrucciones.
- Los paths del backup asumen que el usuario se llama `sronaalz`. Si tu usuario es diferente, ajustar los paths en install.sh.
