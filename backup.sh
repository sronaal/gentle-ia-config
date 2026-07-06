#!/bin/bash
# backup.sh — Actualiza el backup desde las configs en vivo
# Ejecutar: cd ~/.config-backup && ./backup.sh

set -e

BACKUP_DIR="$(cd "$(dirname "$0")" && pwd)"
USER_HOME="$HOME"
DATE=$(date '+%Y-%m-%d %H:%M')

echo "=== Gentle AI Config Backup ==="
echo "Fecha: $DATE"
echo ""

# 1. OpenCode config (excluyendo node_modules)
echo "[1/5] Copiando OpenCode config..."
rsync -a --delete --exclude=node_modules "$USER_HOME/.config/opencode/" "$BACKUP_DIR/opencode-config/"
echo "  ✅ opencode-config/"

# 2. Agent skills
echo "[2/5] Copiando agent skills..."
rsync -a --delete "$USER_HOME/.agents/skills/" "$BACKUP_DIR/agents-skills/"
echo "  ✅ agents-skills/"

# 3. Dotfiles
echo "[3/5] Copiando dotfiles..."
cp "$USER_HOME/.zshrc"     "$BACKUP_DIR/dotfiles/zshrc"
cp "$USER_HOME/.gitconfig" "$BACKUP_DIR/dotfiles/gitconfig"
cp "$USER_HOME/.p10k.zsh"  "$BACKUP_DIR/dotfiles/p10k.zsh"
cp "$USER_HOME/.bashrc"    "$BACKUP_DIR/dotfiles/bashrc"
cp "$USER_HOME/.profile"   "$BACKUP_DIR/dotfiles/profile"
echo "  ✅ dotfiles/"

# 4. Skill registry
echo "[4/5] Copiando skill registry..."
cp "$USER_HOME/.atl/skill-registry.md" "$BACKUP_DIR/atl/"
echo "  ✅ atl/"

# 5. Engram (backup seguro de la DB SQLite)
echo "[5/5] Respaldando Engram..."
if [ -f "$USER_HOME/.engram/engram.db" ]; then
    sqlite3 "$USER_HOME/.engram/engram.db" ".backup '$BACKUP_DIR/engram/engram-backup.db'" 2>/dev/null || \
    cp "$USER_HOME/.engram/engram.db" "$BACKUP_DIR/engram/engram-copy.db"
    echo "  ✅ engram/ (backup via sqlite3)"
else
    echo "  ⚠️  No se encontró engram.db"
fi

# 6. Auto-commit + push (si hay cambios)
echo "[6/6] Commiteando y pusheando..."
cd "$BACKUP_DIR"
if ! git diff --quiet HEAD || ! git diff --cached --quiet; then
    git add -A
    git commit -m "backup: $(date '+%Y-%m-%d')"
    git push
    echo "  ✅ Commit y push exitoso"
else
    echo "  ℹ️  Sin cambios nuevos"
fi

echo ""
echo "=== Backup completado ==="
