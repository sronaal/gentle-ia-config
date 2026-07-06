#!/bin/bash
# install.sh — Restauración completa de configs desde backup
# Ejecutar en una máquina FRESCA después de clonar el repo
#
# Uso:
#   ./install.sh            # Modo interactivo
#   ./install.sh --apply    # Automático (sin preguntar)

set -e

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
USER_HOME="$HOME"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log()  { echo -e "${GREEN}✅${NC} $1"; }
warn() { echo -e "${YELLOW}⚠️${NC} $1"; }
info() { echo -e "${CYAN}ℹ️${NC} $1"; }
err()  { echo -e "${RED}❌${NC} $1"; }

AUTO=false
[[ "$1" == "--apply" ]] && AUTO=true

confirm() {
    if $AUTO; then return 0; fi
    echo -n "¿Continuar? (Y/n): "; read -r resp
    [[ "$resp" != "n" && "$resp" != "N" ]]
}

echo ""
echo "=============================================="
echo "  Gentle AI — Config Restoration"
echo "=============================================="
echo ""

# ─── Prerequisitos ───────────────────────────────────────
info "Verificando prerequisitos..."

PREREQ_OK=true
for cmd in git node npm rsync; do
    if ! command -v $cmd &>/dev/null; then
        err "$cmd no está instalado. Instalalo primero."
        PREREQ_OK=false
    fi
done

# rsync suele estar, pero si no...
if ! command -v rsync &>/dev/null; then
    warn "rsync no encontrado. Instalando..."
    if command -v apt &>/dev/null; then sudo apt install -y rsync
    elif command -v brew &>/dev/null; then brew install rsync
    else err "No se pudo instalar rsync. Instalalo manualmente."
    fi
fi

$PREREQ_OK || { err "Faltan prerequisitos. Instalalos y volvé a ejecutar."; exit 1; }
log "Prerequisitos OK"

# ─── 1. Restaurar dotfiles ────────────────────────────────
echo ""
info "[1/5] Restaurando dotfiles..."
if confirm; then
    [ -f "$INSTALL_DIR/dotfiles/zshrc" ]    && cp "$INSTALL_DIR/dotfiles/zshrc" "$USER_HOME/.zshrc"     && log ".zshrc restaurado"
    [ -f "$INSTALL_DIR/dotfiles/gitconfig" ] && cp "$INSTALL_DIR/dotfiles/gitconfig" "$USER_HOME/.gitconfig" && log ".gitconfig restaurado"
    [ -f "$INSTALL_DIR/dotfiles/p10k.zsh" ]  && cp "$INSTALL_DIR/dotfiles/p10k.zsh" "$USER_HOME/.p10k.zsh"   && log ".p10k.zsh restaurado"
    [ -f "$INSTALL_DIR/dotfiles/bashrc" ]    && cp "$INSTALL_DIR/dotfiles/bashrc" "$USER_HOME/.bashrc"     && log ".bashrc restaurado"
    [ -f "$INSTALL_DIR/dotfiles/profile" ]   && cp "$INSTALL_DIR/dotfiles/profile" "$USER_HOME/.profile"    && log ".profile restaurado"
fi

# ─── 2. Instalar OpenCode ────────────────────────────────
echo ""
info "[2/5] Instalando OpenCode..."
if confirm; then
    if command -v opencode &>/dev/null; then
        OPENCODE_VER=$(opencode --version 2>/dev/null || echo "desconocido")
        log "OpenCode ya instalado: v$OPENCODE_VER"
    else
        warn "Instalando OpenCode vía npm..."
        npm install -g @opencode/opencode || {
            warn "Instalación global falló. Probando local..."
            mkdir -p "$USER_HOME/.opencode"
            cd "$USER_HOME/.opencode"
            npm init -y
            npm install @opencode/opencode
            log "OpenCode instalado localmente en ~/.opencode"
        }
    fi
fi

# ─── 3. Restaurar OpenCode config ────────────────────────
echo ""
info "[3/5] Restaurando configuración de OpenCode..."
if confirm; then
    # Crear directorios destino
    mkdir -p "$USER_HOME/.config/opencode/skills"
    mkdir -p "$USER_HOME/.config/opencode/prompts/sdd"
    mkdir -p "$USER_HOME/.config/opencode/commands"
    mkdir -p "$USER_HOME/.config/opencode/plugins"
    mkdir -p "$USER_HOME/.config/opencode/profiles"
    mkdir -p "$USER_HOME/.config/opencode/tui-plugins"
    mkdir -p "$USER_HOME/.opencode/skills"
    mkdir -p "$USER_HOME/.agents/skills"
    mkdir -p "$USER_HOME/.atl"

    # Copiar configs
    rsync -a "$INSTALL_DIR/opencode-config/" "$USER_HOME/.config/opencode/"
    log "OpenCode config restaurada"

    # node_modules
    if [ -f "$USER_HOME/.config/opencode/package.json" ]; then
        warn "Instalando dependencias de OpenCode..."
        cd "$USER_HOME/.config/opencode"
        npm install --production 2>/dev/null && log "Dependencias instaladas" || warn "npm install falló (puede no ser necesario)"
    fi
fi

# ─── 4. Restaurar skills ─────────────────────────────────
echo ""
info "[4/5] Restaurando skills de agentes..."
if confirm; then
    rsync -a "$INSTALL_DIR/agents-skills/" "$USER_HOME/.agents/skills/"
    log "Agent skills restauradas (~/agents/skills/)"

    # Skill registry
    [ -f "$INSTALL_DIR/atl/skill-registry.md" ] && cp "$INSTALL_DIR/atl/skill-registry.md" "$USER_HOME/.atl/" && log "Skill registry restaurado"
fi

# ─── 5. Restaurar Engram (opcional) ──────────────────────
echo ""
info "[5/5] Restaurando Engram (memoria persistente)..."
if confirm; then
    ENGRAM_BACKUP="$INSTALL_DIR/engram/engram-backup.db"
    ENGRAM_COPY="$INSTALL_DIR/engram/engram-copy.db"

    if [ -f "$ENGRAM_BACKUP" ]; then
        mkdir -p "$USER_HOME/.engram"
        # Detener Engram si está corriendo
        pkill engram 2>/dev/null || true
        sleep 1
        cp "$ENGRAM_BACKUP" "$USER_HOME/.engram/engram.db"
        log "Engram restaurado desde backup SQLite"
    elif [ -f "$ENGRAM_COPY" ]; then
        mkdir -p "$USER_HOME/.engram"
        cp "$ENGRAM_COPY" "$USER_HOME/.engram/engram.db"
        log "Engram restaurado desde copia directa"
    else
        warn "No se encontró backup de Engram. Se creará uno nuevo al usar OpenCode."
    fi
fi

# ─── Final ────────────────────────────────────────────────
echo ""
echo "=============================================="
echo -e "${GREEN}  🎉 Restauración completada${NC}"
echo "=============================================="
echo ""
info "Recordá:"
echo "  1. Cerrar y reopen terminal (o: source ~/.zshrc)"
echo "  2. Verificar que OpenCode funciona: opencode --version"
echo "  3. Configurar GitHub: git config --global user.name / user.email si no están"
echo "  4. Para backup periódico: cd ~/.config-backup && ./backup.sh"
echo ""
info "Si algo no funciona, revisá los archivos en ~/.config-backup/"
echo "y ajustá los paths según tu usuario."
echo ""
