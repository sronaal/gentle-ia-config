# Engram — Backup & Restore

Engram es una base de datos SQLite que almacena memoria persistente (decisiones, bugs, discoveries, artifacts SDD).

## Backup

### Método recomendado (backup seguro)

```bash
sqlite3 ~/.engram/engram.db ".backup 'engram-backup.db'"
```

Esto crea un snapshot consistente sin riesgo de corrupción.

### Método rápido (solo si Engram NO está corriendo)

```bash
cp ~/.engram/engram.db engram-copy.db
```

## Restore

```bash
# Detener Engram si está corriendo
pkill engram 2>/dev/null; sleep 1

# Restaurar
cp engram-backup.db ~/.engram/engram.db

# O desde copia directa
cp engram-copy.db ~/.engram/engram.db
```

## Automatización

El script `backup.sh` ejecuta el backup seguro automáticamente.

## Notas

- La DB puede estar bloqueada mientras OpenCode está activo
- Si el backup falla por "database is locked", cerrar OpenCode primero
- Los archivos `*.db-wal` y `*.db-shm` son temporales de SQLite — no son necesarios para restore
