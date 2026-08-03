---
name: azure-vm-enum
description: Enumerar Azure VMs, discos, NICs, NSGs, Managed Identities, VM extensions, availability sets y scale sets
phase: cloud-enum
---

# azure-vm-enum — Enumeración de Azure VMs

## Activation Contract

**Trigger**: Se cuenta con acceso a Azure CLI (`az`) autenticado en la suscripción target, o se detectaron VMs en el resource graph del target.

**Pre-requisitos**:
- Azure CLI configurado (`az login --service-principal` o `az login` con device code)
- Permisos `Reader` a nivel de suscripción (o al menos en los resource groups objetivo)
- `az account set --subscription <sub-id>` para apuntar a la suscripción correcta

## Hard Rules

1. NO modificar VMs (start, stop, restart, delete, update)
2. NO crear/eliminar snapshots de discos
3. NO ejecutar comandos en VMs (eso es explotación)
4. OPSEC: `--output json`, paginación con `--max-items`, jitter entre consultas
5. NO leer extensiones de VM que requieran secretos o keys de acceso

## Decision Gates

Preguntar al usuario ANTES de:
- Listar las `Managed Identities` asignadas a VMs (indica qué recursos puede acceder la VM)
- Leer `RunCommand` outputs históricos (pueden contener credenciales en texto plano)
- Enumerar todas las VMs de la suscripción (puede ser un volumen grande)

## Execution Steps

### Paso 1: Listar suscripciones y resource groups
```bash
az account list --output table
az account set --subscription <sub-id>
az group list --output table
```

### Paso 2: Listar VMs
```bash
az vm list --output json | jq '[.[] | {name: .name, rg: .resourceGroup, location: .location, vmId: .vmId, hardware: .hardwareProfile.vmSize, os: .storageProfile.osDisk.osType, status: .provisioningState}]'
```
Extraer: `name`, `resourceGroup`, `location`, `vmSize` (tipo de instancia), `osType` (Linux/Windows), `provisioningState`.

### Paso 3: Describir cada VM en detalle
```bash
az vm show --name <vm-name> --resource-group <rg> --expand instanceView
```
Extraer:
- `identity` → `type` (SystemAssigned, UserAssigned, None), `principalId` (AAD object ID de la managed identity)
- `networkProfile` → `networkInterfaces[]`
- `storageProfile` → `osDisk`, `dataDisks[]`
- `instanceView` → `statuses[]`, `vmAgent` (versión), `extensions[]`
- `diagnosticsProfile` → `bootDiagnostics` (habilitado/deshabilitado)
- `availabilitySet` → `id` (si aplica)

### Paso 4: Enumerar NICs y NSGs (ataque surface)
```bash
az vm nic list --vm-name <vm-name> --resource-group <rg>
az network nic show --ids <nic-id> | jq '{name: .name, privateIp: .ipConfigurations[0].privateIpAddress, publicIp: .ipConfigurations[0].publicIpAddress?.id, nsg: .networkSecurityGroup?.id}'
```
```bash
# IPs públicas asignadas
az network public-ip show --ids <public-ip-id>
```
```bash
# Reglas del NSG (puertos abiertos)
az network nsg show --ids <nsg-id> | jq '.securityRules[] | {name: .name, direction: .direction, access: .access, protocol: .protocol, sourcePortRange: .sourcePortRange, destinationPortRange: .destinationPortRange, sourceAddressPrefix: .sourceAddressPrefix, destinationAddressPrefix: .destinationAddressPrefix}'
```
**Caso crítico**: NSG con `0.0.0.0/0` en puertos 22, 3389, 443 o 8443.

### Paso 5: Enumerar Managed Identities
```bash
# System-assigned
az vm show --name <vm> --rg <rg> --query identity
# User-assigned
az identity list --resource-group <rg>
```
Documentar qué identidad está asignada a cada VM para identificar potenciales tokens que se puedan robar.

### Paso 6: Enumerar VM extensions
```bash
az vm extension list --vm-name <vm-name> --resource-group <rg>
az vm extension show --vm-name <vm> --rg <rg> --name <ext-name>
```
Extensiones de interés:
- `CustomScriptExtension` / `CustomScript` — puede contener scripts con credenciales hardcodeadas
- `DependencyAgent`, `AzureMonitorWindowsAgent` — monitoreo
- `AADSSHLoginForLinux` — login SSH via Azure AD
- `DockerExtension` — Docker expuesto

### Paso 7: Enumerar discos y snapshots
```bash
az disk list --resource-group <rg>
az disk show --name <disk-name> --resource-group <rg>
```
Detectar si hay snapshots de discos (posible extracción de secrets):
```bash
az snapshot list --resource-group <rg>
```

### Paso 8: Enumerar availability sets y scale sets
```bash
az vm availability-set list --resource-group <rg>
az vmss list --resource-group <rg>
az vmss show --name <vmss> --resource-group <rg>
```

## Output Contract

```json
{
  "phase": "cloud-enum",
  "skill": "azure-vm-enum",
  "target": "<subscription-id>",
  "vms": [
    {
      "name": "prod-web-01",
      "location": "eastus",
      "os": "Linux",
      "size": "Standard_D2s_v3",
      "public_ips": ["20.10.10.10"],
      "open_ports": ["22", "443", "8443"],
      "managed_identity": "SystemAssigned (principalId: xxxx)",
      "extensions": ["CustomScriptExtension", "DependencyAgent"],
      "availability_set": "prod-as"
    }
  ],
  "disks": [
    {"name": "prod-web-osdisk", "type": "SSD", "size_gb": 128, "encrypted": false}
  ],
  "identity_map": [
    {"vm": "prod-web-01", "identity": "prod-web-mi", "type": "UserAssigned"}
  ],
  "findings": [
    {
      "title": "VM expuesta a Internet con puerto 22 abierto",
      "severity": "medium",
      "category": "exposed-vm",
      "evidence": "prod-web-01 tiene NSG permitiendo SSH desde 0.0.0.0/0",
      "remediation": "Restringir NSG a IPs corporativas o usar Azure Bastion",
      "next_steps": ["Probar si se puede acceder via SSH sin credenciales", "Enumerar si tiene CustomScriptExtension con credenciales"]
    },
    {
      "title": "Disco del sistema operativo sin cifrado",
      "severity": "medium",
      "category": "unencrypted-disk",
      "evidence": "prod-web-osdisk tiene encryption.type=null",
      "remediation": "Habilitar Azure Disk Encryption"
    }
  ],
  "next_phase": "cloud-exploit",
  "recommended_skills": ["azure-vm-exploit", "cloud-credential-harvest"]
}
```
