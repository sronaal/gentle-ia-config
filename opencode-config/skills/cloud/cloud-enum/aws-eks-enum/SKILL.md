---
name: aws-eks-enum
description: Enumerar clusters EKS, node groups, fargate profiles, ConfigMaps, secrets, deployments, service accounts y roles IAM vinculados
phase: cloud-enum
---

# aws-eks-enum — Enumeración de EKS

## Activation Contract

**Trigger**: Se detectó un cluster EKS activo (por rol IAM `eks.amazonaws.com`, etiquetas `kubernetes.io/cluster/`, o endpoints de K8s API expuestos).

**Pre-requisitos**:
- AWS CLI configurado (`--profile <target>`)
- `kubectl` instalado y configurado
- Permisos `eks:ListClusters`, `eks:DescribeCluster`, `eks:ListNodegroups`, `eks:DescribeNodegroup`
- Autenticación al cluster: `aws eks update-kubeconfig --name <cluster> --profile <target>`

## Hard Rules

1. NO modificar recursos de K8s (deployments, configmaps, secrets, roles)
2. NO ejecutar pods en el cluster salvo autorización expresa
3. NO escalar nodegroups ni modificar su configuración
4. OPSEC: usar `--output json` y `-o json` en kubectl, jitter entre namespaces

## Decision Gates

Preguntar al usuario ANTES de:
- Listar Secrets de K8s (pueden exponer credenciales de producción)
- Leer ConfigMaps con datos sensibles
- Intentar acceso anónimo al K8s API endpoint público
- Usar `describe` en pods de namespaces críticos (kube-system, production)

## Execution Steps

### Paso 1: Listar y describir clusters
```bash
aws eks list-clusters --profile <target> --region <region>
aws eks describe-cluster --name <cluster-name> --profile <target>
```
Extraer: `endpoint` (API server URL), `clusterSecurityGroupId`, `roleArn` (cluster IAM role), `resourcesVpcConfig` (subnets, security groups, endpointPublicAccess, endpointPrivateAccess), `encryptionConfig`, `logging` (habilitado o no).

**Caso crítico**: `resourcesVpcConfig.endpointPublicAccess: true` — API K8s expuesta públicamente.

### Paso 2: Autenticarse al cluster
```bash
aws eks update-kubeconfig --name <cluster-name> --profile <target> --region <region>
kubectl auth can-i --list  # Ver permisos del IAM user/role
```

### Paso 3: Enumerar recursos de K8s
```bash
kubectl get namespaces -o json
kubectl get nodes -o wide
kubectl describe nodes  # Ver si hay pods con service accounts montadas
kubectl get pods --all-namespaces -o json | jq '.items[] | {name: .metadata.name, ns: .metadata.namespace, sa: .spec.serviceAccount, node: .spec.nodeName}'
kubectl get deployments --all-namespaces -o json
kubectl get services --all-namespaces -o json
```
Identificar:
- Namespaces no estándar (no `kube-system`, `kube-public`, `default`)
- Pods con `automountServiceAccountToken: true` (default)
- Services de tipo `LoadBalancer` (expuestos)

### Paso 4: Enumerar ConfigMaps y Secrets (solo con autorización)
```bash
kubectl get secrets --all-namespaces -o json | jq '.items[] | {name: .metadata.name, ns: .metadata.namespace, keys: .data | keys}'
kubectl get configmaps --all-namespaces -o json
```
Señales de riesgo:
- Secrets con nombres como `db-password`, `api-key`, `tls-*`
- ConfigMaps con datos en base64 (chequear si `data` tiene contenido sensible)

### Paso 5: Enumerar service accounts y roles
```bash
kubectl get serviceaccounts --all-namespaces -o json | jq '.items[] | {name: .metadata.name, ns: .metadata.namespace, secrets: [.secrets[].name]}'
kubectl get clusterroles -o json | jq '.items[] | {name: .metadata.name, rules: [.rules[].resources[], .rules[].verbs[]]}'
kubectl get clusterrolebindings -o json
```
Identificar:
- Service Accounts con roles de alto privilegio (cluster-admin)
- Service Accounts vinculadas a pods en namespaces de producción
- ClusterRoleBindings a `system:anonymous` o `system:unauthenticated`

### Paso 6: Enumerar nodegroups y Fargate profiles
```bash
aws eks list-nodegroups --cluster-name <cluster> --profile <target>
aws eks describe-nodegroup --cluster-name <cluster> --nodegroup-name <ng> --profile <target>
```
Extraer: `nodeRole` (IAM role de los worker nodes), `instanceTypes`, `diskSize`, `scalingConfig`, `subnets`, `amiType`, `capacityType` (ON_DEMAND o SPOT).

```bash
aws eks list-fargate-profiles --cluster-name <cluster> --profile <target>
```

### Paso 7: Mapear OIDC provider
```bash
aws iam list-open-id-connect-providers --profile <target>
# Asociar OIDC provider con el cluster EKS
aws eks describe-cluster --name <cluster> --query 'cluster.identity.oidc.issuer' --output text
```

## Output Contract

```json
{
  "phase": "cloud-enum",
  "skill": "aws-eks-enum",
  "target": "<cluster-name>",
  "cluster": {
    "name": "prod-eks",
    "endpoint": "https://XXXXXXXX.gr7.us-east-1.eks.amazonaws.com",
    "public_access": true,
    "k8s_version": "1.28",
    "node_groups": [
      {"name": "workers", "node_role": "arn:aws:iam::...:role/EKSWorkerRole", "instance_type": "t3.large", "min": 3, "max": 10}
    ]
  },
  "k8s_resources": {
    "namespaces": ["default", "kube-system", "production", "staging"],
    "pods_total": 47,
    "service_accounts_high_risk": [
      {"name": "cluster-admin-sa", "namespace": "kube-system", "role": "cluster-admin"}
    ]
  },
  "findings": [
    {
      "title": "EKS API endpoint expuesto públicamente",
      "severity": "high",
      "category": "eks-api-exposed",
      "evidence": "endpointPublicAccess: true en cluster <name>",
      "remediation": "Restringir endpoint a acceso privado o listas de IP confiables",
      "next_steps": ["Probar acceso anónimo al endpoint", "Verificar si está protegido por WAF/IP whitelist"]
    }
  ],
  "next_phase": "cloud-exploit",
  "recommended_skills": ["aws-eks-exploit", "k8s-rbac-deep", "cloud-iam-enum"]
}
```
