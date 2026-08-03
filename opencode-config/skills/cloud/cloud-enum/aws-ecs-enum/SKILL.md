---
name: aws-ecs-enum
description: Enumerar clusters ECS, tasks, servicios, task definitions, container instances y roles IAM vinculados
phase: cloud-enum
---

# aws-ecs-enum — Enumeración de ECS

## Activation Contract

**Trigger**: Se detectó que el target usa ECS (por etiquetas en recursos, roles IAM con `ecs-tasks.amazonaws.com`, o containers expuestos).

**Pre-requisitos**:
- AWS CLI configurado con perfil (`--profile <target>`)
- Permisos `ecs:ListClusters`, `ecs:DescribeClusters`, `ecs:ListServices`, `ecs:ListTasks`, `ecs:DescribeTaskDefinition`, `ecs:DescribeContainerInstances`
- (Opcional) `ssm:DescribeInstanceInformation` si se usan instancias EC2 como capacity provider

## Hard Rules

1. NO ejecutar `RunTask` ni `StartTask` — eso es explotación, no enumeración
2. NO actualizar servicios ni task definitions
3. NO modificar el estado de clusters ni container instances
4. OPSEC: `--no-cli-pager`, `--output json`, 1 request por segundo para no rate-limitear

## Decision Gates

Preguntar al usuario ANTES de:
- Conectarse a un container vía ECS Exec (requiere `ecs:ExecuteCommand`)
- Listar variables de entorno de tasks activas (pueden contener secrets en texto plano)
- Leer logs de CloudWatch asociados a tasks

## Execution Steps

### Paso 1: Listar clusters
```bash
aws ecs list-clusters --profile <target> --region <region>
aws ecs describe-clusters --clusters <cluster-arn> --include ATTACHMENTS --profile <target>
```
Extraer: `clusterName`, `status`, `activeServicesCount`, `runningTasksCount`, `capacityProviders`, `settings` (containerInsights, etc.), `tags`.

### Paso 2: Listar servicios
```bash
aws ecs list-services --cluster <cluster-name> --profile <target>
aws ecs describe-services --cluster <cluster-name> --services <service-name> --profile <target>
```
Extraer: `serviceName`, `taskDefinition`, `desiredCount`, `runningCount`, `launchType` (FARGATE o EC2), `networkConfiguration`, `loadBalancers`, `role` (IAM role del servicio).

### Paso 3: Listar tasks activas
```bash
aws ecs list-tasks --cluster <cluster-name> --profile <target>
aws ecs describe-tasks --cluster <cluster-name> --tasks <task-arn> --profile <target>
```
Extraer: `taskDefinitionArn`, `lastStatus`, `desiredStatus`, `containers` (name, image, runtimeId), `startedBy`, `overrides`, `availabilityZone`, `connectivity` (para Fargate Spot).

### Paso 4: Describir task definitions (la joya — secretos!)
```bash
# Obtener task definition activa
TASK_DEF=$(aws ecs describe-services --cluster <cluster> --services <service> \
  --query 'services[0].taskDefinition' --output text --profile <target>)

# Describir la task definition completa
aws ecs describe-task-definition --task-definition $TASK_DEF --profile <target>
```
Extraer: `containerDefinitions` → `environment` (variables de entorno en texto plano), `secrets` (referencias a Secrets Manager o Parameter Store — documentar el ARN, no leer el valor), `logConfiguration`, `mountPoints`, `readonlyRootFilesystem`.

Señales de riesgo:
- Variables de entorno con nombres como `DB_PASSWORD`, `API_KEY`, `SECRET`
- `secrets` apuntando a parámetros de SSM (posible escalación)
- Container con `readonlyRootFilesystem: false`

### Paso 5: Enumerar container instances (solo EC2 launch type)
```bash
aws ecs list-container-instances --cluster <cluster> --profile <target>
aws ecs describe-container-instances --cluster <cluster> --container-instances <instance> --profile <target>
```
Extraer: `ec2InstanceId`, `agentConnected`, `runningTasksCount`, `remainingResources` (CPU, memory), `attributes`.

### Paso 6: Mapear IAM roles
- Task execution role: `taskDefinition.executionRoleArn` — permisos para pull de imágenes y logs
- Task role: `taskDefinition.taskRoleArn` — el rol que la task asume para interactuar con otros servicios
- Service role: `service.role` — rol que ECS usa para integrarse con ELB, etc.

Documentar cada rol, anotar si están sobredimensionados (ej: task role con `AdministratorAccess`).

### Paso 7: Identificar imágenes y registries
```bash
aws ecr describe-repositories --profile <target>
aws ecr list-images --repository-name <repo> --profile <target>
```
Si la imagen es privada y el repositorio ECR no tiene auth, se puede intentar pull posteriormente.

## Output Contract

```json
{
  "phase": "cloud-enum",
  "skill": "aws-ecs-enum",
  "target": "<account-id>",
  "clusters": [
    {
      "name": "prod-cluster",
      "status": "ACTIVE",
      "services_count": 5,
      "running_tasks": 12,
      "launch_types": ["FARGATE", "EC2"]
    }
  ],
  "task_definitions": [
    {
      "family": "api-service",
      "revision": 42,
      "images": ["nginx:1.25", "myapp:latest"],
      "env_vars_plaintext": ["DB_HOST=prod-db.internal", "DB_USER=app"],
      "secrets_refs": ["arn:aws:ssm:.../prod/DB_PASSWORD"],
      "execution_role_arn": "arn:aws:iam::...:role/ecsTaskExecutionRole",
      "task_role_arn": "arn:aws:iam::...:role/apiTaskRole",
      "risk": "high"
    }
  ],
  "findings": [
    {
      "title": "Variables de entorno con secretos en texto plano",
      "severity": "high",
      "category": "ecs-secrets-exposure",
      "evidence": "La task definition api-service:42 expone DB_PASSWORD via environment (no Secrets Manager)",
      "remediation": "Migrar environment a secrets con referencia a AWS Secrets Manager",
      "next_steps": ["Verificar si DB_HOST es accesible desde internet", "Probar credenciales descubiertas"]
    }
  ],
  "next_phase": "cloud-exploit",
  "recommended_skills": ["aws-ecs-exploit", "cloud-iam-enum"]
}
```
