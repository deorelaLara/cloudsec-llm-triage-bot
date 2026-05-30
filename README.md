# CloudSec LLM Triage Bot

CloudSec LLM Triage Bot es un MVP serverless para triage de findings de seguridad en AWS. Recibe findings de Amazon GuardDuty y Amazon Inspector por EventBridge, los normaliza, los analiza con un LLM configurable, aplica un policy engine determinístico y distribuye la decisión final a Slack y Confluence.

## Problema que resuelve

Los equipos SecOps suelen recibir findings ruidosos y heterogéneos. Este proyecto reduce el tiempo de triage sin delegar decisiones críticas a un LLM. El LLM recomienda; el policy engine decide. El resultado es un flujo más rápido, trazable y seguro.

## Arquitectura

El flujo objetivo es:

`GuardDuty / Inspector -> EventBridge -> Lambda -> Secrets Manager -> LLM -> Policy Engine -> Slack + Confluence -> CloudWatch Logs`

Consulta:

- `architecture.md`
- `docs/architecture.mmd`

## Stack

- AWS Lambda (Python 3.12)
- Amazon EventBridge
- AWS Secrets Manager
- Amazon GuardDuty
- Amazon Inspector
- OpenAI o Amazon Bedrock
- Slack Incoming Webhook
- Confluence REST API
- Terraform
- Pydantic
- Requests

## Integraciones

1. AWS Security Findings
   GuardDuty y Inspector emiten eventos reales.
2. Slack
   Se envía un resumen operativo con riesgo, decisión y enlace a Confluence.
3. Confluence
   Se crea una página con resumen ejecutivo, detalle técnico, análisis del LLM, decisión y raw finding.
4. LLM configurable
   OpenAI o Bedrock, con salida JSON estructurada y validación Pydantic.

## Requisitos previos

- AWS account con GuardDuty e Inspector habilitados.
- Acceso a Terraform 1.6+.
- Python 3.12 para empaquetar dependencias manualmente.
- Un secreto en AWS Secrets Manager con las credenciales de integración.
- Permisos para crear recursos de red dedicados: VPC, subnets, route tables, Internet Gateway, NAT Gateway, EIP y security groups.

## Variables requeridas

Variables de entorno de la Lambda:

- `ENVIRONMENT`
- `PROJECT_NAME`
- `LLM_PROVIDER`
- `SECRET_NAME`
- `CONFLUENCE_SPACE_KEY`
- `CONFLUENCE_PARENT_PAGE_ID` opcional
- `LOG_LEVEL`
- `OPENAI_MODEL`
- `OPENAI_BASE_URL`
- `BEDROCK_MODEL_ID`
- `SUPPRESSION_ALLOWLIST`

`AWS_REGION` no se define manualmente en Terraform porque AWS Lambda la inyecta automáticamente en runtime. Si ejecutas el código fuera de Lambda, puedes configurarla localmente.

Para modelos como `Claude Sonnet 4.6` en Amazon Bedrock, configura `BEDROCK_MODEL_ID` con un inference profile ID o ARN, no con el model ID base. En `ap-southeast-2`, una opción recomendada es `au.anthropic.claude-sonnet-4-6`.

Variables Terraform principales:

- `aws_region`
- `project_name`
- `environment`
- `vpc_cidr`
- `availability_zones`
- `public_subnet_cidrs`
- `private_subnet_cidrs`
- `llm_provider`
- `confluence_space_key`
- `lambda_package_path`

## Cómo configurar Secrets Manager

Terraform crea un secreto placeholder con esta estructura:

```json
{
  "openai_api_key": "",
  "slack_webhook_url": "",
  "confluence_base_url": "",
  "confluence_email": "",
  "confluence_api_token": ""
}
```

Después del `terraform apply`, carga los valores reales manualmente en AWS Secrets Manager para el secreto generado.

## Cómo desplegar con Terraform

Desde `cloudsec-llm-triage-bot/terraform`:

```bash
terraform init
terraform fmt -check
terraform validate
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

Usa `terraform/terraform.tfvars.example` como base para crear tu `terraform.tfvars` real.

## Empaquetado manual de la Lambda

Este repositorio no incluye scripts automáticos de build o deploy. Para preparar el ZIP de la Lambda, ejecuta manualmente desde la raíz del proyecto:

```bash
rm -rf package cloudsec-llm-triage-bot-lambda.zip
mkdir -p package
/opt/homebrew/bin/python3.12 -m pip install \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version 3.12 \
  --abi cp312 \
  --only-binary=:all: \
  --target package \
  -r requirements.txt
cp src/*.py package/
cd package
zip -r ../cloudsec-llm-triage-bot-lambda.zip .
cd ..
```

Luego define `lambda_package_path` apuntando a ese ZIP.

## Cómo probar con Lambda Test Events o samples

Usa cualquiera de los 5 eventos JSON de `samples/` como Lambda Test Event:

- `guardduty_high_credential_compromise.json`
- `inspector_critical_cve.json`
- `guardduty_low_port_probe_dev.json`
- `inspector_medium_dev.json`
- `guardduty_false_positive_sandbox.json`

Al ejecutar revisa:

- `llm_analysis`
- `policy_decision`
- `ingestion_metadata`
- `confluence_page_url`
- `slack_notification_sent`
- `errors`

## Cómo validar con findings reales de AWS

Si quieres validar el flujo con eventos auténticos y no solo con samples, usa esta ruta:

1. Genera o espera un finding real en Inspector o GuardDuty.
2. Confirma que el evento llegue por EventBridge a la Lambda.
3. Revisa en la respuesta registrada por la Lambda o en Confluence estos campos:
   - `ingestion_metadata.source`
   - `ingestion_metadata.detail_type`
   - `ingestion_metadata.event_shape`
   - `ingestion_metadata.event_id`
4. Valida que el finding normalizado coincida con la consola de AWS.

Valores esperados:

- GuardDuty real por EventBridge:
  - `source = aws.guardduty`
  - `detail_type = GuardDuty Finding`
  - `event_shape = eventbridge_guardduty_finding`
- Inspector real por EventBridge:
  - `source = aws.inspector2`
  - `detail_type = Inspector2 Finding`
  - `event_shape = eventbridge_inspector_finding`

Guía detallada en `docs/real-validation.md`.

## Cómo correr las pruebas

Desde la raíz del proyecto:

```bash
python -m pytest
```

## Cómo preparar la demo de 5–7 minutos

1. Mostrar el problema y el diagrama.
2. Ejecutar el sample high `guardduty_high_credential_compromise.json`.
3. Mostrar que el policy engine bloquea cualquier supresión.
4. Ejecutar el sample `guardduty_false_positive_sandbox.json`.
5. Mostrar que, incluso en un caso de bajo riesgo aparente, la decisión final sigue siendo conservadora si la confianza es baja o el finding implica exposición pública.
6. Enseñar Slack, Confluence y `docs/rubric-mapping.md`.

Guion detallado en `docs/demo-script.md`.

## Limitaciones

- El proyecto no ejecuta supresión real de findings.
- Para OpenAI, Slack y Confluence la salida a Internet depende del NAT Gateway único; es una decisión consciente de ahorro de costos, no de alta disponibilidad.
- El adaptador Bedrock está optimizado para el formato de modelos Anthropic vía Bedrock Runtime.
- La evaluación LLM depende de credenciales reales y de ejecutar los samples en AWS.
- La allowlist inicial incluye `Recon:EC2/PortProbeUnprotectedPort`, pero en pruebas reales ese hallazgo puede seguir siendo bloqueado si el LLM lo clasifica como exposición pública o eleva el riesgo por contexto.

## Networking incluido

Terraform ahora crea una red dedicada para el proyecto:

- 1 VPC exclusiva
- 3 subnets públicas
- 3 subnets privadas
- 1 Internet Gateway
- 1 NAT Gateway compartido por todas las subnets privadas
- 1 route table pública
- 1 route table privada
- 1 security group restrictivo para la Lambda

Reglas de seguridad de la Lambda:

- Sin inbound rules
- Egress HTTPS `443/tcp` a Internet para AWS APIs, Slack, Confluence y OpenAI
- Egress DNS `53/udp` y `53/tcp` dentro del CIDR de la VPC para resolver nombres

## Trabajo futuro

- Agregar persistencia histórica en DynamoDB para auditoría y métricas.
- Integrar Jira o ServiceNow para seguimiento de remediación.
- Añadir VPC endpoints privados si la arquitectura corporativa lo permite.
- Incorporar scoring adicional con contexto CMDB o asset inventory.
- Crear un pipeline de evaluación continua para prompts y decisiones.
- Añadir actualización idempotente en Confluence: detectar páginas existentes y actualizarlas en vez de crear una nueva página con sufijo único.
- Refinar la allowlist y el orden de reglas del policy engine para alinear mejor los casos de `candidate_for_suppression` con findings realmente suprimibles.

## Repositorio listo para GitHub

El repositorio de entrega excluye artefactos locales y sensibles:

- no incluye `terraform.tfstate` ni `terraform.tfvars`
- no incluye `package/` ni ZIPs generados manualmente
- no incluye `.venv/` ni caches locales

Antes de desplegar:

1. Copia `terraform/terraform.tfvars.example` a `terraform/terraform.tfvars`.
2. Genera de nuevo `cloudsec-llm-triage-bot-lambda.zip`.
3. Ejecuta `terraform init`, `terraform validate`, `terraform plan` y `terraform apply`.

## Cómo cumple cada punto de la rúbrica

1. Usa al menos 1 LLM.
   Soporta OpenAI o Bedrock y valida su salida en JSON.
2. Integra al menos 2 servicios externos reales.
   Integra AWS findings, Slack y Confluence, además del proveedor LLM.
3. Caso funcional de punta a punta.
   Desde el finding hasta Slack y Confluence con decisión final.
4. Repositorio con README.
   Este archivo documenta instalación, uso, pruebas y demo.
5. Diagrama de arquitectura.
   Incluido en `docs/architecture.mmd` y explicado en `architecture.md`.
6. Demo de 5–7 minutos.
   Documentada en `docs/demo-script.md`.
7. Evaluación de calidad del LLM.
   Cubierta con 5 casos de muestra y `docs/evaluation.md`.
8. Documentación clara y reproducible.
   README, arquitectura, evaluación y mapping de rúbrica incluidos.

## Estructura del repositorio

```text
cloudsec-llm-triage-bot/
├── README.md
├── requirements.txt
├── .env.example
├── architecture.md
├── src/
├── samples/
├── tests/
├── docs/
└── terraform/
```
