# CloudSec LLM Triage Bot Architecture

## Descripción de componentes

- `VPC dedicada` aísla por completo los recursos del proyecto.
- `3 subnets públicas` alojan el Internet Gateway path y el NAT Gateway compartido.
- `3 subnets privadas` alojan la Lambda y cualquier expansión privada futura.
- `GuardDuty` y `Inspector` generan findings reales de seguridad.
- `EventBridge` recibe ambos tipos de eventos y los enruta a una sola Lambda.
- `AWS Lambda` ejecuta el flujo de normalización, análisis LLM, policy engine, documentación y notificación.
- `Secrets Manager` guarda credenciales para OpenAI, Slack y Confluence.
- `LLM Provider` es configurable entre OpenAI y Amazon Bedrock.
- `Policy Engine` decide de forma determinística si el finding debe alertarse, revisarse manualmente o quedar como `candidate_for_suppression`.
- `Slack` recibe una notificación operativa resumida.
- `Confluence` recibe una página con trazabilidad completa del análisis.
- `CloudWatch Logs` conserva auditoría y errores operativos.

## Flujo end-to-end

1. GuardDuty o Inspector emite un finding.
2. EventBridge lo enruta hacia la Lambda `cloudsec-llm-triage-bot`.
3. La Lambda normaliza el payload a un contrato común.
4. La Lambda lee secretos desde Secrets Manager.
5. El LLM genera un análisis estructurado en JSON validado con Pydantic.
6. El policy engine aplica reglas determinísticas y bloquea decisiones inseguras.
7. Se crea una página en Confluence con el análisis y el raw finding.
8. Se envía un resumen a Slack con la decisión final y el link a Confluence.
9. Todo el proceso queda auditado en CloudWatch Logs.

## Justificación del stack

- `Python 3.12`: rápido para integrar AWS, SaaS APIs y validación estructurada.
- `AWS Lambda + EventBridge`: encaja con el requisito de arquitectura serverless y reduce superficie expuesta.
- `Pydantic`: obliga a que la salida del LLM sea JSON estructurado y validado.
- `OpenAI / Bedrock`: el proveedor del LLM queda desacoplado por configuración.
- `Slack + Confluence`: integraciones reales, separadas y fáciles de mostrar en una demo académica.
- `Terraform`: infraestructura declarativa, reproducible y alineada con buenas prácticas de AWS.

## Decisiones de seguridad

- La solución crea una VPC exclusiva del proyecto con 3 subnets públicas y 3 privadas para aislar el procesamiento de seguridad.
- La Lambda corre únicamente en subnets privadas y no recibe tráfico entrante.
- Un único NAT Gateway compartido entrega salida controlada desde las subnets privadas para reducir costo en este MVP.
- No se crea API Gateway ni Lambda Function URL pública.
- Los secretos viven en Secrets Manager; las variables de entorno solo contienen referencias y parámetros no sensibles.
- El rol IAM usa permisos mínimos: logs, lectura del secret exacto, ENIs para VPC y Bedrock solo si aplica.
- Se crea explícitamente el CloudWatch Log Group con retención configurable.
- El policy engine bloquea supresión automática para riesgos altos, producción y categorías peligrosas.

## Trade-offs

- Un solo procesador Lambda simplifica la demo, aunque separarlo por dominio podría aislar mejor fallas en un entorno enterprise.
- Soportar Bedrock mediante el formato de Anthropic simplifica el MVP; si se requieren otros modelos Bedrock, conviene agregar adaptadores por proveedor.
- El proyecto documenta y notifica, pero deja la supresión real fuera de alcance para evitar automatizaciones peligrosas.
- Un solo NAT Gateway reduce costo, pero también concentra la salida de las subnets privadas en un único punto de egress.

## Por qué el LLM no ejecuta supresión real

El LLM es útil para resumir, clasificar y recomendar, pero no debe tener autoridad para tomar acciones críticas sobre findings de seguridad. En este proyecto el LLM solo produce una recomendación estructurada. La decisión final la toma un policy engine determinístico que puede marcar `candidate_for_suppression`, pero nunca ejecuta supresión automática real. Esto reduce el riesgo de ocultar incidentes verdaderos por alucinaciones, baja confianza o contexto incompleto.
