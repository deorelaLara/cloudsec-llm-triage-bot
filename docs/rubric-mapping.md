# Rubric Mapping

## 1. Caso de uso y funcionalidad

El proyecto resuelve un caso de uso claro y completo: recibir findings de Amazon GuardDuty y Amazon Inspector, analizarlos, aplicar reglas de seguridad y distribuir el resultado a Slack y Confluence. El flujo está diseñado de punta a punta y listo para demostrarse con Lambda Test Events usando los archivos de `samples/`.

## 2. Uso del LLM

El LLM no se usa de forma trivial. Produce un análisis estructurado en JSON con:

- resumen ejecutivo
- nivel de riesgo
- confianza
- justificación
- indicadores
- acción recomendada
- recomendación inicial sobre si el finding podría ser candidato a excepción

La salida se valida con Pydantic en `src/models.py`, y `src/llm_analyzer.py` implementa fallback seguro cuando el JSON del LLM es inválido o falla la llamada.

## 3. Integraciones

El proyecto integra más de dos servicios externos reales:

- AWS GuardDuty
- AWS Inspector
- AWS EventBridge
- AWS Lambda
- AWS Secrets Manager
- Slack Incoming Webhook
- Confluence REST API
- OpenAI o Amazon Bedrock

No son dos endpoints del mismo servicio; son integraciones distintas con responsabilidades separadas.

## 4. Arquitectura y decisiones

La arquitectura está documentada en:

- `architecture.md`
- `docs/architecture.mmd`
- `terraform/`

También se explican decisiones y trade-offs:

- Lambda privada en subnets existentes
- sin endpoints públicos
- secretos fuera del código
- IAM least privilege
- el LLM recomienda, pero el policy engine decide

## 5. Evaluación / calidad del LLM

Se incluyen 5 casos de evaluación en `samples/` y una guía de evaluación en `docs/evaluation.md`. Además, las pruebas unitarias validan:

- normalización de findings
- contrato de modelos Pydantic
- reglas determinísticas del policy engine

Esto permite demostrar tanto comportamiento esperado como controles de calidad alrededor del output del LLM. La documentación de evaluación ya incorpora resultados reales observados en AWS, incluyendo casos donde el LLM eleva el riesgo, casos donde la confianza baja fuerza `manual_review`, y hallazgos de diseño como títulos duplicados en Confluence o conflictos entre allowlist y reglas de bloqueo.

## 6. Presentación, demo y documentación

La documentación principal está en:

- `README.md`
- `architecture.md`
- `docs/demo-script.md`
- `docs/evaluation.md`
- `docs/rubric-mapping.md`
- `docs/real-validation.md`

El README explica requisitos, despliegue con Terraform, configuración de secretos, uso de samples, validación con findings reales, demo de 5–7 minutos, limitaciones, trabajo futuro y cumplimiento explícito de la rúbrica.
