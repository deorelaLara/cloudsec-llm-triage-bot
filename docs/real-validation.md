# Validacion con Findings Reales

Esta guia complementa los `samples/` y sirve para validar que la regla de EventBridge, la Lambda y la normalizacion estan funcionando con eventos autenticos de AWS.

## Objetivo

Confirmar tres cosas:

1. AWS emite el evento esperado.
2. EventBridge lo enruta a la Lambda correcta.
3. La Lambda detecta y normaliza el finding como `guardduty` o `inspector` usando el sobre real del evento.

## Evidencia que debes revisar

En CloudWatch Logs de la Lambda:

- `event_source`
- `detail_type`
- `event_shape`
- `event_id`
- `finding_id`
- `finding_source`

En la respuesta del procesamiento y en Confluence:

- `ingestion_metadata.source`
- `ingestion_metadata.detail_type`
- `ingestion_metadata.event_shape`
- `ingestion_metadata.event_id`

## Inspector: prueba real recomendada

La validacion real mas controlable suele ser Amazon Inspector.

Opciones practicas:

1. ECR con una imagen deliberadamente desactualizada en una cuenta de laboratorio.
2. EC2 de laboratorio con paquetes viejos y escaneo habilitado por Inspector.

Flujo esperado:

1. Inspector detecta la vulnerabilidad.
2. Se genera un evento `Inspector2 Finding`.
3. EventBridge ejecuta la Lambda.
4. La Lambda registra:
   - `source = aws.inspector2`
   - `detail_type = Inspector2 Finding`
   - `event_shape = eventbridge_inspector_finding`

Comandos utiles:

```bash
aws inspector2 list-findings \
  --region ap-southeast-2 \
  --max-results 10
```

```bash
aws logs tail /aws/lambda/cloudsec-llm-triage-bot-dev-processor \
  --region ap-southeast-2 \
  --since 15m \
  --follow
```

## GuardDuty: prueba real recomendada

GuardDuty es mas delicado. Un finding realmente "real" implica actividad sospechosa autentica o al menos un escenario de laboratorio que la produzca. No conviene intentar esto en cuentas compartidas o productivas.

La mejor ruta es:

1. Usar una cuenta de laboratorio aislada.
2. Esperar un finding real ya existente o generar una actividad controlada y aprobada por tu equipo de seguridad.
3. Confirmar que EventBridge dispare la Lambda.

Flujo esperado:

1. GuardDuty genera el finding.
2. Se emite un evento `GuardDuty Finding`.
3. EventBridge ejecuta la Lambda.
4. La Lambda registra:
   - `source = aws.guardduty`
   - `detail_type = GuardDuty Finding`
   - `event_shape = eventbridge_guardduty_finding`

Comandos utiles:

```bash
aws guardduty list-detectors \
  --region ap-southeast-2
```

```bash
aws guardduty list-findings \
  --region ap-southeast-2 \
  --detector-id <DETECTOR_ID> \
  --finding-criteria '{"Criterion":{"service.archived":{"Eq":["false"]}}}'
```

```bash
aws logs tail /aws/lambda/cloudsec-llm-triage-bot-dev-processor \
  --region ap-southeast-2 \
  --since 15m \
  --follow
```

## Como validar que el evento fue autentico

La Lambda ahora distingue el tipo de sobre recibido:

- `eventbridge_guardduty_finding`
- `eventbridge_inspector_finding`
- `direct_guardduty_payload`
- `direct_inspector_payload`

Para una validacion autentica de EventBridge, busca especificamente:

- `has_eventbridge_envelope = true`
- `event_shape = eventbridge_guardduty_finding` o `eventbridge_inspector_finding`

Eso prueba que la Lambda no solo proceso un JSON compatible, sino que recibio el sobre nativo de EventBridge con `id`, `source`, `detail-type`, `account`, `region`, `time` y `detail`.

## Criterio de aceptacion

Da por valida una prueba real cuando se cumplan todos estos puntos:

1. El finding existe en la consola de GuardDuty o Inspector.
2. La regla de EventBridge registra invocacion hacia la Lambda.
3. CloudWatch Logs muestra el `event_shape` correcto.
4. El finding normalizado coincide con el finding original en:
   - `finding_id`
   - `source`
   - `severity`
   - `resource_id`
   - `resource_type`
5. Slack recibe la notificacion.
6. Confluence crea la pagina y registra el metadata del evento.

## Notas operativas

- Un evento reenviado manualmente desde un sample puede ser compatible con el esquema de EventBridge, pero no demuestra por si mismo que el finding se genero de forma nativa en el servicio.
- Si necesitas evidencia fuerte para auditoria o demo, usa screenshots de:
  - finding en la consola de AWS
  - logs de Lambda con `event_shape`
  - mensaje de Slack
  - pagina de Confluence
