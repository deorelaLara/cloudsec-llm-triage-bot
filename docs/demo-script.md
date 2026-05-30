# Demo Script (5–7 minutos)

## Minuto 0–1: Problema

- Explicar que los findings de GuardDuty e Inspector suelen llegar sin suficiente contexto operativo.
- Mostrar que el objetivo es acelerar triage sin permitir que un LLM suprima findings por sí solo.

## Minuto 1–2: Arquitectura

- Enseñar `docs/architecture.mmd` o el diagrama renderizado.
- Recorrer el flujo: EventBridge -> Lambda -> Secrets Manager -> LLM -> Policy Engine -> Slack -> Confluence -> CloudWatch.

## Minuto 2–4: Demo con finding high

- Abrir el sample `samples/guardduty_high_credential_compromise.json`.
- Ejecutarlo como Lambda Test Event.
- Mostrar en el resultado:
  - `policy_decision.decision = alert_and_document`
  - `reason_codes` que bloquean supresión
  - página de Confluence generada
  - mensaje enviado a Slack

## Minuto 4–5: Demo con false positive sandbox

- Abrir `samples/guardduty_false_positive_sandbox.json`.
- Ejecutarlo como Lambda Test Event.
- Mostrar cómo el LLM puede clasificar el caso como bajo riesgo, pero la salida final sigue siendo conservadora si la confianza es insuficiente o si el finding termina bloqueado por política.

## Minuto 5–6: Explicación del policy engine

- Enseñar `src/policy_engine.py`.
- Resaltar reglas:
  - no high/critical
  - no production
  - no malware / credential compromise / privilege escalation / public exposure / active exploitation
  - no baja confianza
  - solo allowlist + dev/sandbox + low risk

## Minuto 6–7: Cierre y cumplimiento de rúbrica

- Recordar integraciones reales: AWS Security Findings, Slack, Confluence y LLM provider.
- Mostrar `docs/rubric-mapping.md`.
- Cerrar con el mensaje clave: el LLM acelera triage, pero la autoridad final sigue siendo determinística y segura.
