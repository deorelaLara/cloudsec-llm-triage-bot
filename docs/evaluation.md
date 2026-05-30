# CloudSec LLM Triage Bot Evaluation

Esta evaluación usa 5 findings representativos para demostrar calidad del flujo LLM + policy engine. Cada caso se puede ejecutar como Lambda Test Event cargando el JSON correspondiente desde `samples/`.

| Caso | Servicio | Severidad | Resultado esperado | Resultado observado | Criterio de aceptación |
| --- | --- | --- | --- | --- | --- |
| `guardduty_high_credential_compromise.json` | GuardDuty | High | `alert_and_document` | `alert_and_document` con `confidence=0.82`, Slack y Confluence exitosos. | Nunca aparece como `candidate_for_suppression`. |
| `inspector_critical_cve.json` | Inspector | Critical | `alert_and_document` | Debe mantenerse en alerta/documentación por criticidad y ambiente production. | Nunca aparece como `candidate_for_suppression`. |
| `guardduty_low_port_probe_dev.json` | GuardDuty | Low | `candidate_for_suppression` si el LLM devuelve alta confianza | `alert_and_document` con `final_risk_level=medium` y `reason_codes=["dangerous_finding_type_blocked"]`; Slack y Confluence exitosos. | El caso demuestra que el LLM puede elevar el riesgo y que la política bloquea findings tratados como `public exposure`. |
| `inspector_medium_dev.json` | Inspector | Medium | `manual_review` | `manual_review` con `confidence=0.62`; Slack exitoso. | No puede pasar a `candidate_for_suppression`. |
| `guardduty_false_positive_sandbox.json` | GuardDuty | Low | `candidate_for_suppression` con confianza alta | `alert_and_document` en una re-ejecución real, con `reason_codes=["dangerous_finding_type_blocked"]`, Slack exitoso y Confluence exitoso con retry de título único. | La decisión final debe seguir indicando revisión/aprobación humana o alerta, nunca supresión automática real. |

## Cómo ejecutar la evaluación manual

1. Despliega la Lambda y carga los secretos requeridos.
2. En la consola de AWS Lambda, crea un Test Event pegando uno de los archivos de `samples/`.
3. Ejecuta la función y revisa:
   - `policy_decision.decision`
   - `policy_decision.reason_codes`
   - `llm_analysis.confidence`
   - `confluence_page_url`
   - `slack_notification_sent`
4. Registra el resultado observado en esta tabla para la defensa o demo académica.

## Hallazgos de diseño observados

- El caso `guardduty_low_port_probe_dev.json` mostró que incluir `Recon:EC2/PortProbeUnprotectedPort` en la allowlist no garantiza un resultado `candidate_for_suppression`. Si el LLM interpreta el hallazgo como exposición pública o eleva el riesgo a `medium`, el policy engine lo bloqueará correctamente.
- Los casos repetidos pueden provocar `400 Bad Request` en Confluence por títulos duplicados. La implementación actual ya mitiga esto reintentando con un título único para mantener el flujo end-to-end.
- Con la política actual, el sistema es conservador por diseño: ante confianza < `0.80` o señales de exposición pública, el resultado cae en `manual_review` o `alert_and_document`.
