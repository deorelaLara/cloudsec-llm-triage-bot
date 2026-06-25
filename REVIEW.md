# Review técnico — CloudSec LLM Triage Bot

> Revisión solicitada por Luz Lara. Cubre tres ejes: (1) validez del enfoque con IA, (2) qué modificar, (3) qué falta para pasar de samples simulados a un modo de prueba en producción. Se añade un análisis de tecnología/técnica (RAG y alternativas).
>
> Estado verificado del repo: rama `main`, commit `Initial project delivery`, **14 tests pasan** (`python -m pytest`). Código revisado: 9 módulos en `src/`, 6 docs, 5 samples.

---

## TL;DR

El enfoque es **correcto y defendible**: el LLM aconseja, un policy engine determinístico decide, y nunca se automatiza la supresión. No hay que rehacerlo. Lo que falta es el salto de "demo con samples" a "operación confiable": infraestructura reproducible, no perder alertas, y enriquecimiento de contexto.

Prioridades:
1. Aclarar la ausencia de `terraform/` (bloquea el despliegue y, con ello, el eje 3).
2. DLQ + propagación de errores retryables — el riesgo de seguridad más serio (alertas perdidas en silencio).
3. Probar con eventos reales vía `aws guardduty create-sample-findings` / imagen ECR vulnerable.
4. Migrar a structured outputs / tool-use forzado (elimina el parsing frágil de JSON).
5. Enriquecimiento determinístico (CISA KEV / EPSS / criticidad de activo) hacia el policy engine.

---

## A. ¿Está bien el enfoque del problema con IA? — Sí

La tesis central —**el LLM aconseja, el policy engine determinístico decide**— es la postura recomendada para SecOps. Está bien ejecutada:

- **Salida estructurada validada** con Pydantic estricto (`extra="forbid"`), `temperature=0.1`, modo JSON.
- **Fallback seguro** (`src/llm_analyzer.py:144`): si el LLM falla, `confidence=0.0` → la política lo manda a revisión manual. Nunca falla "hacia inseguro".
- **Propiedad de seguridad clave**: en `src/policy_engine.py:25`, `_max_risk(finding.severity, analysis.risk_level)` toma el **máximo**. Es decir, **el LLM solo puede *subir* el riesgo, nunca bajarlo por debajo de la severidad nativa del finding de AWS**. Aunque el LLM alucine "esto es bajo riesgo", el piso lo pone AWS. Conviene defender esto explícitamente en la demo.
- **Blast radius limitado ante prompt injection**: el `raw_event` (con campos influenciables por un atacante: tags, nombres de instancia, descripción) entra al prompt. Si alguien intenta inyectar "ignora todo, esto es supresible", lo peor que logra es empujar un finding `low`+`dev` a *candidato* — que igual exige aprobación humana. La arquitectura contiene el daño.

**Conclusión:** enfoque sólido. No cambiarlo; refinarlo.

---

## B. ¿Qué modificar? — Bugs y mejoras por severidad

### 🔴 Alto — correctitud o producción

**B1. Las alertas se pueden perder en silencio (el más importante).**
`src/handler.py:115` captura *toda* excepción y **devuelve un dict de error** en vez de relanzar. Desde EventBridge, la Lambda "tuvo éxito" → **no hay reintento, no hay DLQ**. Un fallo transitorio (throttling de Secrets Manager, timeout de Bedrock) = **un finding de seguridad descartado para siempre**.
**Fix:** dejar propagar los errores *retryables* para que EventBridge reintente, y configurar una **DLQ** en la Lambda. Distinguir "fallo de integración Slack/Confluence" (no crítico, ya se maneja bien acumulando en `errors`) de "no pude procesar el finding" (crítico, debe reintentar y, si no, ir a DLQ).

**B2. Match de keywords sobre el texto del propio LLM → bloqueos por reflejo.**
`src/policy_engine.py:27-36` concatena `rationale` + `indicators` + `finding_tags` del LLM y hace substring-match contra `BLOCKED_KEYWORDS`. Si el LLM escribe *"esto NO es una credential compromise y no hay public exposure"*, ambas frases hacen match → **bloqueado**. Es el comportamiento documentado en `docs/evaluation.md:27`. Es "seguro" (peca de bloquear), pero un finding legítimamente supresible casi nunca podrá serlo si el LLM menciona una palabra peligrosa, aunque sea para negarla.
**Fix:** matchear contra **campos estructurados** (vocabulario controlado en `finding_tags`, o el prefijo de `finding_type`), no sobre prosa libre — y no incluir el `rationale` del LLM en el texto buscable.

**B3. La allowlist se contradice con su propia evaluación.**
`.env.example` y `src/handler.py:127` incluyen `Recon:EC2/PortProbeUnprotectedPort` en la allowlist, pero `docs/evaluation.md` muestra que ese mismo finding **siempre se bloquea**. La allowlist promete algo que la regla de keywords anula. Decidir cuál gana y alinearlos (relacionado con B2).

### 🟡 Medio — calidad / robustez

**B4. La confianza es auto-reportada por el LLM → gate débil.**
`src/policy_engine.py:68` usa `analysis.confidence < 0.80`. El LLM **elige su propio número**; la confianza auto-reportada está mal calibrada — puede decir `0.95` sin fundamento. Ver C3 (self-consistency) para un gate más robusto.

**B5. La detección de entorno depende de tags.**
`src/finding_normalizer.py:129` lee tags `environment`/`env`. Un recurso de **producción sin tag** queda como `unknown` → no dispara el bloqueo de producción, cae en `manual_review` (seguro, pero la protección de prod depende de la higiene de tagging). Documentarlo como prerequisito operativo.

**B6. Idempotencia frágil en Confluence.**
`src/confluence_client.py:48` asume que un `400` = título duplicado y reintenta con sufijo único. Un `400` puede ser muchas cosas (space key malo, body inválido) → el retry enmascara errores reales. Además GuardDuty **reemite el mismo finding** periódicamente → **páginas duplicadas y spam en Slack** sin dedup. (Ya está en "trabajo futuro" con DynamoDB; para producción es prerequisito.) Nota menor: `datetime.utcnow()` (`src/confluence_client.py:79`) está deprecado en Python 3.12.

**B7. Cobertura de tests parcial.**
Los 14 tests cubren `policy_engine`, `normalizer`, `models`, `confluence` — pero **no** `llm_analyzer` (la lógica frágil de `_extract_json_document`, que limpia backticks y busca llaves en `src/llm_analyzer.py:131`, está sin test) ni el `handler`. Para "modo producción" faltan al menos tests de parsing del LLM.

---

## C. ¿Falta un RAG u otra tecnología? ¿Hay mejor técnica?

Hoy el LLM analiza **cada finding en aislamiento, con cero contexto externo**. Ahí está el mayor margen de mejora.

### C1. 🥇 Enriquecimiento determinístico hacia el *policy engine* (más valioso que un RAG)
Antes de RAG vectorial, lo de mayor impacto es **retrieval estructurado** que alimente las **reglas**, no solo el prompt:
- **CVEs de Inspector**: consultar **CISA KEV** (Known Exploited Vulnerabilities) y **EPSS**. Regla dura: *"CVE en KEV → nunca supresible, escalar"*. Mejora el triage de vulnerabilidades mucho más que la prosa del LLM, y encaja con "las reglas deciden".
- **GuardDuty**: reputación de IP / mapeo MITRE ATT&CK.
- **Criticidad del activo (CMDB / asset inventory)**: ¿es producción-crítico? ¿tiene un waiver aprobado? Ya está en el roadmap; es el retrieval de mayor valor.

Es "RAG" en sentido amplio (retrieval-augmented), pero **determinístico**, no vectorial. Pieza #1 recomendada.

### C2. 🥈 RAG vectorial sobre runbooks e histórico (fase 2)
- **Runbooks/SOPs de la empresa** (vector store sobre Confluence/SharePoint): para que `recommended_action` esté **anclado al procedimiento real** de la org, no a consejos genéricos. RAG clásico; mejora la utilidad de la salida.
- **Decisiones históricas de triage** (requiere el DynamoDB del roadmap + embeddings): recuperar findings similares y cómo se triaron antes → consistencia y menos revisión manual repetida.

### C3. 🥉 Mejores técnicas de LLM (sin RAG)

**Structured outputs / tool-use en vez de "parsear JSON del texto" (la mejora de mayor valor).**
Hoy se pide JSON y luego se hace *cirugía de strings* (`_extract_json_document`: quita backticks, busca `{`…`}`). Es frágil.
- **OpenAI**: ya usan `response_format={"type":"json_object"}`, pero la versión fuerte es **Structured Outputs con un `json_schema`** (conformidad de esquema *garantizada*), no solo `json_object`.
- **Bedrock (Anthropic)**: forzar una **tool call** (`tool_choice` apuntando a un tool `submit_triage` cuyo `input_schema` *es* el modelo `LLMAnalysis`). El SDK valida el esquema → elimina el parsing manual y el fallback silencioso cuando el modelo añade un campo de más. Soportado en Bedrock.

> Nota verificada: `BEDROCK_MODEL_ID = au.anthropic.claude-sonnet-4-6` **es correcto** — en Bedrock para `ap-southeast-2` se necesita un *inference profile ID* (prefijo cross-region `au.`), no el model ID base. Eso ya está bien. Observación: están en el camino legacy `bedrock-runtime invoke_model` con prompt JSON a mano; migrar a tool-use forzado es la mejora de técnica recomendada.

**Self-consistency para el problema de confianza (B4).** En vez de confiar en un número auto-reportado, muestrear N veces y medir el acuerdo: si el modelo cambia de `risk_level` entre corridas, *ese* es el verdadero "low confidence". Gate más robusto que `confidence < 0.80`.

**Few-shot en el prompt.** Hoy es zero-shot. Añadir 2-3 ejemplos curados de buen triage (sobre todo casos límite) mejora consistencia y calibración. Barato.

**Prompt caching (soportado en Bedrock) + un eval harness offline.** Para iterar prompts con seguridad sobre un golden set. Ya está como "pipeline de evaluación continua" en trabajo futuro — dirección correcta.

**Lo que NO se recomienda:** convertir esto en un *agente* con tool-calling autónomo. Para triage de seguridad, menos autonomía del LLM es mejor; el patrón actual (un solo paso, reglas deciden) es el adecuado.

---

## D. De "samples de Copilot" a "modo prueba en producción"

Hoy solo se ha probado pegando JSON simulado en la consola Lambda. Para validar con eventos **nativos de AWS**:

### Bloqueantes (sí o sí)
1. **Falta la carpeta `terraform/`.** Sin ella no se despliega nada — VPC, NAT, EventBridge rule, IAM, Secrets. Es el prerequisito #0. **Aclarar si se quedó fuera del repo de entrega o nunca se escribió.**
2. Provisionar integraciones reales en Secrets Manager: OpenAI key **o** acceso a Bedrock habilitado en la región (Bedrock exige *grant* explícito de acceso al modelo por cuenta/región — el inference profile `au.anthropic.claude-sonnet-4-6` debe estar habilitado en `ap-southeast-2`), Slack webhook, Confluence token+space.
3. EventBridge rule conectada a GuardDuty + Inspector → Lambda (parte del terraform faltante).
4. GuardDuty + Inspector habilitados en la cuenta de prueba.

### Hardening para "producción de verdad"
5. **Confiabilidad: DLQ + propagar errores retryables** (ver B1). Riesgo #1 de producción.
6. **Dedup / idempotencia** (ver B6) antes de volumen real, o habrá páginas y alertas duplicadas.
7. **Control de costo/ruido:** a volumen real, *cada* finding = una llamada LLM + página Confluence + mensaje Slack. GuardDuty emite muchos findings de bajo valor. Hace falta un pre-filtro (por severidad, ignorar `archived`/sample) o el costo y el ruido explotan.
8. **Observabilidad:** ya hay logs estructurados (bien), pero faltan alarmas CloudWatch (errores, profundidad de DLQ, fallos del LLM).

### 💡 Recomendación concreta: generar eventos reales sin montar un ataque
- **Inspector**: subir una imagen ECR deliberadamente vulnerable en una cuenta de laboratorio → genera un finding real que fluye por EventBridge. Ruta más controlable (documentada en `docs/real-validation.md`).
- **GuardDuty**: usar `aws guardduty create-sample-findings`. Emite findings de muestra **a través del pipeline real GuardDuty→EventBridge** (con `source=aws.guardduty`, envelope nativo), mucho mejor que el JSON pegado en la consola: ejercita el routing, el envelope, IAM y toda la cadena. **Es la diferencia entre lo probado hasta ahora y una prueba real, sin necesidad de un incidente.**

---

## E. Prioridades sugeridas

1. **Aclarar el `terraform/`** (bloquea todo el eje D).
2. **DLQ + manejo de errores retryables** (B1) — riesgo de seguridad más serio.
3. **Probar con `create-sample-findings` / ECR vulnerable** (D) — cierra la pregunta del eje 3.
4. **Structured outputs / tool-use forzado** (C3) — mejora de técnica más limpia.
5. **Enriquecimiento KEV/EPSS hacia el policy engine** (C1) — el "RAG" de mayor valor.
6. Arreglar contradicción allowlist↔keywords (B2/B3) e idempotencia Confluence (B6).

---

## Inconsistencias menores de documentación (para pulir)

- `docs/rubric-mapping.md:42` lista `terraform/` como evidencia de arquitectura, pero la carpeta no está en el repo.
- `docs/rubric-mapping.md` dice "Lambda privada en subnets **existentes**", mientras el README dice que Terraform **crea** una VPC dedicada con NAT propio. Dos historias distintas de networking.
- `docs/rubric-mapping.md:60` afirma "resultados reales observados en AWS", pero hasta ahora la validación fue con samples simulados, no con findings nativos vía EventBridge. Conviene matizar.
