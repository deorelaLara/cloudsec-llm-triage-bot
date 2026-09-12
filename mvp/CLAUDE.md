# MVP CloudSec Triage — contexto permanente

## Producto

MVP local de triage asistido por LLM para findings de Amazon GuardDuty y Amazon
Inspector. Entrega academica. Reutiliza la logica de dominio del sistema serverless
que vive en la raiz de este repositorio y anade dos capacidades que ese sistema
promete en su ficha de caso de uso pero todavia no implementa: contexto de recurso
e historial de patron.

Publico: un evaluador academico que abre la pagina, hace clic en un identificador de
finding y espera ver una decision de triage con su razon.

## Alcance

- Todo el MVP vive en `mvp/`. Nada fuera de esa carpeta se modifica.
- Corre en local. No se despliega: ni Lambda, ni API Gateway, ni Vercel, ni Docker.
- Sin autenticacion, sin bases remotas, sin colas, sin microservicios, sin frameworks
  de frontend.
- Sin dependencias fuera de `mvp/requirements.txt`.

## Arquitectura

```
navegador (index.html + static/)
    |  POST /api/chat  {"pregunta": "..."}
    v
api/chat.py (FastAPI, puerto 8000)
    v
agent.py  -- create_agent (LangChain 1.x) + MultiServerMCPClient por HTTP
    |  descubre tools contra MCP_URL, no importa la funcion directamente
    v
api/mcp.py (FastMCP, puerto 8001)  ->  mcp_server.py  ->  UNA tool: triagear_finding
    v
core/triage.py  triagear(evento) -> CasoTriage
    1. normalize_finding_event   T1  (copiado)
    2. consultar_contexto_recurso T2 (nuevo, SQLite solo lectura)
    3. consultar_historial_patron T3 (nuevo, SQLite solo lectura)
    4. enriquecimiento local KEV/EPSS T4 (nuevo, lee SQLite en vez de internet)
    5. LLMAnalyzer.analyze       T5  (copiado) UNICA llamada de clasificacion
    6. evaluate_policy(..., context=, history=)  (copiado + 2 reglas)
    7. registrar en decision_triage T6  (unico punto de escritura)
```

Dos capas llaman al modelo: el analizador de triage y el agente conversacional.
Ambas obtienen su cliente de `llm_factory.py`, asi que **siempre** usan el mismo
proveedor. Si el analizador fuera por Bedrock y el agente por OpenAI, el finding
completo saldria igual de AWS hacia un tercero y el argumento de privacidad se caeria.

## Reglas de desarrollo

- **No modificar nada fuera de `mvp/`.** Unica excepcion ya acordada: `.gitignore`
  de la raiz, que ignora `mvp/.env` y `mvp/data/mvp_triage.db`.
- **`mvp/core/` es una copia deliberada**, no un import a `../src`. El hash del commit
  de origen esta en `mvp/README.md`. La divergencia debe quedar rastreable.
- Los modulos copiados conservan su logica. La unica modificacion permitida es
  `policy_engine.evaluate_policy()`, que gana dos parametros opcionales al final.
- Los tests copiados de `tests/` deben pasar **sin modificarlos**. Si uno falla, se
  rompio algo.
- Imports planos dentro de `core/` (`from models import ...`), como en el repo de
  origen. `core/__init__.py` inserta `mvp/core` y `mvp/` en `sys.path`.
- `mvp/src` -> `core/` y `mvp/samples` -> `data/samples/` son symlinks que existen
  solo para que los tests copiados resuelvan sus rutas sin tocarlos.
- El modelo nunca ve SQL. Todas las consultas son parametrizadas y se abren en modo
  solo lectura (`file:...?mode=ro`), salvo la escritura en `decision_triage`.
- Ninguna clave ni credencial en codigo, README, logs ni commits.
- Nada de `AgentExecutor`, `initialize_agent` ni `create_react_agent`. Solo
  `create_agent`.
- Una sola tool MCP. No se anaden mas.

## Lo que NO se copia del sistema serverless

`handler.py`, `slack_notifier.py`, `confluence_client.py`, `dedup.py`, `secrets.py`
y todo `terraform/`. El MVP no publica en Slack, no escribe en Confluence, no
deduplica en DynamoDB y no se despliega.

## Reglas de politica anadidas

Se insertan en `evaluate_policy()` **despues** de la puerta de
`production_environment_blocked` y **antes** de la puerta de confianza:

1. `history.variacion_detectada` -> `manual_review`, reason code
   `pattern_variation_detected`.
2. `not context.encontrado` -> `manual_review`, reason code
   `resource_context_not_found`.

Con `context=None` y `history=None` el comportamiento es identico al original.
El umbral de confianza sigue en 0.80. La puerta de CISA KEV y el orden de las reglas
existentes no se tocan.

## Criterios de aceptacion

| # | Caso | Esperado |
|---|------|----------|
| a | Compromiso de credenciales | `alert_and_document`, `candidate_for_suppression = False` |
| b | Recurso no inventariado | `manual_review` con `resource_context_not_found` |
| c | Fuera de alcance | `out_of_scope`, cero llamadas al modelo, ninguna fila en `decision_triage` |
| d | Tool invalida | `finding_id` vacio e inexistente -> `{"ok": False, "error": ...}` |
| e | MCP caido | `POST /api/chat` devuelve error JSON legible, sin traza cruda ni secretos |
| f | Variacion de patron | `manual_review` con `pattern_variation_detected` |

Ademas:

- Verificacion estatica: `ast.parse` sobre todo `mvp/**/*.py`, todos los modulos
  importan, `pytest mvp/tests/` en verde incluyendo los copiados sin modificar.
- Arranque: `uvicorn api.mcp:app --port 8001` responde; `uvicorn api.chat:app --port
  8000` sirve `GET /` con 200 y `/static/app.js` y `/static/style.css` con 200.
- `decision_triage` tiene una fila por finding procesado y ninguna por el caso fuera
  de alcance.
- Un `POST` real a `/api/chat` con `curl` devuelve respuesta.

## Honestidad en la verificacion

Si un caso da FAIL, se arregla la causa. No se maquilla ni se ajusta el criterio.
Si algo no se puede ejecutar por falta de credenciales o de red, se dice
explicitamente y no cuenta como aprobado.
