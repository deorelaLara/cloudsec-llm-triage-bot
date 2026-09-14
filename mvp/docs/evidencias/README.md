# Evidencias

Material de apoyo para la evaluacion. Nada de esta carpeta lo usa el codigo.

Todo procede de plantillas anonimizadas y datos sinteticos: por privacidad, el MVP no
se conecta a la cuenta real de AWS (ver la seccion 14 del README principal). Los JSON
de `salidas/`, las capturas y los videos se pueden compartir sin exponer datos
operativos.

Los diagramas de arquitectura estan un nivel arriba: `docs/arquitectura-iconos.png`
(solo iconos, con su fuente `arquitectura-iconos.svg`) y `docs/arquitectura.png`
(detallado).

## capturas/

Capturas reales de la interfaz, una por estado o funcionalidad, tomadas con un
navegador automatizado (Chromium, 1280x800 a escala 2, tema claro salvo la ultima)
sobre la pagina servida en `http://127.0.0.1:8000` con OpenAI `gpt-4.1-mini`.

| Fichero | Que muestra |
|---|---|
| `01-pagina-inicial.png` | La pagina recien abierta: titulo, aviso de datos sinteticos, lista de findings, estado vacio, proveedor |
| `02-consulta-preparada.png` | Un finding clicado y la consulta rellenada en el cuadro de texto |
| `03-cargando.png` | El estado de carga con el cronometro |
| `04-alert-and-document.png` | Caso a: compromiso de credenciales, `alert_and_document`, `risk_level_blocked` |
| `05-manual-review-no-inventariado.png` | Caso b: `manual_review` con `resource_context_not_found` (T2) |
| `06-manual-review-variacion.png` | Caso f: `manual_review` con `pattern_variation_detected` y las variaciones de puerto y origen (T3) |
| `07-out-of-scope.png` | Caso c: el evento de AWS Health en gris, sin llamada al modelo |
| `08-error-mcp-caido.png` | Caso e: la tarjeta de error con el puerto 8001 apagado |
| `09-movil.png` | La pagina a 375 px de ancho, pagina completa |
| `10-tema-oscuro.png` | El resultado de la variacion con el tema oscuro |
| `11-inspector-kev.png` | CVE critico en CISA KEV: `alert_and_document`, `cve_in_cisa_kev_blocked` |
| `12-inspector-medio.png` | CVE medio en dev: `manual_review`, `only_low_risk_can_be_suppressed` |
| `13-tool-invalida.png` | Caso d: un identificador inexistente escrito a mano; el agente reporta el error de la tool |
| `14-leyenda.png` | La leyenda de decisiones desplegada |

## videos/

Grabaciones de la demo. Sugerido: `demo-completa.mp4` (recorrido de los siete
findings, unos 3 minutos) y `error-mcp-caido.mp4` (apagar el 8001, pulsar Ejecutar,
volver a levantarlo).

## salidas/

Respuestas JSON reales de la tool y del backend, generadas con:

```bash
python verificar.py --todos-los-samples --guardar docs/evidencias/salidas
```

Cada fichero es la respuesta completa de `triagear_finding` para un caso (`a_*`,
`b_*`, ..., `sample_*`) o del `POST /api/chat` (`chat_post_api_chat.json`). Sirven
para comparar lo que ve el evaluador con lo que devolvio el sistema en la
verificacion documentada en el README.
