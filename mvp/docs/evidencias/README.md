# Evidencias

Material de apoyo para la evaluacion. Nada de esta carpeta lo usa el codigo.

Todo procede de plantillas anonimizadas y datos sinteticos: por privacidad, el MVP no
se conecta a la cuenta real de AWS (ver la seccion 14 del README principal). Los JSON
de `salidas/`, las capturas y los videos se pueden compartir sin exponer datos
operativos.

## capturas/

Capturas de pantalla de la interfaz, una por estado. Nombres sugeridos, para que el
README principal pueda enlazarlas sin cambios:

| Fichero | Que muestra |
|---|---|
| `01-pagina-inicial.png` | La pagina recien abierta: titulo, aviso de datos sinteticos, lista de findings, estado vacio |
| `02-consulta-preparada.png` | Un finding clicado y la consulta rellenada en el cuadro de texto |
| `03-cargando.png` | El estado de carga con el cronometro |
| `04-alert-and-document.png` | Resultado en rojo: compromiso de credenciales o CVE en KEV |
| `05-manual-review-no-inventariado.png` | Resultado en ambar con `resource_context_not_found` |
| `06-manual-review-variacion.png` | Resultado en ambar con `pattern_variation_detected` y las variaciones de puerto y origen |
| `07-out-of-scope.png` | El evento de AWS Health en gris, sin llamada al modelo |
| `08-error-mcp-caido.png` | La tarjeta de error con el puerto 8001 apagado |
| `09-movil.png` | La pagina a 375 px de ancho |
| `10-tema-claro.png` | La pagina con el tema claro del sistema |

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
