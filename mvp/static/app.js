// Frontend del MVP. No consulta datos ni conoce al modelo: habla con /api/findings y
// /api/chat por ruta relativa. Todo el texto que pinta viene del backend y se inserta
// con textContent; aqui no hay HTML generado a partir de la respuesta del modelo.

(function () {
  "use strict";

  var historial = document.getElementById("historial");
  var formulario = document.getElementById("formulario");
  var campo = document.getElementById("pregunta");
  var boton = document.getElementById("enviar");
  var grupos = document.getElementById("grupos-findings");
  var contador = document.getElementById("contador-findings");
  var proveedor = document.getElementById("proveedor");
  var proveedorTexto = proveedor.querySelector(".pill-texto") || proveedor;
  var limpiar = document.getElementById("limpiar");
  var plantillaVacio = document.getElementById("plantilla-vacio").cloneNode(true);

  var ocupado = false;
  var tarjetas = [];
  var catalogo = [];

  function consultaPara(f) {
    return "Haz el triage del finding " + f.finding_id;
  }

  var ETIQUETA_DECISION = {
    alert_and_document: "Escalar y documentar",
    manual_review: "Revisión manual",
    candidate_for_suppression: "Candidato a supresión",
    out_of_scope: "Fuera de alcance"
  };

  var FUENTES = {
    "aws.guardduty": { grupo: "guardduty", titulo: "Amazon GuardDuty", badge: "GuardDuty" },
    "aws.inspector2": { grupo: "inspector", titulo: "Amazon Inspector", badge: "Inspector" }
  };

  // --- utilidades ------------------------------------------------------------

  function el(etiqueta, clase, texto) {
    var nodo = document.createElement(etiqueta);
    if (clase) nodo.className = clase;
    if (texto !== undefined && texto !== null) nodo.textContent = texto;
    return nodo;
  }

  function abreviar(id) {
    if (!id) return "";
    if (id.length <= 26) return id;
    var partes = id.split("/");
    if (partes.length > 1 && partes[partes.length - 1].length <= 26) {
      return "…/" + partes[partes.length - 1];
    }
    return id.slice(0, 10) + "…" + id.slice(-6);
  }

  function segundos(ms) {
    return (ms / 1000).toFixed(1).replace(".", ",") + " s";
  }

  function fuenteLegible(fuente) {
    return (FUENTES[fuente] && FUENTES[fuente].badge) || fuente || "desconocida";
  }

  // --- lista de findings -----------------------------------------------------

  async function cargarFindings() {
    try {
      var respuesta = await fetch("/api/findings");
      var datos = await respuesta.json();

      if (datos.proveedor) {
        proveedorTexto.textContent = "Modelo: " + datos.proveedor;
        proveedor.classList.remove("desconocido");
      } else {
        proveedorTexto.textContent = "Modelo: no configurado";
      }

      pintarGrupos(datos.findings || []);
    } catch (e) {
      grupos.innerHTML = "";
      grupos.appendChild(
        el("p", "estado-lista estado-error",
          "No se pudo cargar la lista de findings. Comprueba que el backend está levantado en el puerto 8000.")
      );
      proveedorTexto.textContent = "Modelo: sin conexión";
    }
  }

  function pintarGrupos(findings) {
    grupos.innerHTML = "";
    tarjetas = [];
    catalogo = findings;
    contador.textContent = findings.length;

    var orden = [
      { clave: "guardduty", titulo: "Amazon GuardDuty", items: [] },
      { clave: "inspector", titulo: "Amazon Inspector", items: [] },
      { clave: "otros", titulo: "Fuera de alcance", items: [] }
    ];

    findings.forEach(function (f) {
      var fuente = FUENTES[f.fuente_aws];
      var clave = f.en_alcance && fuente ? fuente.grupo : "otros";
      orden.filter(function (g) { return g.clave === clave; })[0].items.push(f);
    });

    orden.forEach(function (g) {
      if (!g.items.length) return;
      var seccion = el("section", "grupo");
      seccion.appendChild(el("h3", null, g.titulo));
      var lista = el("ul");
      g.items.forEach(function (f) {
        var li = el("li");
        var tarjeta = crearTarjeta(f);
        tarjetas.push(tarjeta);
        li.appendChild(tarjeta);
        lista.appendChild(li);
      });
      seccion.appendChild(lista);
      grupos.appendChild(seccion);
    });

    if (!tarjetas.length) {
      grupos.appendChild(el("p", "estado-lista", "No hay findings disponibles."));
    }
  }

  // Cada tarjeta tiene dos acciones: el cuerpo rellena el cuadro de texto con una
  // consulta lista para enviar (asi el evaluador ve exactamente que se pregunta), y
  // el boton Ejecutar lanza el triage directamente.
  function crearTarjeta(f) {
    var fuente = FUENTES[f.fuente_aws];
    var fuera = f.en_alcance === false;

    var tarjeta = el("div", "tarjeta" + (fuera ? " tarjeta-fuera" : ""));
    tarjeta.dataset.id = f.finding_id;

    var cuerpo = el("button", "tarjeta-cuerpo");
    cuerpo.type = "button";
    cuerpo.title = f.finding_id;
    cuerpo.setAttribute("aria-label", "Preparar la consulta de triage de " + f.titulo);

    var fila = el("div", "tarjeta-fila");
    fila.appendChild(el("span", "badge badge-" + (fuente && !fuera ? fuente.grupo : "otros"),
      fuera ? "Fuera de alcance" : fuente.badge));
    if (f.severidad) {
      fila.appendChild(el("span", "badge badge-sev sev-" + f.severidad, f.severidad));
    }
    cuerpo.appendChild(fila);

    cuerpo.appendChild(el("div", "tarjeta-titulo", f.titulo));

    var meta = el("div", "tarjeta-meta");
    var id = el("code", null, abreviar(f.finding_id));
    id.title = f.finding_id;
    meta.appendChild(id);
    if (f.recurso) meta.appendChild(el("span", null, f.recurso));
    if (f.entorno && f.entorno !== "unknown") meta.appendChild(el("span", null, f.entorno));
    if (fuera) meta.appendChild(el("span", null, f.fuente_aws));
    cuerpo.appendChild(meta);

    cuerpo.addEventListener("click", function () {
      prepararConsulta(consultaPara(f), tarjeta);
    });

    var ejecutar = el("button", "tarjeta-ejecutar", "Ejecutar");
    ejecutar.type = "button";
    ejecutar.setAttribute("aria-label", "Ejecutar el triage de " + f.titulo);
    ejecutar.addEventListener("click", function () {
      enviar(consultaPara(f), f);
    });

    tarjeta.appendChild(cuerpo);
    tarjeta.appendChild(ejecutar);
    return tarjeta;
  }

  function prepararConsulta(texto, tarjeta) {
    campo.value = texto;
    autoajustar();
    tarjetas.forEach(function (t) { t.classList.toggle("seleccionada", t === tarjeta); });
    campo.focus();
    campo.setSelectionRange(campo.value.length, campo.value.length);
  }

  function findingDesdeTexto(texto) {
    for (var i = 0; i < catalogo.length; i++) {
      if (catalogo[i].finding_id && texto.indexOf(catalogo[i].finding_id) !== -1) return catalogo[i];
    }
    return null;
  }

  function marcarActiva(finding) {
    tarjetas.forEach(function (t) {
      t.classList.remove("seleccionada");
      t.classList.toggle("activa", !!finding && t.dataset.id === finding.finding_id);
    });
  }

  // --- historial -------------------------------------------------------------

  function anadir(nodo) {
    var vacio = historial.querySelector(".vacio");
    if (vacio) vacio.remove();
    historial.appendChild(nodo);
    // Una respuesta se lee desde su cabecera; el resto de mensajes, desde el final.
    if (nodo.classList.contains("resultado") && !nodo.classList.contains("cargando")) {
      nodo.scrollIntoView({ block: "start", behavior: "smooth" });
    } else {
      historial.scrollTop = historial.scrollHeight;
    }
    limpiar.hidden = false;
    return nodo;
  }

  function mensajeUsuario(texto) {
    return el("div", "mensaje-usuario", texto);
  }

  // Estado visual 1: cargando, con cronometro real.
  function tarjetaCargando(finding) {
    var nodo = el("article", "resultado cargando");
    nodo.setAttribute("aria-busy", "true");

    var cabecera = el("div", "resultado-cabecera");
    cabecera.appendChild(el("span", "spinner"));
    cabecera.appendChild(el("span", "cargando-texto",
      finding ? "Ejecutando el triage de " + finding.titulo : "Consultando al agente"));
    var crono = el("span", "cronometro", "0 s");
    cabecera.appendChild(crono);
    cabecera.appendChild(el("span", "cargando-detalle",
      "Normalización, contexto del recurso, historial del patrón, clasificación del modelo y motor de política."));
    nodo.appendChild(cabecera);

    var inicio = performance.now();
    var temporizador = setInterval(function () {
      crono.textContent = Math.round((performance.now() - inicio) / 1000) + " s";
    }, 500);

    return {
      nodo: nodo,
      detener: function () { clearInterval(temporizador); nodo.remove(); }
    };
  }

  // Estado visual 3: error. Criterio de aceptacion, no decoracion.
  function tarjetaError(texto) {
    var nodo = el("article", "resultado error");
    nodo.setAttribute("role", "alert");

    var cabecera = el("div", "resultado-cabecera");
    var titulo = el("span", "error-titulo");
    titulo.innerHTML =
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">' +
      '<circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>';
    titulo.appendChild(document.createTextNode("La consulta no se pudo completar"));
    cabecera.appendChild(titulo);
    nodo.appendChild(cabecera);

    nodo.appendChild(el("div", "resultado-cuerpo", texto));
    return nodo;
  }

  // Extrae decision, riesgo, reason codes y accion recomendada del texto plano del
  // agente. Primero busca el bloque de lineas `campo: valor` que exige el prompt; si
  // el modelo respondio en prosa, rastrea los codigos dentro del texto. Si ni asi
  // encuentra la decision, la tarjeta se pinta como texto simple.
  var CODIGOS_DECISION = /\b(alert_and_document|manual_review|candidate_for_suppression|out_of_scope)\b/;
  var NIVELES_RIESGO = { low: "low", medium: "medium", high: "high", critical: "critical",
                         bajo: "low", medio: "medium", alto: "high", critico: "critical", "crítico": "critical" };

  function analizarRespuesta(texto) {
    var campos = {};
    var resto = [];
    var patron = /^\s*[-•*]?\s*`?(decision|decisión|final_risk_level|reason_codes|recommended_action)`?\s*:\s*(.+?)\s*$/i;

    String(texto).split("\n").forEach(function (linea) {
      var m = linea.match(patron);
      if (m) {
        var clave = m[1].toLowerCase().replace("decisión", "decision");
        if (!(clave in campos)) {
          campos[clave] = m[2].replace(/`/g, "").trim();
          return;
        }
      }
      resto.push(linea);
    });

    var plano = String(texto);
    var decision = campos.decision ? campos.decision.toLowerCase().replace(/[^a-z_]/g, "") : null;
    if (!(decision in ETIQUETA_DECISION)) {
      var md = plano.match(CODIGOS_DECISION);
      decision = md ? md[1] : null;
    }

    var riesgo = campos.final_risk_level ? campos.final_risk_level.toLowerCase().replace(/[^a-záéíóú]/g, "") : null;
    if (!riesgo) {
      var mr = plano.match(/final_risk_level\b[^a-záéíóú]*(?:es|de|:)?\s*([a-záéíóú]+)/i);
      riesgo = mr ? mr[1].toLowerCase() : null;
    }
    riesgo = riesgo ? (NIVELES_RIESGO[riesgo] || riesgo) : null;

    var codigosBruto = campos.reason_codes || null;
    if (!codigosBruto) {
      var mc = plano.match(/reason_codes\b[^a-z_]*(?:son|es|:)?\s*([a-z_]+(?:\s*(?:,|;|\sy\s)\s*[a-z_]+)*)/i);
      codigosBruto = mc ? mc[1] : null;
    }
    var codigos = codigosBruto
      ? codigosBruto.replace(/[\[\]"'`]/g, "").split(/\s*(?:,|;|\sy\s)\s*/).map(function (c) { return c.trim(); }).filter(function (c) { return /_/.test(c); })
      : [];

    return {
      decision: decision in ETIQUETA_DECISION ? decision : null,
      riesgo: riesgo,
      codigos: codigos,
      accion: campos.recommended_action || null,
      cuerpo: resto.join("\n").replace(/\n{3,}/g, "\n\n").trim()
    };
  }

  // Estado visual 2: respuesta del agente.
  function tarjetaResultado(texto, finding, ms) {
    var datos = analizarRespuesta(texto);
    var nodo = el("article", "resultado");

    if (datos.decision) {
      nodo.dataset.decision = datos.decision;

      var cabecera = el("div", "resultado-cabecera");

      var contexto = el("div", "resultado-contexto");
      contexto.appendChild(document.createTextNode(finding ? finding.titulo : "Resultado del triage"));
      if (finding) {
        var id = el("code", null, abreviar(finding.finding_id));
        id.title = finding.finding_id;
        contexto.appendChild(id);
      }
      cabecera.appendChild(contexto);

      var decision = el("div", "decision");
      decision.appendChild(el("code", null, datos.decision));
      decision.appendChild(el("small", null, ETIQUETA_DECISION[datos.decision]));
      cabecera.appendChild(decision);

      if (datos.riesgo) {
        var riesgo = el("span", "riesgo");
        riesgo.dataset.riesgo = datos.riesgo;
        riesgo.appendChild(document.createTextNode("Riesgo "));
        riesgo.appendChild(el("code", null, datos.riesgo));
        cabecera.appendChild(riesgo);
      }

      if (datos.codigos.length) {
        var chips = el("div", "chips");
        chips.appendChild(el("span", "chips-etiqueta", "reason codes"));
        datos.codigos.forEach(function (c) { chips.appendChild(el("span", "chip", c)); });
        cabecera.appendChild(chips);
      }

      nodo.appendChild(cabecera);

      if (datos.cuerpo) nodo.appendChild(el("div", "resultado-cuerpo", datos.cuerpo));

      if (datos.accion) {
        var accion = el("div", "resultado-accion");
        accion.appendChild(el("b", null, "Acción recomendada"));
        accion.appendChild(document.createTextNode(datos.accion));
        nodo.appendChild(accion);
      }
    } else {
      nodo.appendChild(el("div", "resultado-cuerpo", String(texto)));
    }

    var pie = el("div", "resultado-pie");
    pie.appendChild(el("span", null, "Respuesta del agente a través de la herramienta triagear_finding"));
    if (ms) pie.appendChild(el("span", null, "Tiempo total " + segundos(ms)));
    nodo.appendChild(pie);

    return nodo;
  }

  // --- envio -----------------------------------------------------------------

  function bloquear(activo) {
    ocupado = activo;
    boton.disabled = activo;
    campo.disabled = activo;
    tarjetas.forEach(function (t) {
      t.classList.toggle("ocupada", activo);
      Array.prototype.forEach.call(t.querySelectorAll("button"), function (b) { b.disabled = activo; });
    });
    historial.setAttribute("aria-busy", activo ? "true" : "false");
  }

  async function enviar(pregunta, finding) {
    if (ocupado) return;
    bloquear(true);
    marcarActiva(finding || null);

    anadir(mensajeUsuario(pregunta));
    var carga = tarjetaCargando(finding || null);
    anadir(carga.nodo);
    var inicio = performance.now();

    try {
      var respuesta = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pregunta: pregunta })
      });

      var datos = null;
      try { datos = await respuesta.json(); } catch (e) { datos = null; }

      carga.detener();

      if (!respuesta.ok || !datos || datos.ok !== true) {
        var mensaje = (datos && datos.error) ||
          "El servidor respondió con el código " + respuesta.status + " y sin detalle.";
        anadir(tarjetaError(mensaje));
        return;
      }

      anadir(tarjetaResultado(datos.respuesta, finding || null, performance.now() - inicio));
    } catch (e) {
      carga.detener();
      anadir(tarjetaError(
        "No se pudo contactar con el backend. Comprueba que está levantado con " +
        "`uvicorn api.chat:app --port 8000` desde la carpeta mvp/."
      ));
    } finally {
      bloquear(false);
      campo.focus();
    }
  }

  // --- compositor ------------------------------------------------------------

  function autoajustar() {
    campo.style.height = "auto";
    campo.style.height = Math.min(campo.scrollHeight, 160) + "px";
  }

  formulario.addEventListener("submit", function (evento) {
    evento.preventDefault();
    var pregunta = campo.value.trim();
    if (!pregunta) return;
    campo.value = "";
    autoajustar();
    enviar(pregunta, findingDesdeTexto(pregunta));
  });

  campo.addEventListener("input", autoajustar);
  campo.addEventListener("keydown", function (evento) {
    if (evento.key === "Enter" && !evento.shiftKey) {
      evento.preventDefault();
      formulario.requestSubmit();
    }
  });

  limpiar.addEventListener("click", function () {
    historial.innerHTML = "";
    historial.appendChild(plantillaVacio.cloneNode(true));
    limpiar.hidden = true;
    marcarActiva(null);
    campo.focus();
  });

  // La cabecera fija cambia de alto con el ancho de la ventana (el aviso puede ocupar
  // una o dos lineas); los paneles calculan su altura con esta variable.
  var cabecera = document.querySelector(".cabecera");
  function ajustarCabecera() {
    if (!cabecera) return;
    document.documentElement.style.setProperty("--cabecera-alto", cabecera.offsetHeight + "px");
  }
  ajustarCabecera();
  window.addEventListener("resize", ajustarCabecera);
  if (window.ResizeObserver) new ResizeObserver(ajustarCabecera).observe(cabecera);

  cargarFindings();
})();
