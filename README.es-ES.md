

[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/alexgoller-illumio-mcp-server-badge.png)](https://mseep.ai/app/alexgoller-illumio-mcp-server)

# Servidor MCP de Illumio

Un servidor de Protocolo de Contexto de Modelo (MCP) que proporciona una interfaz para interactuar con Illumio PCE (Policy Compute Engine). Este servidor habilita el acceso programático a la gestión de cargas de trabajo de Illumio, operaciones de etiquetas, análisis de flujo de tráfico, segmentación automática (ringfencing) e identificación de servicios de infraestructura.

<a href="https://glama.ai/mcp/servers/xhqzxlo9iy">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/xhqzxlo9iy/badge" alt="Servidor MCP de Illumio" />
</a>

## ¿Qué puede hacer?

Usa IA conversacional para comunicarte con tu PCE:

- **CRUD completo** en cargas de trabajo, etiquetas, listas IP, servicios y sets de reglas
- **Análisis de tráfico** — consulta flujos, obtén resúmenes, filtra por decisión de política
- **Segmentación automática (ringfencing)** — analiza el tráfico y crea políticas de segmentación entre aplicaciones con un solo comando
- **Aplicación selectiva** — añade reglas de denegación para aplicaciones en modo selectivo con variantes de consumidor configurables
- **Identificación de servicios de infraestructura** — descubre qué aplicaciones son servicios de infraestructura usando análisis de centralidad de grafos, para saber qué política aplicar primero
- **Gestión de reglas de denegación** — crear, actualizar y eliminar reglas de denegación (incluyendo denegación con sobrescritura para emergencias)
- **Monitoreo de eventos** — consulta eventos del PCE con filtros de severidad y tipo
- **Verificaciones de estado del PCE** — verifica conectividad y credenciales

## Requisitos previos

- Python 3.8+
- Acceso a una instancia de Illumio PCE
- Credenciales API válidas para el PCE

## Instalación

1. Clona el repositorio:

```bash
git clone https://github.com/alexgoller/illumio-mcp-server.git
cd illumio-mcp-server
```

2. Instala las dependencias:

```bash
uv sync
```

## Configuración

Deberías ejecutarlo usando el comando `uv`, lo cual facilita pasar variables de entorno y ejecutarlo en segundo plano.

## Uso de uv y Claude Desktop

En MacOS: `~/Library/Application\ Support/Claude/claude_desktop_config.json`
En Windows: `%APPDATA%/Claude/claude_desktop_config.json`

Agrega lo siguiente a la sección `custom_settings`:

```json
"mcpServers": {
    "illumio-mcp": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/illumio-mcp-server",
        "run",
        "illumio-mcp"
      ],
      "env": {
        "PCE_HOST": "your-pce-host",
        "PCE_PORT": "your-pce-port",
        "PCE_ORG_ID": "1",
        "API_KEY": "api_key",
        "API_SECRET": "api_secret"
      }
    }
  }
}
```

## Transporte HTTP con servidor de recursos OAuth (Fase 3a)

El servidor se ejecuta sobre HTTP usando el transporte Streamable HTTP de MCP (especificación rev 2025-03-26) y valida tokens portadores OAuth 2.1 emitidos por tu IdP. Esta es la **Fase 3a**: se aplica identidad; las claves PCE por usuario llegarán en la Fase 3b.

### Ejecución con autenticación (configuración de producción)

```bash
export MCP_PUBLIC_URL=https://mcp.illumio.example
export MCP_OAUTH_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
export MCP_OAUTH_JWKS_URL=https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys
export MCP_OAUTH_AUDIENCE=https://mcp.illumio.example
export MCP_OAUTH_REQUIRED_SCOPE=illumio-mcp.use   # default; override if needed
illumio-mcp-http --host 127.0.0.1 --port 8080
```

El servidor se niega a iniciar sin estas variables de entorno (a menos que `MCP_DEV_INSECURE=1`).

Los clientes MCP descubren el AS mediante el endpoint estándar RFC 9728:

```
GET /.well-known/oauth-protected-resource
```

Las solicitudes no autenticadas a `/mcp` retornan `401` con
`WWW-Authenticate: Bearer resource_metadata="<URL>"`, lo cual cualquier cliente MCP compatible con la especificación (Claude Desktop, ChatGPT, MCP Inspector) sigue automáticamente para ejecutar el flujo de código de autorización PKCE contra el AS configurado.

### Ejecución sin autenticación (solo desarrollo)

```bash
MCP_DEV_INSECURE=1 illumio-mcp-http
```

El servidor registra una advertencia prominente. NO usar en producción.

### Endpoints de estado (siempre no autenticados)

- `GET /healthz` — disponibilidad (liveness)
- `GET /readyz` — preparación (readiness) (La Fase 3a retorna lo mismo que healthz; las Fases 3b/c añadirán verificabilidad de PCE + JWKS)

### Dos modos de PCE (Fase 3b vs Fase 3e)

El servidor HTTP soporta dos formas de obtener credenciales de PCE, seleccionadas vía
`MCP_PCE_MODE`:

| Modo | `MCP_PCE_MODE` | Credenciales PCE | Incorporación | Auditoría en PCE |
|---|---|---|---|---|
| **Por usuario** (predeterminado) | `per_user` | Una clave API de PCE por usuario autenticado, cifrada en el almacén de claves | El usuario se registra en la página `/setup` o con la herramienta `register-pce-credentials` | Los registros del PCE muestran la persona real mediante la clave API por usuario |
| **Compartido** | `shared` | Una clave de cuenta de servicio de PCE desde el entorno (igual que stdio) | Ninguna — funciona inmediatamente para cualquier usuario autenticado | Los registros del PCE muestran la cuenta de servicio; el registro de auditoría de MCP es la fuente de verdad para "quién hizo qué" |

**Elige por usuario cuando:**
- Quieras que la atribución de auditoría en el PCE identifique a la persona
- Los usuarios estén dispuestos a proporcionar su propia clave API de PCE una vez
- Puedas tolerar la proliferación de claves PCE por usuario (el PCE tiene límites)

**Elige compartido cuando:**
- El PCE limite las claves API por usuario de manera demasiado agresiva para el modo por usuario
- Quieras una incorporación sin fricción (sin paso de `/setup`)
- Estés conforme dependiendo solo del registro de auditoría de MCP para la atribución a nivel humano
- Operes la cuenta de servicio del PCE tú mismo y la roten según un cronograma

En el modo **compartido**, `/setup` no se monta, las herramientas de gestión de credenciales
(`register-pce-credentials`, `delete-pce-credentials`) se niegan con un error amigable, y `MCP_KEK` no es requerido. SSO + JWT + autorización basada en roles + registro de auditoría + tokens de confirmación siguen aplicándose idénticamente.

```bash
# Modo compartido — mismo entorno que stdio usa hoy, más configuración de auth/roles
export MCP_PCE_MODE=shared
export PCE_HOST=https://your-pce.example.com
export PCE_PORT=8443
export PCE_ORG_ID=1
export API_KEY=your_pce_api_key_name
export API_SECRET=your_pce_api_key_secret
# (otras variables de entorno de auth/roles de secciones anteriores siguen aplicando)
illumio-mcp-http
```

### Claves PCE por usuario (Fase 3b)

Cada usuario autenticado tiene su propia clave/secreto API de PCE almacenado en un
almacén de claves SQLite cifrado. Los registros de auditoría en el PCE atribuyen correctamente por persona; revocar a un usuario es una sola llamada de herramienta.

Variables de entorno adicionales requeridas al ejecutar con autenticación:

```bash
export MCP_KEK=$(python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())')
export MCP_KEYSTORE_PATH=/var/lib/illumio-mcp/keys.db   # default: ./data/keys.db
```

El KEK **nunca** se almacena junto a la base de datos. Pérdida del KEK = pérdida total de
credenciales almacenadas (intencional, fallo cerrado). Para producción, obtén MCP_KEK de
KMS o Vault en lugar de la shell del operador.

Rutas de incorporación (cualquiera funciona):

1. **Navegador** — visita `/setup` después de autenticarte; pega las credenciales en el formulario.
2. **Cliente MCP** — llama a la herramienta `register-pce-credentials`; la única herramienta
   disponible antes de registrar credenciales.

Otras herramientas de credenciales:
- `check-pce-credentials-status` — ¿tiene este usuario credenciales registradas?
- `delete-pce-credentials` — elimina las credenciales de este usuario.

### Autorización basada en roles (Fase 3c)

El servidor mapea los grupos del IdP de cada usuario a uno de tres roles internos:
**lector**, **operador**, **administrador**. La autorización por herramienta se aplica por el
despachador usando el metadato `roles` en cada `ToolSpec`.

Configura el mapeo grupo → rol vía entorno (separado por comas):

```bash
# Un usuario que coincida con CUALQUIERA de estos grupos obtiene ese rol; el rol más alto gana.
export MCP_ROLE_GROUPS_ADMIN=sg-illumio-mcp-admin
export MCP_ROLE_GROUPS_OPERATOR=sg-illumio-mcp-operator,sg-illumio-mcp-admin
export MCP_ROLE_GROUPS_READER=sg-illumio-mcp-readonly,sg-illumio-mcp-operator,sg-illumio-mcp-admin

# Opcional: rol de fallback cuando ningún grupo coincide. Déjalo sin establecer para rechazar.
# export MCP_ROLE_DEFAULT=reader
```

Predeterminados por herramienta:

| Categoría de herramienta | Roles permitidos | Ejemplos |
|---|---|---|
| Lecturas | lector, operador, admin | `get-labels`, `get-workloads`, `get-traffic-flows` |
| Escrituras | operador, admin | `create-*`, `update-*`, `delete-*` |
| Aprovisionamiento + masivo | admin | `provision-policy`, `ringfence-batch` |

Un usuario sin un rol coincidente (y sin `MCP_ROLE_DEFAULT`) recibe un error estructurado
`forbidden_no_role`.

### Registro de auditoría (Fase 3c)

Cada decisión del despachador (permitir / denegar / error) se escribe en una base de datos SQLite de auditoría. Esquema y ubicación de almacenamiento:

```bash
# Por defecto en <keystore_dir>/audit.db
export MCP_AUDIT_LOG_PATH=/var/lib/illumio-mcp/audit.db
```

Las filas de auditoría incluyen `(ts, sub, iss, tool, decision, reason, role, request_id)`
— **nunca** argumentos de herramienta. El `request_id` coincide con el encabezado de respuesta `X-Request-Id` para que las trazas externas puedan correlacionarse.

Ejemplos de consulta:

```sql
-- Llamadas denegadas recientes por usuario
SELECT ts, sub, tool, reason FROM audit_log
WHERE decision='denied'
ORDER BY ts DESC LIMIT 20;

-- Volumen de llamadas de herramienta por usuario
SELECT sub, COUNT(*) FROM audit_log
WHERE ts > date('now', '-7 days')
GROUP BY sub ORDER BY 2 DESC;
```

### Tokens de confirmación para herramientas mutantes (Fase 3d)

Las herramientas marcadas con `requires_confirm=True` (actualmente `provision-policy`,
`ringfence-batch`, `register-pce-credentials`, `delete-pce-credentials`) requieren
un token de confirmación de un solo uso emitido por el servidor en `params._meta.confirm_token` cuando
se llaman sobre HTTP. El modo stdio no se ve afectado: el operador que inició el
proceso puede llamar a herramientas mutantes directamente.

Variables de entorno requeridas en modo de autenticación:

```bash
export MCP_CONFIRM_HMAC_KEY=$(python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())')
# Opcional:
# export MCP_CONFIRM_TTL_SECONDS=120
# export MCP_CONFIRM_JTI_PATH=/var/lib/illumio-mcp/jti.db
# export MCP_CONFIRM_FRESH_AUTH_SECONDS=300   # requiere JWT auth_time dentro de 5 min
```

#### Cómo un cliente lo usa

1. Llama a la herramienta mutante sin token → el servidor retorna:
   ```json
   {"error": "confirm_required", "params_hash": "<sha256>", "message": "..."}
   ```
2. Llama a `POST /confirm` con el JWT y el params_hash:
   ```bash
   curl -X POST https://mcp.illumio.example/confirm \
     -H "Authorization: Bearer $JWT" \
     -H "Content-Type: application/json" \
     -d '{"tool":"provision-policy","params_hash":"<sha256>"}'
   # → {"confirm_token": "...", "expires_in": 120}
   ```
3. Vuelve a llamar a la herramienta con el token en `params._meta.confirm_token`.

Los tokens son de **un solo uso** (replays retornan `confirm_token_replay`) y de **alcance**
a `(sub, tool, params_hash)`. Manipular cualquier campo invalida el token.

#### Autenticación escalonada (opcional, recomendada para producción)

Establece `MCP_CONFIRM_FRESH_AUTH_SECONDS=300` para requerir que el reclamo `auth_time`
del JWT esté dentro de los últimos 5 minutos. Obliga al usuario a reautenticarse
antes de acuñar un token: la defensa contra inyección de prompts más fuerte disponible
sin un modelo de sesión interactiva. Requiere que el IdP emita `auth_time`
(Entra y Okta lo hacen para flujos de inicio de sesión OIDC).

## Herramientas

### Gestión de Cargas de Trabajo
- `get-workloads` — Recupera cargas de trabajo con filtrado opcional por nombre, hostname, IP, etiquetas y resultados máximos
- `create-workload` — Crea una carga de trabajo no gestionada con nombre, direcciones IP y etiquetas
- `update-workload` — Actualiza las propiedades de una carga de trabajo existente
- `delete-workload` — Elimina una carga de trabajo del PCE

### Operaciones de Etiquetas
- `get-labels` — Recupera etiquetas con filtrado opcional por clave, valor y resultados máximos
- `create-label` — Crea una nueva etiqueta con par clave-valor
- `update-label` — Actualiza una etiqueta existente
- `delete-label` — Elimina una etiqueta

### Gestión de Sets de Reglas y Reglas
- `get-rulesets` — Obtén sets de reglas con filtrado opcional por nombre, descripción y estado habilitado
- `create-ruleset` — Crea un nuevo set de reglas con alcances (scopes)
- `update-ruleset` — Actualiza propiedades del set de reglas
- `delete-ruleset` — Elimina un set de reglas
- `create-deny-rule` — Crea una regla de denegación (regular o con sobrescritura) en un set de reglas
- `update-deny-rule` — Actualiza una regla de denegación existente
- `delete-deny-rule` — Elimina una regla de denegación

### Gestión de Listas IP
- `get-iplists` — Obtén listas IP con filtrado opcional por nombre, descripción, FQDN y resultados máximos
- `create-iplist` — Crea una nueva lista IP
- `update-iplist` — Actualiza una lista IP existente
- `delete-iplist` — Elimina una lista IP

### Gestión de Servicios
- `get-services` — Obtén servicios con filtrado opcional por nombre, puerto, protocolo y resultados máximos
- `create-service` — Crea una nueva definición de servicio
- `update-service` — Actualiza un servicio existente
- `delete-service` — Elimina un servicio

### Análisis de Tráfico
- `get-traffic-flows` — Obtén datos detallados de flujo de tráfico con filtrado por rango de fechas, origen/destino, servicio, decisión de política y más
- `get-traffic-flows-summary` — Obtén resúmenes de tráfico agregados agrupados por aplicación, entorno, puerto y protocolo

### Segmentación Automática (Ringfencing)
- `create-ringfence` — **Creación automatizada de políticas de segmentación entre aplicaciones.** Analiza flujos de tráfico para descubrir qué aplicaciones remotas se comunican con una aplicación objetivo, luego crea un set de reglas con:
  - **Regla de permiso intra-alcance** — todas las cargas de trabajo dentro de la aplicación pueden comunicarse libremente
  - **Reglas de permiso extra-alcance** — cada aplicación remota descubierta obtiene una regla de permiso en Todos los Servicios
  - **Modo de aplicación selectiva** (`selective=true`) — añade una regla de denegación bloqueando todo el tráfico entrante, con reglas de permiso para aplicaciones conocidas procesadas primero. Te lleva a la aplicación más rápido que el modo de aplicación completa.
  - **Variantes de consumidor de denegación** (parámetro `deny_consumer`):
    - `any` (predeterminado) — Lista IP Any (0.0.0.0/0) como consumidor, denegación solo en el destino. Más seguro.
    - `ams` — Todas las Cargas de Trabajo como consumidor, denegación enviada a cada carga de trabajo gestionada. Más amplia.
    - `ams_and_any` — Ambas. Cobertura máxima.
  - **Conciencia de cobertura de política** — cada regla se anota como `already_allowed` (tráfico cubierto por política existente, creado para documentación) o `newly_allowed` (llenando un vacío de política). El resumen muestra cuántas aplicaciones remotas ya están cubiertas vs necesitan nuevas reglas.
  - **Parámetro `skip_allowed`** — establece en `true` para crear reglas solo para tráfico no cubierto por política existente, produciendo sets de reglas mínimos que solo llenan vacíos
  - **Seguro para fusiones** — detecta sets de reglas y reglas existentes, nunca crea duplicados
  - **Soporte para dry-run** — previsualiza lo que se crearía sin hacer cambios

### Identificación de Servicios de Infraestructura
- `identify-infrastructure-services` — **Descubre qué aplicaciones son servicios de infraestructura** analizando patrones de tráfico. Construye un grafo de comunicación entre aplicaciones y usa **puntuación de doble patrón** para reconocer dos tipos de infraestructura:

  **Infra de proveedor** (AD, DNS, DB compartida) — consumida por muchas aplicaciones, alto grado de entrada, bajo grado de salida.
  **Infra de consumidor** (monitoreo, respaldo, envío de logs) — se conecta a muchas aplicaciones, alto grado de salida, bajo grado de entrada.

  Se calculan dos puntuaciones por aplicación, y la más alta gana:

  | Puntuación | Métrica de grado (40%) | Direccionalidad (30%) | Betweenness (25%) | Volumen (5%) |
  |---|---|---|---|---|
  | **Proveedor** | Grado de entrada | Relación consumidor (entrada/total) | Centralidad de betweenness | Volumen de conexión |
  | **Consumidor** | Grado de salida | Relación productor (salida/total) | Centralidad de betweenness | Volumen de conexión |

  **Atenuación de tráfico mixto:** `score *= 1 / (1 + min(in_degree, out_degree) * 0.3)` — las aplicaciones con conexiones entrantes Y salientes significativas son aplicaciones de negocio, no infraestructura. Las aplicaciones puramente direccionales (todo entrada O todo salida) no reciben penalización.

  Los entornos no productivos (staging, dev, etc.) reciben una **penalización de puntuación del 50%** ya que los servicios de infraestructura suelen vivir en producción.

  Las aplicaciones se clasifican en niveles:
  - **Infraestructura Principal** (puntuación >= 75) — monitoreo, AD, SIEM, DNS. Política primero.
  - **Servicio Compartido** (puntuación >= 50) — bases de datos compartidas, colas de mensajes. Política segundo.
  - **Aplicación Estándar** (puntuación < 50) — aplicaciones de negocio normales.

  Cada resultado incluye un campo `dominant_pattern` ("provider" o "consumer") que indica qué tipo de infraestructura se parece la aplicación.

  **¿Por qué importa esto:** Los servicios de infraestructura son consumidos por muchas aplicaciones O se conectan a muchas aplicaciones. Si segmentas aplicaciones sin permitir primero los servicios de infraestructura, rompes dependencias. Esta herramienta te dice qué política aplicar primero.

### Ciclo de Vida de Política
- `provision-policy` — **Aprovisiona cambios de borrador pendientes** para moverlos del estado de borrador a activo. Puede aprovisionar todos los cambios pendientes o elementos específicos por href. Incluye descripciones de cambios para la ruta de auditoría.
- `compare-draft-active` — **Compara política de borrador vs activa** para previsualizar qué cambiaría al aprovisionar. Muestra sets de reglas, reglas, listas IP y servicios creados, actualizados y eliminados.

### Preparación para Aplicación
- `enforcement-readiness` — **Evalúa si una aplicación está lista para la aplicación de políticas.** Analiza flujos de tráfico, cobertura de política existente, modos de aplicación y estado de segmentación. Retorna una puntuación de preparación (0-100) con recomendaciones accionables:
  - **Cobertura de política** (40 puntos) — qué porcentaje de tráfico está cubierto por reglas
  - **Existe segmentación** (20 puntos) — se ha creado un set de reglas de segmentación
  - **Modo de aplicación** (20 puntos) — están las cargas de trabajo en completo/selectivo/solo_visibilidad
  - **Sin tráfico bloqueado** (10 puntos) — sin bloqueos no intencionales
  - **Todas las aplicaciones remotas cubiertas** (10 puntos) — sin tráfico de aplicaciones remotas no cubierto

### Operaciones por Lote
- `ringfence-batch` — **Segmenta múltiples aplicaciones a la vez.** Opcionalmente usa `identify-infrastructure-services` para ordenar automáticamente aplicaciones por puntuación de infraestructura (infraestructura primero, luego aplicaciones estándar). Soporta modo dry-run para previsualizar todos los cambios antes de aplicarlos.

### Estado de Aplicación de Cargas de Trabajo
- `get-workload-enforcement-status` — **Obtén el estado del modo de aplicación en cargas de trabajo**, agrupado por aplicación y entorno. Muestra conteos por modo (inactivo, solo_visibilidad, selectivo, completo) e identifica aplicaciones con **estados de aplicación mixtos** — un problema común durante despliegues.

### Cobertura de Política
- `get-policy-coverage-report` — **Genera un informe de cobertura de política** para una aplicación mostrando qué tráfico está cubierto por reglas existentes vs qué se bloquearía. Desglosa por entrante/saliente, identifica servicios y aplicaciones remotas no cubiertos, y proporciona un porcentaje general de cobertura.
- `find-unmanaged-traffic` — **Encuentra tráfico que involucra cargas de trabajo no gestionadas** o direcciones IP. Estos son orígenes/destinos sin etiquetas de app/entorno, representando puntos ciegos de política. Filtra por dirección (entrante/saliente/ambas) y conteo de conexiones.

### Análisis de Seguridad
- `detect-lateral-movement-paths` — **Detecta rutas potenciales de movimiento lateral** analizando patrones de tráfico entre aplicaciones. Identifica puntos de articulación (nodos puente) cuya comprometencia proporcionaría acceso a grupos de aplicaciones desconectados. Calcula alcanzabilidad desde cualquier aplicación inicial y traza rutas multi-salto hasta una profundidad configurable.
- `compliance-check` — **Verifica el cumplimiento de políticas** contra frameworks (PCI-DSS, NIST 800-53, Controles CIS, o mejores prácticas generales). Evalúa segmentación, modos de aplicación, exposición de puertos de alto riesgo y cobertura de política. Retorna una puntuación de cumplimiento con hallazgos por verificación (PASS/FAIL/WARNING).

### Monitoreo de Eventos
- `get-events` — Obtén eventos del PCE con filtrado opcional por tipo de evento, severidad, estado y límites de resultados

### Pruebas de Conexión
- `check-pce-connection` — Verifica conectividad y credenciales del PCE

## Pruebas

El proyecto incluye un conjunto integral de pruebas de integración que se ejecutan contra un PCE real usando el protocolo MCP.

```bash
# Configura credenciales en .env
cat > .env << EOF
PCE_HOST=your-pce-host
PCE_PORT=8443
PCE_ORG_ID=1
API_KEY=your-api-key
API_SECRET=your-api-secret
EOF

# Ejecuta todas las pruebas
uv run pytest tests/ -v
```

El conjunto de pruebas cubre:
- Listado de herramientas y validación de esquema
- Ciclo de vida CRUD completo para cargas de trabajo, etiquetas, listas IP, servicios, sets de reglas y reglas de denegación
- Consultas y resúmenes de flujo de tráfico
- Creación de segmentación (estándar, selectiva, variantes de consumidor de denegación, idempotencia de fusión)
- Identificación de servicios de infraestructura (puntuación, ordenamiento, clasificación por nivel)
- Manejo de errores para recursos faltantes

## Orden de procesamiento de reglas de Illumio

Comprender el procesamiento de reglas es esencial para la segmentación:

1. **Reglas esenciales** — integradas, no se pueden modificar
2. **Reglas de Denegación con Sobrescritura** — bloquean tráfico sobrescribiendo todos los permisos (uso de emergencia)
3. **Reglas de Permiso** — permiten tráfico (aquí van las reglas de aplicaciones remotas de segmentación)
4. **Reglas de Denegación** — bloquean tráfico específico (aquí va denegar-todo-entrante de segmentación)
5. **Acción predeterminada** — modo selectivo = permitir-todo, aplicación completa = denegar-todo

En la aplicación selectiva, el predeterminado es permitir-todo, por lo que se necesita una regla de denegación para que la segmentación sea efectiva. Las aplicaciones remotas conocidas obtienen reglas de permiso (paso 3) que se procesan antes de la denegación (paso 4).

## Ejemplos visuales

Todos los ejemplos a continuación fueron generados por Claude Desktop y con datos obtenidos a través de este servidor MCP.

### Análisis de Aplicación
![Análisis de Aplicación](images/application-analysis.png)
*Vista detallada de patrones de comunicación y dependencias de la aplicación*

![Análisis de Nivel de Aplicación](images/application-tier-analysis.png)
*Análisis de patrones de tráfico entre diferentes niveles de aplicación*

### Información de Infraestructura
![Panel de Análisis de Infraestructura](images/infrastrcture-analysis-dashboard.png)
*Panel de visión general mostrando métricas clave de infraestructura y estado*

![Servicios de Infraestructura](images/infrastructure-services-analysis.png)
*Análisis detallado de comunicaciones de servicios de infraestructura*

### Evaluación de Seguridad
![Informe de Análisis de Seguridad](images/security-analysis-report.png)
*Informe integral de análisis de seguridad*

![Hallazgos de Alto Riesgo](images/security-assessment-findings-high-risk.png)
*Hallazgos de evaluación de seguridad para vulnerabilidades de alto riesgo*

![Cumplimiento PCI](images/security-assessment-findings-pci.png)
*Hallazgos de evaluación de cumplimiento PCI*

![Cumplimiento SWIFT](images/security-assessment-findings-swift.png)
*Hallazgos de evaluación de cumplimiento SWIFT*

### Planificación de Remediación
![Visión General del Plan de Remediación](images/security-remediation-plan.png)
*Visión general de la planificación de remediación de seguridad*

![Pasos Detallados de Remediación](images/security-remediation-plan-2.png)
*Pasos detallados para la implementación de remediación de seguridad*

### Gestión de Políticas
![Visión General de Listas IP](images/iplists-overview.png)
*Interfaz de gestión para listas IP*

![Categorías de Sets de Reglas](images/ruleset-categories.png)
*Visión general de categorías de sets de reglas y organización*

![Ordenamiento de Sets de Reglas de Aplicación](images/ordering-application-ruleset-overview.png)
*Configuración del ordenamiento de sets de reglas de aplicación*

### Gestión de Cargas de Trabajo
![Análisis de Cargas de Trabajo](images/workload-analysis.png)
*Análisis y métricas detallados de cargas de trabajo*

![Tráfico de Cargas de Trabajo](images/workload-traffic-identification.png)
*Identificación y análisis de patrones de tráfico de cargas de trabajo*

### Gestión de Etiquetas
![Etiquetas PCE por Tipo](images/pce-labels-by-type.png)
*Organización de etiquetas PCE por tipo y categoría*

### Análisis de Servicios
![Inferencia de Roles de Servicio](images/service-role-inference.png)
*Inferencia automática de roles de servicio basada en patrones de tráfico*

![Top 5 Orígenes y Destinos](images/top-5-sources-and-destinations.png)
*Análisis de los 5 principales orígenes y destinos de tráfico*

### Planificación de Proyectos
![Plan de Proyecto](images/project-plan-mermaid.png)
*Cronograma de implementación y hitos del proyecto*

## Prompts disponibles

### Segmentación de Aplicación
El prompt `ringfence-application` ayuda a crear políticas de seguridad para aislar y proteger aplicaciones controlando el tráfico entrante y saliente.

**Argumentos requeridos:**
- `application_name`: Nombre de la aplicación a segmentar
- `application_environment`: Entorno de la aplicación a segmentar

**Características:**
- Crea reglas para comunicación inter-nivel dentro de la aplicación
- Usa flujos de tráfico para identificar conexiones externas requeridas
- Implementa restricciones de tráfico entrante basadas en aplicaciones de origen
- Crea reglas de tráfico saliente para comunicaciones externas necesarias
- Maneja conexiones intra-alcance (misma app/entorno) y extra-alcance (externas)
- Crea sets de reglas separados para conexiones de aplicaciones remotas

### Análisis de Tráfico de Aplicación
El prompt `analyze-application-traffic` proporciona un análisis detallado de los patrones de tráfico y conectividad de la aplicación.

**Argumentos requeridos:**
- `application_name`: Nombre de la aplicación a analizar
- `application_environment`: Entorno de la aplicación a analizar

**Características de análisis:**
- Ordena el tráfico por flujos entrantes y salientes
- Agrupa por combinaciones aplicación/entorno/rol
- Identifica tipos y patrones de etiquetas relevantes
- Muestra resultados en formato de componente React
- Muestra información de protocolo y puerto
- Intenta identificar patrones de servicio conocidos (ej. Nagios en puerto 5666)
- Categoriza el tráfico en tipos de infraestructura y aplicación
- Determina exposición a internet
- Muestra etiquetas de rol, aplicación y entorno de Illumio

### Cómo usar prompts de MCP

Paso 1: Haz clic en el botón "Attach from MCP" en la interfaz

![Flujo de Prompt MCP](images/prompts-finding-prompt-menu.png)

Paso 2: Elige entre los servidores MCP instalados

![Flujo de Prompt MCP](images/prompts-choose-integration.png)

Paso 3: Rellena los argumentos requeridos del prompt:

![Flujo de Prompt MCP](images/prompts-required-parameters.png)

Paso 4: Haz clic en Enviar para enviar el prompt configurado

### Cómo funcionan los prompts

- El servidor MCP envía el prompt configurado a Claude
- Claude recibe contexto a través del Protocolo de Contexto de Modelo
- Permite un manejo especializado de tareas específicas de Illumio

Este flujo habilita el intercambio automatizado de contexto entre sistemas de Illumio y Claude para tareas de análisis de tráfico de aplicaciones y segmentación.

## Docker

La aplicación está disponible como contenedor Docker desde el Registro de Contenedores de GitHub.

### Extraer el contenedor

```bash
docker pull ghcr.io/alexgoller/illumio-mcp-server:latest
```

También puedes usar una versión específica reemplazando `latest` con un número de versión:

```bash
docker pull ghcr.io/alexgoller/illumio-mcp-server:1.0.0
```

### Ejecutar con Claude Desktop

Para usar el contenedor con Claude Desktop, deberás:

1. Crear un archivo de entorno (ej. `~/.illumio-mcp.env`) con tus credenciales de PCE:

```env
PCE_HOST=your-pce-host
PCE_PORT=your-pce-port
PCE_ORG_ID=1
API_KEY=your-api-key
API_SECRET=your-api-secret
```

2. Agregar la siguiente configuración a tu archivo de configuración de Claude Desktop:

En MacOS (`~/Library/Application Support/Claude/claude_desktop_config.json`):
```json
{
    "mcpServers": {
        "illumio-mcp-docker": {
            "command": "docker",
            "args": [
                "run",
                "-i",
                "--init",
                "--rm",
                "-v",
                "/Users/YOUR_USERNAME/tmp:/var/log/illumio-mcp",
                "-e",
                "DOCKER_CONTAINER=true",
                "-e",
                "PYTHONWARNINGS=ignore",
                "--env-file",
                "/Users/YOUR_USERNAME/.illumio-mcp.env",
                "illumio-mcp:latest"
            ]
        }
    }
}
```

Asegúrate de:
- Reemplazar `YOUR_USERNAME` con tu nombre de usuario real
- Crear el directorio de logs (ej. `~/tmp`)
- Ajustar las rutas según tu sistema

### Ejecutar Independiente

También puedes ejecutar el contenedor directamente:

```bash
docker run -i --init --rm \
  -v /path/to/logs:/var/log/illumio-mcp \
  -e DOCKER_CONTAINER=true \
  -e PYTHONWARNINGS=ignore \
  --env-file ~/.illumio-mcp.env \
  ghcr.io/alexgoller/illumio-mcp-server:latest
```

### Docker Compose

Para desarrollo o pruebas, puedes usar Docker Compose:

```yaml
version: '3'
services:
  illumio-mcp:
    image: ghcr.io/alexgoller/illumio-mcp-server:latest
    init: true
    volumes:
      - ./logs:/var/log/illumio-mcp
    environment:
      - DOCKER_CONTAINER=true
      - PYTHONWARNINGS=ignore
    env_file:
      - ~/.illumio-mcp.env
```

Luego ejecuta:

```bash
docker-compose up
```

## Contribuir

1. Haz un fork del repositorio
2. Crea una rama de funcionalidad
3. Confirma tus cambios
4. Empuja a la rama
5. Crea una Pull Request

## Licencia

Este proyecto está licenciado bajo la Licencia GPL-3.0. Consulta el archivo [LICENSE](LICENSE) para detalles.

## Soporte

Para soporte, por favor [crea un issue](https://github.com/alexgoller/illumio-mcp-server/issues).
