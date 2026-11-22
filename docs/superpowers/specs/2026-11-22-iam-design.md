# Plugin IAM para GLPI 12 — Documento de diseño

Fecha: 2026-11-22 · Estado: en aprobación · Clave del plugin: `iam` (propuesta)

## 1. Intención

Dar al analista de ciberseguridad una herramienta dentro de GLPI para gobernar el
acceso a las aplicaciones y recursos de negocio según ISO/IEC 27001:2022
(A.5.3 segregación de funciones, A.5.15 control de acceso, A.5.16 gestión de
identidades, A.5.18 derechos de acceso, A.8.2 derechos de acceso privilegiado).

El centro es una **matriz RBAC de doble entrada**: puestos de la organización ×
roles de las aplicaciones/recursos del inventario GLPI. Sobre esa matriz se ve,
de forma nominal, quién tiene qué acceso, se detectan **desvíos** de forma visual
e inmediata, y cada caso es buscable. Los dueños de cada aplicación ven y
validan los accesos a sus activos. Hoy la carga del acceso real es manual; más
adelante un agente de IA, a partir de un ticket o de otro insumo, registrará los
casos y ejecutará controles por API.

**Por qué**: GRC Manager ya revisa los *perfiles de GLPI* de los usuarios
(`accessreviews`), pero nadie gobierna los roles dentro de las aplicaciones de
negocio. Ese es el hueco que cubre este plugin. Se mantiene todo en GLPI, junto
al SGSI, el inventario y el ERM.

## 2. Objetivos

1. Catálogo de **puestos** de toda la empresa en GLPI (árbol Área → Puesto).
2. Catálogo de **recursos** (aplicación/sistema) vinculados a cualquier elemento
   del inventario GLPI, cada uno con sus **roles** y su **dueño** (usuario o grupo).
3. **Matriz** puesto × rol con el acceso esperado.
4. Registro de **accesos reales** (persona × rol) con su origen (ticket),
   aprobación, cuenta usada y vencimiento.
5. Motor de **desvíos** que compara lo esperado contra lo real y aplica
   excepciones de GRC.
6. Control de **acceso privilegiado** (A.8.2) y de **segregación de funciones** (A.5.3).
7. **Ciclo de vida**: altas, cambios de puesto (movers), bajas (leavers), suplencias.
8. **Campañas de recertificación** validadas por el dueño, con evidencia en GRC.
9. **"Mis activos"** para el dueño.
10. **Notas permanentes** (bitácora no borrable) sobre controles y accesos.
11. Visibilidad por **perfiles/derechos**: el técnico común no ve el módulo.
12. **API** completa (REST de GLPI) para que un agente registre casos.
13. **Fotos por fecha** de la matriz para auditoría.

## 3. No objetivos

- No aprovisiona ni desaprovisiona cuentas en los sistemas reales (no hay
  conectores a AD/SAP en esta etapa). Registra, compara y controla.
- No reemplaza las revisiones de perfiles GLPI de GRC Manager.
- No gestiona contraseñas (eso es Accounts Inventory; solo se referencia la cuenta).
- No incluye el agente de IA ni el servidor MCP: se deja la API lista para él.
- No importa desde RRHH/AD en la primera versión (sí se deja un import CSV
  como mejora posterior; ver §12).

## 4. Anti-objetivos (fracaso aunque “funcione”)

- Una matriz que no permita ver en segundos dónde están los desvíos.
- Que un técnico sin perfil IAM vea quién tiene acceso a qué.
- Que un dueño pueda validar sus propios accesos o ver activos que no son suyos.
- Que la historia (accesos, decisiones, notas) se pueda alterar o borrar.
- Duplicar en el plugin las excepciones que ya viven en GRC.
- Que el plugin deje de funcionar si GRC Manager no está instalado.

## 5. Restricciones

- GLPI 12.0.x, PHP 8.2+, mismo stack y convenciones que el ERM
  (`/home/daniel/claude/glpi-plugin-erm`): namespace `GlpiPlugin\Iam`, PSR-12,
  PHPStan nivel 5, PHPUnit con clases puras, locales es_AR/es_ES con msgid en
  inglés, CI en GitHub Actions.
- Gotchas de GLPI 12 aprendidos en ERM aplican (typed statics, `csrf_compliant`,
  `addDefaultWhere` para la API, tablas sin `is_recursive`, cache:clear, etc.).
- Integración con GRC Manager **opcional y protegida** (como en ERM): si no está
  activo, las funciones de excepciones/evidencias se ocultan.
- Multi-entidad: todo objeto con `entities_id`; puestos y recursos recursivos.
- Entorno de prueba: GLPI de laboratorio (<glpi-url>), demo Empresa A (demo) (entidad 1).

## 6. Enfoques considerados

| Enfoque | Ventaja | Por qué no / sí |
|---|---|---|
| **A. Plugin propio `iam`, esqueleto del ERM** | Modelo de datos a medida, motor de desvíos, API rica, reutiliza patrones probados | **Elegido** |
| B. Módulo dentro del ERM | Comparte menú, derechos, fotos | Mezcla disciplinas y usuarios distintos; engorda un plugin público con su propio ciclo |
| C. Solo nativo GLPI (cargos, grupos, Fields) | Sin código de tablas | Sin lugar para calcular desvíos/SoD ni dibujar la matriz; API pobre para el agente |

## 7. Modelo de datos (conceptual)

Todas las tablas `glpi_plugin_iam_*`. Nombres orientativos; el builder ajusta.

**Puesto** (`Position`, CommonTreeDropdown): nombre, área (padre en el árbol),
`usertitles_id` opcional (vínculo con el cargo GLPI), `groups_id` opcional,
descripción, entidad/recursivo, activo.

**Persona ↔ Puesto** (`Position_User`): `users_id`, `positions_id`,
`is_primary`, `type` (titular / suplencia / temporal), `date_begin`, `date_end`,
`tickets_id` de origen. Una persona puede tener **varios puestos**.

**Recurso** (`Resource`): nombre, `itemtype` + `items_id` (cualquier inventario
GLPI: Software, Appliance, Computer, NetworkEquipment, Database, DatabaseInstance,
WebApplication, etc.), dueño (`users_id_owner` y/o `groups_id_owner`), criticidad
(enlazable con clasificación del inventario), frecuencia de recertificación
(por defecto anual), entidad.

**Rol del recurso** (`Role`): recurso, nombre (Consulta, Carga, Aprobador,
Admin…), descripción, **nivel**: `standard` / `sensitive` / `privileged`,
`is_breakglass` (cuenta de emergencia; cada uso se registra como `GrantUsage`:
grant, fecha, ticket obligatorio, motivo — por formulario o API).

**Matriz** (`Position_Role`): puesto × rol → `allowed` (esperado) /
`on_request` (permitido con aprobación del dueño) / `forbidden`.
Ausencia de celda = no previsto (default deny).

**Acceso real** (`Grant`): `users_id`, `roles_id`, `plugin_accounts_accounts_id`
opcional (cuenta usada), `date_begin`, `date_end` (vencimiento), `tickets_id`
de origen, `users_id_approver`, justificación, MFA (sí/no/n.a.),
estado (`active` / `revoked` / `expired`), fecha y motivo de revocación,
`source` (`manual` / `api` / `agent`). Las revocaciones son cambios de estado,
nunca borrado. Entidad del grant = **entidad del recurso** (la visibilidad sigue
al dueño de la aplicación, no a la entidad de la persona); lo mismo para
Deviation. `users_id` y `roles_id` son inmutables tras crear; los demás campos
(vencimiento, cuenta, MFA) se pueden corregir con historial de GLPI
(`dohistory`); el purge está deshabilitado para todos salvo super-admin vía
mantenimiento.

**Regla SoD** (`SodRule`): par de roles (o rol ↔ rol de otro recurso)
incompatibles, severidad, justificación normativa.

**Desvío** (`Deviation`): materializado por el motor para poder buscar,
filtrar, asignar y anotar. Tipo, persona, rol/recurso, grant(s) implicados,
severidad, estado (`open` / `excepted` / `resolved`),
`waivers_id` de GRC si está exceptuado, fechas de detección/resolución.

**Campaña** (`Campaign`) + **ítem de campaña** (`CampaignItem`): alcance
(recursos), período, revisor (dueño), decisión por acceso
(`keep` / `revoke` / `modify`), quién decidió y cuándo. Una decisión `revoke`
o `modify` **no** cambia el grant al instante: lo pasa a `revoke_pending`
(o `modify_pending`) y abre un ticket hijo para ejecutar el cambio en el sistema
real; el analista lo confirma al cerrar ese ticket y recién ahí el grant queda
`revoked`. La campaña cierra cuando todos los ítems están decididos; la evidencia
a GRC incluye las revocaciones pendientes.

**Nota permanente** (`Note`): `itemtype` + `items_id` (Grant, Deviation,
CampaignItem, Campaign, Resource), autor, fecha, texto. **Solo inserción**: sin
editar ni borrar, ni siquiera el administrador. Una corrección es una nota nueva
que referencia a la anterior.

**Foto** (`Snapshot`): estado serializado de matriz + accesos + desvíos a una fecha
(cron y manual), mismo patrón que `Snapshot` del ERM.

**Modelo de registro (decidido)**: el plugin registra accesos *ya otorgados*.
El pedido y su aprobación siguen en el ticket de GLPI (validaciones nativas);
el analista o el agente cargan el grant con ticket y aprobador(es). Una
aprobación faltante se detecta después, como desvío. El esquema de `Grant`
incluye desde 1.0 el estado `pending` y `users_id_approver_security` (sin uso
en 1.0) para poder sumar más adelante un circuito de solicitud y aprobación
dentro del plugin sin migraciones disruptivas.

## 8. Motor de desvíos

Acceso esperado de una persona = **unión** de los roles `allowed` de todos sus
puestos vigentes (`on_request` solo vale con aprobación registrada).

Tipos de desvío (cada uno con color, ícono y filtro):

| Código | Condición | Severidad base |
|---|---|---|
| `not_expected` | grant activo sin celda en ningún puesto vigente | media |
| `forbidden` | grant activo con celda `forbidden` | alta |
| `on_request_unapproved` | celda `on_request` sin aprobador | media |
| `sod_conflict` | la persona acumula dos roles de una regla SoD (incluso vía doble puesto) | alta |
| `priv_no_expiry` | rol privilegiado sin `date_end` | alta |
| `priv_no_mfa` | rol privilegiado sin MFA | alta |
| `priv_shared_account` | privilegiado usando la misma cuenta que el acceso estándar o cuenta sin dueño | alta |
| `orphan` | usuario inactivo/baja en GLPI con grants activos | crítica |
| `mover_leftover` | grant que solo justificaba un puesto ya finalizado (cambio de puesto o fin de suplencia) | alta |
| `no_ticket` | grant sin ticket ni aprobador | baja |
| `expired` | `date_end` pasada y estado aún activo | media |
| `review_overdue` | recurso con recertificación vencida | media |

**Excepciones (GRC)**: si existe un waiver de GRC Manager `approved`, vigente
(`date_begin ≤ hoy ≤ date_end`) y vinculado al grant, a la persona+recurso o al
elemento de inventario del recurso, el desvío pasa a `excepted` (se muestra en
ámbar con candado, con número EXC y vencimiento). Si el waiver vence o se rechaza,
el desvío vuelve a `open` automáticamente. Desde un desvío se puede **pedir una
excepción** en GRC prellenada (solicitud; la aprobación sigue el flujo de GRC).
Pendiente técnico: verificar qué itemtypes acepta `waivers_items`; si no admite
los del plugin, se vincula al elemento de inventario + persona.

El motor es una clase pura (testeable) más un cron que recalcula y también se
dispara al guardar grants, puestos o matriz.

Sin GRC Manager no hay excepciones: el desvío solo puede resolverse (corrigiendo
el acceso o la matriz). No existe un “riesgo aceptado” propio del plugin.

**Escritura en GRC**: se hace instanciando las clases de GRC Manager desde PHP
(`add()` sobre su waiver/evidencia), protegido por `Plugin::isPluginActive` y
`class_exists`; nunca SQL directo. Si la clase rechaza la creación
(p. ej. `canCreate()=false` en evidencias), se degrada a un enlace prellenado y
a un PDF/CSV de evidencia descargable para adjuntar a mano. Versión de referencia:
GRC Manager 2.80.0 instalado en la VM.

## 9. Acceso privilegiado (A.8.2)

Un grant sobre rol `privileged` exige: justificación, aprobación del dueño
**y** de un aprobador de seguridad (derecho `plugin_iam_approve`), vencimiento
obligatorio (máximo configurable, p. ej. 90 días), cuenta separada de la
estándar (vínculo a Accounts Inventory), MFA, y recertificación más frecuente
(trimestral por defecto). Cuentas de emergencia (break-glass) se marcan como
tales en el rol; cada uso se registra como nota permanente con ticket.

## 10. Ciclo de vida (altas, cambios, bajas)

- **Alta**: asignar puesto → la matriz sugiere los grants esperados a registrar.
- **Cambio de puesto / fin de suplencia**: al cerrar `Position_User`, los grants
  que ya no tienen respaldo pasan a `mover_leftover`.
- **Baja**: usuario inactivo o `end_date` en GLPI → `orphan` en todos sus grants.

## 11. Pantallas

1. **Matriz** (vista central). Filas: puestos (agrupables por área). Columnas:
   recursos, expandibles a roles. Celda: definición esperada (✓ / ◐ a pedido /
   ⛔ prohibido / vacío) + conteo de personas reales + badge de desvíos
   (rojo = abierto, ámbar con candado = exceptuado). Clic en celda → panel
   lateral con las **personas nominales** de esa intersección y su estado.
   Filtros: entidad, área, recurso, tipo de desvío, solo desvíos, privilegiados.
   Modo edición (solo derecho de configuración) para definir la matriz.
2. **Vista por persona**: puestos vigentes, accesos esperados vs reales, desvíos,
   SoD, notas. Accesible desde la ficha del usuario GLPI (pestaña).
3. **Vista por recurso**: roles, quién tiene cada uno, desvíos, campañas, excepciones.
   Pestaña en el elemento de inventario vinculado (Software, Appliance, etc.).
4. **Buscador rápido** de casos: persona, recurso, rol, ticket, EXC, tipo de desvío.
   Además, búsqueda estándar de GLPI sobre Grant y Deviation.
5. **Mis activos** (dueño): por recurso suyo → accesos, desvíos, excepciones
   vigentes/por vencer, campañas pendientes con botón Validar, controles hechos.
6. **Campañas**: lanzar, seguir avance, cerrar.
7. **Tablero**: KPIs (desvíos abiertos por tipo/severidad, privilegiados, huérfanos,
   SoD, cobertura de recertificación, excepciones por vencer).

```
               SAP-FI      Core Banking   Firewall
Analista Cob.  ✓ 4/4       ✓ 4/4          ·
Tesorero       ✓ 2/2       ⚠ 1 desvío      ·
Jefe IT        ·           🔒 1 exc.       ✓ 1/1 (priv.)
```

## 12. Perfiles y derechos

Derechos (mismo patrón que ERM, con READ / READ_OWNED, UPDATE / UPDATE_OWNED):

- `plugin_iam` — ver/editar accesos y desvíos (todo o solo “lo mío”).
- `plugin_iam_config` — puestos, recursos, roles, matriz, reglas SoD.
- `plugin_iam_review` — decidir en campañas (dueños).
- `plugin_iam_approve` — aprobación de seguridad para privilegiados.

“Lo mío” para un dueño = recursos donde es `users_id_owner` o integrante de
`groups_id_owner`, y todo lo que cuelga de ellos (roles, grants, desvíos, campañas).

Perfiles creados al instalar (marcados con `[iam:key]` como en ERM):

| Perfil | Ve | Puede |
|---|---|---|
| IAM – Analista | todo | configurar, registrar accesos, gestionar desvíos, pedir excepciones |
| IAM – Dueño de activo | solo sus recursos | ver quién accede, validar/revocar en campañas, anotar |
| IAM – Auditor | todo, lectura | historial, fotos, notas |
| IAM – Agente | según alcance de su entidad | solo crear/proponer grants, puestos y notas vía API; nunca aprobar ni revocar sin ticket |

Reglas: nadie valida sus propios accesos; si el dueño es un grupo, cualquier
integrante valida y queda registrado quién; un técnico sin estos derechos no ve
el menú ni las pestañas. La API respeta las mismas restricciones (`addDefaultWhere`
en todas las tablas, incluidas las hijas).

## 12 bis. Multi-entidad

Mismo modelo que ERM (varias empresas en una instancia, p. ej. Empresa A y
Empresa B (demo)):

- Toda tabla tiene `entities_id`; catálogos (puestos, recursos, roles, reglas SoD)
  además `is_recursive`, para que un holding defina puestos o aplicaciones
  comunes heredados por las filiales, y cada filial agregue los propios.
- Celda de matriz, grant, desvío y campaña pertenecen a la **entidad del recurso**.
  Una persona de la entidad B puede tener acceso a una aplicación de la entidad A
  (servicio compartido); lo ve quien tenga visibilidad sobre A.
- La matriz, el tablero, “Mis activos” y las fotos se filtran por la entidad
  activa (con o sin sub-entidades, según la selección de GLPI).
- Configuración por entidad heredable (pestaña en Entidad, como `EntityConfig`
  del ERM): prefijo de numeración, vencimiento máximo de privilegiados,
  frecuencias de recertificación por nivel, si se exige MFA en privilegiados.
- Las reglas SoD se evalúan por persona en todas las entidades que el analista
  puede ver (un conflicto puede cruzar empresas).
- Demo en dos empresas: Empresa A (demo) (entidad 1) y Empresa B (demo) (entidad 2).

## 13. Integraciones

- **Inventario GLPI**: el recurso apunta a cualquier itemtype; pestaña “Accesos
  (IAM)” en ese elemento. Usuarios y grupos GLPI como personas y dueños.
- **Accounts Inventory** (opcional): grant ↔ cuenta.
- **GRC Manager** (opcional): lectura de waivers; solicitud de waiver prellenada;
  al cerrar una campaña, registrar evidencia en el control A.5.18 (y A.8.2 para
  privilegiados).
- **ERM** (opcional, futuro): un desvío crítico puede originar un riesgo.
- **Tickets**: todo grant, puesto y desvío puede referenciar un ticket; pestaña IAM
  en el ticket con lo registrado desde él.
- **API / agente**: endpoints REST estándar de GLPI para todas las clases. El agente
  usa `source=agent`, deja nota permanente con su razonamiento y nunca aprueba
  (solo registra y propone).

## 12 ter. Reportería y evidencia de auditoría

Objetivo: que el dueño y el responsable de seguridad puedan mostrar a un **auditor
externo de certificación ISO 27001** (etapas 1 y 2, y vigilancia) la evidencia del
control de acceso, sin armarla a mano.

Todos los reportes: período y **“a la fecha de”** (desde las fotos), filtros por
entidad/recurso/área, mismos filtros de visibilidad que la pantalla (un dueño solo
reporta lo suyo), PDF (GLPIPDF, como el reporte de directorio del ERM) y CSV.
Cada PDF lleva portada con entidad, período, quién lo generó, fecha/hora, filtros
y **huella SHA-256** del contenido; la generación queda registrada (quién, cuándo,
qué) para poder demostrar que el documento no se alteró.

**Reporte del dueño** (“Mis activos” → Reporte), por aplicación:
- Roles y su nivel, quién tiene cada uno (nominal), puesto que lo justifica,
  ticket y aprobación de origen.
- Desvíos abiertos/exceptuados/resueltos en el período, con excepciones GRC y vencimiento.
- Recertificaciones: fecha, quién validó, decisiones (mantener/revocar) y
  cumplimiento de las revocaciones (fecha del ticket hijo).
- Privilegiados y usos de cuentas de emergencia.

**Reporte global** (todas las aplicaciones):
- Tablero ejecutivo: cobertura (aplicaciones con dueño, matriz definida,
  recertificación al día), desvíos por tipo/severidad y tendencia, privilegiados,
  conflictos SoD, excepciones por vencer.
- Matriz RBAC completa a una fecha.
- Indicadores de eficacia del control (cláusula 9.1): % de recertificaciones en
  término; tiempo medio entre baja del usuario y revocación de sus accesos;
  % de accesos con ticket y aprobación; privilegiados con vencimiento y MFA;
  desvíos cerrados en plazo.

**Paquete de evidencia para auditoría** (un PDF índice + anexos CSV), organizado
por control del Anexo A:

| Control | Evidencia incluida |
|---|---|
| A.5.15 Control de acceso | matriz RBAC aprobada a la fecha, política/metodología IAM |
| A.5.16 Gestión de identidades | altas, cambios de puesto y bajas del período con sus tiempos |
| A.5.18 Derechos de acceso | accesos con ticket y aprobación; campañas y decisiones; revocaciones ejecutadas |
| A.8.2 Acceso privilegiado | inventario de privilegiados, doble aprobación, vencimiento, MFA, cuentas separadas, usos break-glass |
| A.5.3 Segregación de funciones | reglas SoD, conflictos detectados, resolución o excepción GRC vigente |

- **Muestreo para el auditor**: selección aleatoria reproducible (semilla impresa)
  de N accesos del período, cada uno con su traza completa
  ticket → aprobación → acceso → recertificación → notas. Es lo que el auditor
  suele pedir en etapa 2.
- Excepciones (GRC) usadas en el período con aprobador y medidas compensatorias.
- Lo que falta también se informa (“sin evidencia de recertificación en X”):
  el reporte no maquilla brechas.

El perfil **IAM – Auditor** puede generar todos los reportes en solo lectura; se
puede dar a un auditor externo un usuario temporal con ese perfil.

Reparto: 1.1 tablero + matriz a fecha (CSV); 1.2 reporte del dueño y reporte global
en PDF con huella; 1.3 paquete de evidencia por control + muestreo.

## 13 bis. Ayuda y adopción

Requisito transversal, no una entrega final: cada pantalla sale con su ayuda.
Se reutiliza lo construido en ERM 2.1–2.3.

**Para personas (analista, dueño, auditor):**
- Ayuda en cada campo (tooltips) y recuadros plegables “¿Qué es esto?” en cada
  pantalla, con la referencia ISO 27001:2022 que aplica (A.5.3, A.5.15, A.5.18, A.8.2).
- Leyenda permanente en la matriz (qué significa cada color e ícono) y, en cada
  desvío, **qué hacer**: causa probable, acción recomendada, cómo cerrarlo o pedir
  excepción.
- Página de Ayuda según el perfil activo (Analista / Dueño / Auditor), glosario
  (RBAC, SoD, privilegiado, recertificación, mover/leaver, break-glass) y preguntas
  frecuentes. Contenido en `data/help/{es,en}.json`.
- Checklist de puesta en marcha en el tablero: crear puestos → asignar personas →
  dar de alta recursos y roles → definir matriz → cargar accesos → primera campaña.
- Asistente de alta de recurso (elegir elemento del inventario → roles sugeridos
  → dueño → nivel) y **biblioteca de plantillas**: roles típicos y reglas SoD
  comunes (pagos, compras, nómina, administración de TI) para no partir de cero.
- Guías rápidas por rol y un caso completo de punta a punta en `docs/`
  (es y en), con capturas.
- “Metodología IAM” en PDF descargable (criterios de desvíos, severidades,
  privilegiados, recertificación), útil como documento del SGSI.

**Para el agente de IA (y para integradores):**
- `docs/api-agente.md`: cómo autenticarse, qué clases usar, orden de operaciones
  (buscar persona → buscar recurso/rol → crear grant con ticket → nota permanente),
  ejemplos `curl` y JSON completos, errores esperables y cómo interpretarlos.
- Reglas del agente explícitas: `source=agent`, siempre ticket, siempre nota con
  su razonamiento, nunca aprueba, nunca revoca sin ticket.
- Mensajes de error de la API claros y estables (códigos), pensados para que un
  agente pueda corregir y reintentar.

Reparto por entrega: 1.0 incluye ayuda en campos, recuadros, leyenda de la matriz,
página de Ayuda básica y `api-agente.md`; 1.1 suma el “qué hacer” por desvío y la
biblioteca de plantillas; 1.2 el checklist, guías, caso completo y PDF de metodología.

## 13 ter. Desarrollo seguro (requisito bloqueante)

Es un plugin de seguridad que concentra quién accede a qué: una fuga de datos o
una escalada de privilegios aquí es un incidente grave. Ninguna entrega sale con
una vulnerabilidad conocida. Referencia: **OWASP ASVS 4.0 nivel 2** y OWASP Top 10.

**Lecciones del ERM (ya pagadas, no repetir):** falta de filtro por entidad en
consultas agregadas (1.5.1), entidad del hijo tomada del input y no del padre
(1.4.1), búsqueda guardada no revalidada (1.9.2), tablas hijas expuestas por la API
sin `addDefaultWhere`, derechos a nivel de ítem faltantes y claves de padre mutables
(2.0.2). Cada una se convierte en una regla y un test desde 1.0.

**Reglas de código:**
- **Autorización en el servidor, en cada punto de entrada**: `front/`, `ajax/`,
  pestañas, acciones masivas, cron, API REST. Verificar derecho + entidad + ítem
  (`canViewItem`/`canUpdateItem`) en cada lectura y escritura; nunca confiar en que
  la UI ocultó un botón. Default deny.
- **API**: `addDefaultWhere` en **todas** las tablas (incluidas hijas y de relación),
  restricción por entidad y “lo mío”; derechos a nivel de ítem en las relaciones.
- **Sin SQL armado a mano**: solo el query builder/iterator de GLPI con parámetros;
  ningún valor del usuario concatenado (incluidos `ORDER BY`, nombres de campo e
  `itemtype`, que se validan contra listas blancas).
- **`itemtype` polimórfico** (recurso, notas): lista blanca de clases permitidas;
  nunca instanciar una clase recibida del input sin validarla.
- **Asignación masiva**: `prepareInputForAdd/Update` con lista blanca de campos;
  campos inmutables (persona, rol, padre, entidad heredada, autor y fecha de nota)
  se descartan del input y se toman del servidor. La entidad de un hijo siempre
  sale del padre.
- **Append-only real**: notas y registros de uso sin `UPDATE`/`DELETE` en ninguna
  capa (clase, UI, API, acciones masivas); `canPurge/canDelete` en falso; tests
  que lo intentan por API y fallan.
- **XSS**: Twig con autoescape, sin `|raw` salvo HTML sanitizado por GLPI; datos
  hacia JS por `data-*`/JSON codificado, nunca interpolados en scripts. La matriz
  y el panel nominal escapan todo texto (nombres, notas, comentarios).
- **CSRF**: `csrf_compliant`; en GLPI 12 la protección la aplica el kernel (`CheckCsrfListener` + `CsrfChecker`: rechaza POST con `Sec-Fetch-Site` cross-site/same-site u `Origin` distinto) para todo front de plugin; `csrf_token()` está deprecado y no se usa. Los endpoints AJAX que modifican deben ser POST y pasar por el kernel.
- **Separación de funciones en el propio plugin**: nadie valida sus accesos; el
  aprobador de seguridad no puede ser quien solicita ni el beneficiario; el agente
  (`source=agent`) no puede aprobar ni cerrar campañas.
- **Exportaciones (CSV/PDF)**: aplican los mismos filtros de visibilidad; CSV
  neutraliza inyección de fórmulas (`= + - @` al inicio).
- **Datos sensibles**: el plugin no guarda contraseñas ni secretos (solo referencia
  a Accounts Inventory); no se escriben datos personales en logs.
- **Errores**: sin trazas ni SQL hacia el usuario; mensajes con código estable.
- **Integraciones** (GRC, Accounts, ERM) protegidas: si la clase no existe o el
  usuario no tiene derecho en el otro plugin, no se lee ni se escribe.

**Verificación en cada entrega:**
- Tests de autorización por perfil (Analista, Dueño, Auditor, técnico sin derecho,
  dueño de otra entidad) sobre UI y API: cada caso “no debe ver / no debe modificar”
  es un test.
- PHPStan (nivel 5 mínimo, objetivo 6+), PHPCS, PHPUnit, y **Semgrep** (reglas
  PHP/OWASP) en CI; `composer audit` para dependencias de desarrollo.
- Revisión de seguridad del diff antes de cada release (`/security-review`) y
  documento `docs/revision-seguridad.md` actualizado con el modelo de amenazas
  (STRIDE de alto nivel: analista malicioso, dueño curioso, técnico sin derecho,
  token de API robado, agente con prompt manipulado vía ticket).
- **Agente con prompt injection**: el texto del ticket es dato no confiable; la API
  limita al agente a crear/proponer con su propio usuario de servicio de mínimo
  privilegio (perfil “IAM – Agente”), toda acción queda con nota y es reversible.
- `SECURITY.md` con canal de reporte; releases solo con CI en verde.
- Checklist de release del ERM aplica tal cual (regenerar locales, CI verde antes
  de `gh release create`).

## 14. Entregas sugeridas

1. **1.0** Catálogos (puestos, persona↔puesto, recursos, roles), matriz, grants,
   derechos y perfiles, notas permanentes, matriz visual con panel nominal,
   buscador. Demo Empresa A.
2. **1.1** Motor de desvíos completo + excepciones GRC + privilegiados + SoD + tablero.
3. **1.2** Mis activos + campañas de recertificación + evidencia GRC + fotos.
4. **1.3** Ciclo de vida automático (movers/leavers), import CSV, guía para el agente.

## 15. Decidido por el usuario

- Plugin de IAM orientado al analista de ciberseguridad, criterio ISO 27001:2022.
- Matriz de doble entrada recursos (cualquier inventario GLPI) × puestos, con
  personas nominales, desvíos visuales y búsqueda rápida.
- Excepciones tomadas de la tabla de excepciones de GRC Manager.
- Carga manual hoy; luego un agente IA vía API.
- Visibilidad por perfiles: técnico no ve; perfil IAM sí; dueño ve sus aplicaciones.
- “Mis activos” para el dueño, que valida controles; dueños pueden ser grupos.
- Todos los puestos de la empresa se llevan en GLPI; una persona puede tener más de uno.
- Notas en los controles que no se borran.
- Enfoque A (plugin propio).
- Opción 1: solo registro de accesos ya otorgados; aprobación en el ticket GLPI.
- Ayuda adecuada para adopción rápida, tanto para analistas como para el agente.
- Multi-entidad.
- Reportería para el dueño y global, apta para mostrar a un auditor externo de certificación ISO.
- Cumplir buenas prácticas de desarrollo seguro: cero vulnerabilidades conocidas.
- Repo público nuevo `daniellopez6/glpi-plugin-iam` para publicar a la comunidad.

## 16. Llamadas de Claude (revisables)

- Clave `iam`; separada del ERM; repo propio (crear repo GitHub solo tras preguntar).
- Default deny en la matriz y nivel de rol en tres valores.
- Recertificación dentro del plugin (no en GRC), con evidencia hacia GRC.
- Aprobación dual para privilegiados y vencimiento máximo configurable.
- Desvíos materializados en tabla (para buscar, asignar y anotar).
- Tabla de severidades del §8.

- Alcance del plan: se diseña el esquema completo de 1.0–1.3 en la migración
  inicial (columnas para waivers, campañas, MFA, aprobaciones) y se planifica e
  implementa por entregas, empezando por 1.0.
- Sin “riesgo aceptado” local; excepciones solo vía GRC.
- Entidad de grants/desvíos = entidad del recurso.
- Grant con usuario/rol inmutables, resto editable con historial; sin purge.
- Break-glass como flag del rol + registro de usos con ticket.
- Revocación por campaña en dos pasos (pendiente + ticket hijo).
- Escritura en GRC vía sus clases PHP, con degradación a enlace/export.

## 17. Queda para el builder

Nombres exactos de tablas/clases, librería/JS para la matriz (preferir vanilla +
Twig como en ERM), paginación/virtualización de la matriz grande, formato de
fotos, frecuencia del cron, estructura de los tests.
