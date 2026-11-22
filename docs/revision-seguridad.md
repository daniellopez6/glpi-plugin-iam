# Revisión de seguridad (OWASP ASVS 4.0 L2)

Modelo de amenazas y verificación de autorización del plugin IAM 1.0 (spec §12, §12 bis, §13 ter). Fecha de esta
revisión: 2026-11-22 (Tarea 13), sobre la rama `feat/1.0` desplegada en el laboratorio GLPI 12.0.2 (192.168.88.4).
La revisión de seguridad de todo el diff de la rama la hace la revisión final de la rama (reemplaza el paso
`/security-review` del plan).

## 1. Activos

| Activo | Por qué importa |
| --- | --- |
| Registro de otorgamientos (`glpi_plugin_iam_grants`) | Quién tiene acceso a qué: un mapa de objetivos para un atacante y la evidencia de auditoría (ISO 27001 A.5.15, A.5.18, A.8.2). Debe ser íntegro y no borrable. |
| Bitácora permanente (`glpi_plugin_iam_notes`) | Razonamiento de analistas y del agente; evidencia append-only. |
| Matriz RBAC (`positions_roles`) y asignaciones persona↔puesto (`positions_users`) | Definen el acceso esperado: cambiarlas convierte un desvío en "esperado" y oculta una escalada. |
| Catálogo de recursos y roles (`resources`, `roles`) | Dueños (usuario/grupo) que deciden la visibilidad de "lo mío"; nivel privilegiado / break-glass. |
| Separación de funciones | Registrador ≠ beneficiario ≠ aprobador ≠ aprobador de seguridad. |
| Derechos de perfil (`plugin_iam*`) y pertenencia a grupos de GLPI | Son el único fundamento de las decisiones de autorización. |
| Credenciales de API (app token, user tokens) | Un token robado actúa con el perfil del usuario. El plugin no guarda secretos propios. |
| Datos personales | Nombres de personas, puestos, tickets: no se escriben en logs. |

## 2. Actores

| Actor | Capacidad de partida | Objetivo típico |
| --- | --- | --- |
| Analista malicioso (perfil IAM - Analista) | Lee y escribe el registro de las entidades de su perfil | Registrarse su propio acceso, borrar huellas, aprobar en nombre de otro, ver otra empresa. |
| Dueño curioso (IAM - Dueño de activo) | READ_OWNED / UPDATE_OWNED sobre sus recursos | Ver accesos de recursos ajenos, ver quién "debería" tener acceso en puestos que no administra, cambiar el beneficiario. |
| Técnico sin derecho (Technician/Self-Service) | Sesión GLPI válida sin derechos IAM | Abrir páginas, ajax o API del plugin por URL directa. |
| Token de API robado | Igual que su dueño, sin la UI | Enumerar el registro, crear/alterar otorgamientos, purgar evidencia. |
| Agente con prompt manipulado (IAM - Agente) | Crea otorgamientos/asignaciones/notas vía API, lee tickets (READALL) | Texto de ticket que lo induce a aprobar, revocar, activar sin ticket o borrar su rastro. |

## 3. STRIDE por punto de entrada

| Punto de entrada | S (suplantación) | T (manipulación) | R (repudio) | I (divulgación) | D (denegación) | E (elevación) |
| --- | --- | --- | --- | --- | --- | --- |
| Páginas `front/*.php` y `*.form.php` | Sesión GLPI obligatoria (firewall del kernel). | Derecho + `can*Item()` del ítem en cada POST; campos inmutables descartados (`InputGuard`). | Historial GLPI (`dohistory`) y `users_id_recorder` del servidor. | Lista/búsqueda filtradas por `addDefaultWhere` → `Scope::criteriaFor()`; formularios por `canViewItem()`. | Sin operaciones masivas costosas fuera de la matriz (perf. pinneada en Tarea 10/11). | Técnico: 403 en todas (W2); menú oculto sin derecho IAM (W1). |
| AJAX `ajax/matrixcell.php` (GET) / `ajax/matrixedit.php` (POST) | Sesión del kernel. | Edición solo POST, CSRF del kernel, `Position_Role::upsert()` revalida CONFIG UPDATE y escritura sobre la fila. | Historial de la celda. | Celda revalida puesto + recurso visibles; dueños sin `missing`/`expected` (W3, W4). | Panel por celda bajo demanda. | 403 para el técnico (W2). |
| Pestañas en elementos GLPI (Software, Ticket, User, Grant…) | — | Sin escritura directa en pestañas salvo alta de nota (mismas reglas que la API). | — | `tabAllowed()` + filas por `visibilityCriteria()` del ítem. | Conteos de pestaña (deuda menor: carga todas las notas). | Sin derecho IAM no se muestran. |
| API REST legacy (`apirest.php`) | App token + user token; sesión por token. | Mismas clases (`prepareInputFor*`, `can*Item()`); `itemtype` en lista blanca (X1); notas y otorgamientos sin DELETE/PURGE (N1). | `source` del servidor (`agent`/`api`/`manual`), recorder = sesión. | `addDefaultWhere` en todas las tablas, incluidas las hijas (E1, O1, F2); `searchText` parametrizado (X2). | Rango por defecto de GLPI. | Agente sin aprobar ni revocar (G3); otra entidad no escribe (E2). Grupos dueños leídos de la base en cada petición, no de la sesión (F4; §6, R-1 corregido). |
| Acciones masivas | — | Note: prohibidas update/delete/purge/clone/transfer/amend; Grant: campos con `massiveaction=false`, `canDelete/canPurge=false`. | — | Mismas restricciones de búsqueda. | — | Purga de recurso/rol/puesto con dependencias rechazada. |
| CLI / cron | Solo `www-data` en el servidor. | En 1.0 no hay tareas cron del plugin (vencimientos y campañas: 1.1). `Role::getSystemSQLCriteria` depende de la sesión: el cron de 1.1 debe consultar directo. | — | El plugin no escribe datos personales en logs. | — | Instalación sin autoinstalación (`OPTION_AUTOINSTALL_DISABLED`). |

## 4. Controles implementados

| Control | Dónde |
| --- | --- |
| Restricción de listas y búsqueda para cada itemtype del plugin (punto único) | `hook.php` `plugin_iam_addDefaultWhere()` → `src/Scope.php` `criteriaFor()`; predicados `visibilityCriteria()` en `src/Grant.php`, `src/Role.php`, `src/Position_Role.php`, `src/Note.php`, `src/Position_User.php`, `src/Resource.php`; paridad pinneada en `tests/Unit/ScopeTest.php` |
| Visibilidad por la entidad del recurso (recursiva), no por la columna del hijo | `isEntityAssign()=false` + `visibilityCriteria()` en `src/Grant.php`, `src/Role.php`, `src/Position_Role.php`, `src/Note.php` |
| "Lo mío" para dueños (usuario o grupo dueño, leído de `glpi_groups_users` en cada petición) | `src/Rights.php::currentGroupIds()` (misma semántica que `Session::loadGroups()`: grupos de las entidades activas + hijos con `recursive_membership`, memo por petición), `src/GroupMembership.php` (pura, `tests/Unit/GroupMembershipTest.php`), `src/Ownership.php`, `src/Resource.php`, `src/Grant.php::seesResource()`, `src/Note.php::mayAddOn()` |
| Derechos a nivel de ítem | `canViewItem/canCreateItem/canUpdateItem` en todas las clases; `canDelete*/canPurge*` en falso para Grant y Note |
| Lista blanca de campos e inmutables | `src/InputGuard.php`, `src/FieldSets.php`; `Grant::sanitize()`, `Position_User::prepareInputForUpdate()` |
| Entidad del hijo tomada del padre | `Grant::prepareInputForAdd()` (entidad del recurso), `Role`, `Position_Role`, `Note::prepareInputForAdd()`, `Position_User` |
| `itemtype` polimórfico en lista blanca, sin `new $x` | `src/ResourceItemtypes.php`, `Note::loadTarget()`; regla `iam-dynamic-instantiation` en `.semgrep.yml` |
| Sin SQL armado a mano | Solo iterator/QuerySubQuery; regla `iam-sql-nonliteral` en `.semgrep.yml` |
| XSS | Twig con autoescape, sin `\|raw` (regla `iam-twig-raw`); JSON de la matriz con `JSON_HEX_*` en `data-client` (`front/matrix.php`) |
| CSRF | `$PLUGIN_HOOKS['csrf_compliant']` (`setup.php`); kernel GLPI 12 `CheckCsrfListener`; `ajax/matrixedit.php` solo POST, `ajax/matrixcell.php` solo GET |
| Append-only | `src/Note.php` (update/delete devuelven false, massive actions prohibidas), `src/Grant.php::delete()`; `Resource/Role/Position` sin purga con dependencias |
| Separación de funciones y agente | `src/GrantRules.php` (`separation`, `approvalErrors`, `validate` para agente, `ownerErrors`); `users_id_approver_security` = sesión |
| Menú y páginas sin derecho | `src/Rights.php::hasAny()`, `src/Menu.php`, chequeo de derecho al inicio de cada `front/` y `ajax/` |
| Vista limitada del dueño en la matriz | `src/Matrix.php` (`membersVisible()`), `src/MatrixSummary.php::forOwner()/visibleHolders()`, `templates/matrix*.html.twig` |
| Búsqueda de casos con los mismos filtros | `src/CaseSearch.php` usa `Resource/Role/Grant::visibilityCriteria()` |

## 5. Lecciones del ERM → regla → test (spec §13 ter)

| Lección ERM | Regla en IAM | Test |
| --- | --- | --- |
| 1.5.1 consultas agregadas sin filtro por entidad | Toda lectura agregada (matriz, búsqueda de casos, conteos) pasa por `visibilityCriteria()` | `ScopeTest`, `MatrixOwnerProjectionTest`, `QuickSearchTest`; api_authz E1, F2, W3 |
| 1.4.1 entidad del hijo tomada del input | Entidad del hijo siempre del padre/recurso | `InputGuardTest`; Revisión 4 (Note `entities_id=2` ignorado); api_authz E2 |
| 1.9.2 búsqueda guardada no revalidada | No hay búsquedas guardadas propias; la búsqueda GLPI y la API reaplican `addDefaultWhere` en cada ejecución | api_authz O1, E1, X2 |
| Tablas hijas expuestas por la API sin `addDefaultWhere` | `Scope::criteriaFor()` cubre todas las tablas con clase | `ScopeTest`; api_authz E1 (7 itemtypes), T1 |
| Derechos a nivel de ítem faltantes | `can*Item()` en cada clase; GET de un ítem ajeno = 403 | api_authz O2, F2, E3, T2 |
| Claves de padre mutables (2.0.2) | Persona, rol, recurso, padre y entidad inmutables tras el alta | `InputGuardTest`, `GrantRulesTest`; api_authz O4 |

## 6. Riesgos residuales y decisiones aceptadas

| Id | Riesgo / decisión | Estado |
| --- | --- | --- |
| R-1 | **Sesión de API viva conservaba los grupos del login.** El plugin decidía "lo mío" con `$_SESSION['glpigroups']`. En la web GLPI 12 lo refresca en cada petición (`SessionVariables` compara `glpigroups_cache_date` con `last_group_change`), pero la API legacy restaura la sesión del token dentro del controlador (`API::retrieveSession()`), después de ese listener: un dueño quitado del grupo seguía viendo el recurso con la misma sesión de API (api_authz F4, Revisión 6). | **Corregido** (Tarea 13, ronda 1): `Rights::currentGroupIds()` lee las pertenencias actuales de `glpi_groups_users` en cada petición; ningún camino de propiedad usa `$_SESSION['glpigroups']`. F4 pasa (Revisión 7). |
| R-2 | **Purga de un puesto con puestos hijos.** GLPI (`CommonTreeDropdown::pre_deleteItem`) re-colgaba los hijos del abuelo sin aviso (Super-Admin: HTTP 200, el hijo pasaba a la raíz). | **Corregido** (Tarea 13, ronda 1): `Position::canPurgeItem()` y `pre_deleteItem()` rechazan la purga si hay subpuestos ("El puesto tiene subpuestos…"). B1 pasa como rechazo esperado (Revisión 7). |
| R-3 | **Purga de una entidad** (no ejecutado, análisis de GLPI 12): `Entity::pre_deleteItem()` solo impide la raíz y entidades con sub-entidades; `cleanDBonPurge()` borra `Profile_User` de la entidad y relaciones de KB/recordatorios/RSS; `CommonDBTM::cleanRelationData()` mueve a la entidad 0 (`_replace_by` o 0) las filas de las tablas declaradas en `inc/relation.constant.php` (tickets, usuarios, grupos, inventario…). El plugin no declara `plugin_iam_getDatabaseRelations`, así que sus filas **conservan el `entities_id` de la entidad borrada**: recursos, roles, celdas, otorgamientos, notas, puestos y asignaciones quedan invisibles para todas las sesiones (ninguna tiene esa entidad activa) pero no se pierden; los tickets referenciados pasan a la raíz. Si se declararan relaciones, GLPI llamaría `update(['entities_id'=>0])`, que el plugin descarta (inmutable) o rechaza. | Aceptado para 1.0: documentar en el manual "no purgar una entidad con datos IAM; reasignar antes"; la evidencia sigue en la base y es recuperable por SQL. Evaluar en 1.1 un bloqueo (`pre_deleteItem` hook sobre Entity). |
| D-1 | Perfiles Analista y Agente con `ticket` READALL: procesan pedidos de acceso desde tickets y el otorgamiento debe referenciar un ticket visible. **Ampliado (Tarea 14, ronda 1):** el perfil Agente también lee personas (`user` READ, para resolver al beneficiario). **Alcance real:** ese derecho del núcleo de GLPI da al agente la lectura completa de `User` en sus entidades activas (búsqueda, logins, correos, teléfonos, subelementos de perfiles y grupos), y el agente es conducido por texto de tickets no confiable (riesgo de exfiltración de datos personales por inyección de instrucciones; se mitiga con el mínimo de entidades del usuario de servicio y las reglas de la guía). No tiene derechos sobre seguimientos. Pendiente de decisión: leer validaciones de tickets exige un bit de crear o validar de `ticketvalidation` (READ solo no basta, comprobado en la VM), por lo que no se concedió. El texto del ticket y los comentarios de las validaciones son entrada no confiable para el agente. Una asignación persona-puesto creada en sesión de agente exige `tickets_id` (`agent_requires_ticket`, defensa en profundidad). | Aceptado (ledger Tareas 8 y 14). |
| D-2 | `isEntityAssign()=false` en Grant, Role, Position_Role y Note: el filtro de entidad de GLPI se desactiva y `visibilityCriteria()` (+ `canViewItem()`) es el único predicado. Un error ahí expone todo; por eso la paridad está pinneada (`ScopeTest`) y verificada por API (E1, F2, O1). | Aceptado (ledger Tareas 8 y 10). |
| D-3 | La insignia "agente" en la bitácora se infiere de los perfiles actuales del autor: es una pista visual, no evidencia. La evidencia es `Grant.source` (servidor). | Aceptado (ledger Tarea 9). |
| D-4 | CSRF: GLPI 12 lo aplica en el kernel (`CheckCsrfListener`/`CsrfChecker`: Sec-Fetch-Site/Origin) para todo front de plugin; no se usa `csrf_token()`. Las plantillas de pestañas de puestos/roles todavía llaman `csrf_token()` (aviso de deprecación, menor). | Aceptado. |
| D-5 | Vista limitada del dueño en la matriz: sin `expected`/`complete`/`missing` ni titulares "faltantes", y solo las asignaciones (persona, puesto) que justifican u objetan un otorgamiento visible. | Aceptado (ledger Tarea 11, Ruling I-2); verificado W3/W4. |
| D-6 | Todas las decisiones de seguridad descansan en bits de derecho; `activeRoleKey()` solo para UX/procedencia. Las reglas del agente en `GrantRules` son defensa en profundidad. | Aceptado (ledger Tarea 3). |
| D-7 | Purga del catálogo: recursos, roles y puestos con otorgamientos, asignaciones, celdas o notas no se purgan (papelera/desactivación). | Aceptado (ledger Tareas 3, 5, 6, 9). |
| M-* | Menores diferidos con impacto de seguridad: acciones de CI con tags mutables (fijar a SHA), semgrep `new\s+\$` textual, carrera en "primario duplicado", alta de puesto sin `entities_id` validada contra la entidad 0 por API, `Role::getSystemSQLCriteria` dependiente de la sesión (cron 1.1). | Para la revisión final. |

## Test log

### Revisión 3 - recurso vinculado a un elemento de inventario eliminado (Tarea 6)

Entorno: GLPI 12.0.2 en 192.168.88.4, entidad Finandina (id 1), sesión Super-Admin.

1. Se creó el Software descartable id 1410 ("Disposable test software (IAM T6)") y el recurso id 2 apuntando a él.
2. Se envió el Software a la papelera (API, `is_deleted=1`): el formulario del recurso responde HTTP 200 y muestra la
   insignia "Elemento vinculado eliminado".
3. Se purgó el Software (`force_purge`): la fila ya no existe.
4. Resultado tras la purga:
   - Formulario del recurso (`front/resource.form.php?id=2` y su pestaña principal): HTTP 200 con la insignia
     "Elemento vinculado eliminado".
   - `GET /apirest.php/GlpiPlugin%5CIam%5CResource/2`: HTTP 200 con el JSON del recurso (`items_id` 1410 conservado).
   - `GET /apirest.php/GlpiPlugin%5CIam%5CResource`: HTTP 200.
   - `/var/log/glpi/php-errors.log`: sin entradas nuevas (tamaño sin cambios durante todas las pruebas).
5. La matriz de accesos (Tarea 11) debe repetir esta comprobación cuando exista.

### Otras comprobaciones de la Tarea 6

| Prueba | Resultado |
| --- | --- |
| Recurso con `itemtype` = User | Rechazado, sin fila |
| Propietario (usuario 28, fuera de alcance) | Rechazado, sin fila |
| `criticality` inválida / `level` de rol inválido | Rechazados |
| `entities_id` del rol enviado por el cliente | Ignorado: siempre la entidad del recurso |
| Actualizar `plugin_iam_resources_id` / `entities_id` de un rol o `entities_id` de un recurso | Ignorado (inmutables) |
| Purga de un recurso en la papelera con rol que tiene un otorgamiento (fila ficticia, eliminada luego) | Rechazada, el recurso sigue existiendo |
| Purga de un rol con otorgamiento | Rechazada |
| Purga de un rol sin otorgamientos | Permitida |
| Sesión con perfil "IAM - Dueño de activo" (usuario 12, grupos 2 y 3) | Lista solo los recursos de sus grupos; el recurso 3 (grupo 5) responde 403; no puede crear ni editar roles |
| Pestaña "Accesos (IAM)" en el Software 1395 | Lista el recurso 1 con sus roles y otorgamientos |

### Revisión 4 - notas permanentes: solo inserción (Tarea 9)

Entorno: GLPI 12.0.2 en 192.168.88.4, árbol de la Tarea 9 desplegado y caché limpiada. Usuarios temporales (borrados al
final): auditor (perfil "IAM - Auditor", entidad 1), dueño (perfil "IAM - Dueño de activo", entidad 1, miembro del grupo
3 = dueño del recurso 1), analista de la entidad 2 y agente (perfil "IAM - Agente", entidad 1).

**Super-Admin por API sobre la nota 1** (otorgamiento 2). Fila antes y después de los intentos:

```
SELECT id,itemtype,items_id,entities_id,users_id,md5(content),plugin_iam_notes_id,date_creation
  FROM glpi_plugin_iam_notes WHERE id=1;
antes:   1 | GlpiPlugin\Iam\Grant | 2 | 1 | 2 | 2afc8845f07f1b730022631823bc6ab1 | 0 | 2026-11-22 10:58:49
después: 1 | GlpiPlugin\Iam\Grant | 2 | 1 | 2 | 2afc8845f07f1b730022631823bc6ab1 | 0 | 2026-11-22 10:58:49
```

| Intento | Resultado |
| --- | --- |
| `PUT /Note/1` (content, users_id, plugin_iam_notes_id) | HTTP 400 `ERROR_GLPI_UPDATE` "No tenés permiso" |
| `PUT /Note` masivo `[{id:1}]` | HTTP 400, `{"1": false}` |
| `DELETE /Note/1` | HTTP 400 `ERROR_GLPI_DELETE` |
| `DELETE /Note/1?force_purge=1` | HTTP 400 `ERROR_GLPI_DELETE` |
| `DELETE /Note` masivo con `force_purge` | HTTP 400, `{"1": false}` |
| Capa de clase (CLI como Super-Admin): `update()`, `delete()`, `delete(force)` | `false`; `can(1, UPDATE/PURGE)` `false` |
| Acciones masivas de Note | ninguna (prohibidas update, delete, purge, restore, clone, transfer, amend_comment, add_note) |
| `front/note.form.php`: GET, POST `update`/`delete`/`purge` | HTTP 403 |
| POST de alta con `Sec-Fetch-Site: cross-site` o `Origin` ajeno | HTTP 403 (CSRF de GLPI 12) |

La fila no cambió y la tabla conservó todas las notas. El mismo rechazo se obtuvo para PUT y DELETE con `force_purge`
con las sesiones de auditor, dueño y analista de la entidad 2, y para PUT con la del agente.

**Alta y reglas**

| Prueba | Resultado |
| --- | --- |
| Alta por API en otorgamiento 2, recurso 1 y asignación 1 (admin) | 201; `entities_id` = la del objetivo (1), `users_id` = sesión, fecha del servidor |
| Alta con `users_id=99`, `entities_id=2`, `date_creation=2000-01-01`, `id=500` | Ignorados (users_id 2, entidad 1, fecha actual, id 1) |
| Corrección en el otorgamiento 2 que referencia la nota 1 | 201, `plugin_iam_notes_id=1`; la pestaña muestra "corrige la entrada #1" |
| Referencia a una nota de otro objetivo / inexistente | 400 "La entrada corregida no existe o pertenece a otro elemento." |
| `itemtype` = User, en minúsculas, o elemento inexistente | 400 "No tenés permiso" |
| Contenido vacío / 10001 caracteres / 10000 caracteres | Rechazado / rechazado (`content_too_long`) / aceptado |
| Alta por formulario web (recurso 1, corrección de la nota 2, texto multilínea) | 302 al recurso; fila creada |
| Contenido con `<b>` y `<script>` | Mostrado escapado (`&lt;script&gt;`), saltos de línea como `<br />` |
| Auditor: alta en cualquier objetivo (API y web) | Rechazada; ve las notas, la pestaña no ofrece formulario |
| Dueño: alta en otorgamiento 2 (recurso propio) y en el recurso 1 (API y web) | 201 / 302 |
| Dueño: alta en otorgamiento 4 (recurso 3, de otro grupo) o en la asignación 1 | Rechazada (API 400, web 403) |
| Agente: alta en otorgamiento 2 | 201; la pestaña muestra la insignia "agente" |

**Visibilidad de listas** (`GET /Note` y `search/Note`):

| Sesión | Notas listadas |
| --- | --- |
| Super-Admin (raíz recursiva) | 1-8 (todas) |
| Auditor (entidad 1) | 1-8 |
| Dueño (entidad 1, grupo 3) | 1, 2, 4, 5, 6, 7 (no la 3, de una asignación, ni la 8, del otorgamiento 4 de otro dueño); `GET /Note/3` 403 |
| Analista de la entidad 2 | ninguna (`[]`, `totalcount` 0); `GET /Note/1..3` 403 |

Pestaña "Bitácora (IAM)": HTTP 200 en otorgamiento, recurso y página de la asignación para admin y auditor; 403 para el
dueño en el otorgamiento 4 y en la asignación. `/var/log/glpi/php-errors.log` sin entradas nuevas.

**Corrección (revisión de la Tarea 9): un recurso con notas no se purga.** `Resource::dependencyCount()` cuenta también
las notas del recurso. Recurso 4 ("Recurso solo con nota (demo IAM T9 fix)", sin roles ni otorgamientos) con la nota 12:

| Intento (Super-Admin) | Resultado |
| --- | --- |
| `DELETE /Resource/4?force_purge=1` (activo) | HTTP 400 `ERROR_GLPI_DELETE` |
| `DELETE /Resource/4` (papelera) | HTTP 200, `is_deleted=1` |
| `DELETE /Resource/4?force_purge=1` (en la papelera) | HTTP 400 |
| POST `purge` en `front/resource.form.php` | HTTP 403 |
| Capa de clase: `delete(['id' => 4], true)` | `false`, mensaje "El recurso tiene otorgamientos, celdas de matriz o entradas de bitácora (no se borra nada). Envíelo a la papelera." |

El recurso 4 sigue en la papelera y la nota 12 sigue legible. Los roles no son objetivo de notas (sin cambios en
`Role`); otorgamientos y asignaciones nunca se purgan.

### Revisión 5 - visibilidad consolidada y recursos recursivos de la entidad padre (Tarea 10)

Cambio: `plugin_iam_addDefaultWhere` delega en `Scope::criteriaFor()`, único punto de entrada; cada clase conserva su
predicado (`visibilityCriteria()`), que es la forma SQL de su `canViewItem()`. `Role` y `Position_Role` pasan a
`isEntityAssign() = false` (precedente de `Grant`): sus tablas no tienen `is_recursive`, y el filtro de entidad de GLPI
ocultaba desde una entidad hija los roles y celdas de un recurso recursivo de la entidad padre aunque `GET` del
elemento respondiera 200. Predicados:

- Rol: su recurso es visible (`Resource::visibilityCriteria()`: entidades activas con recursión y, sin CONFIG READ,
  propiedad del usuario o de su grupo actual). Se aplica también a los desplegables de roles (`getSystemSQLCriteria()`).
- Celda de matriz: el puesto es visible (con recursión) y el recurso del rol es visible.
- Puesto: sin cambios; el filtro recursivo de GLPI coincide con `canViewItem()` (`checkEntity(true)`).
- Recurso, otorgamiento, nota y asignación: sin cambios de predicado.

Prueba pura de paridad (`ScopeTest`): toda tabla de `Schema::scope()` con clase en 1.0 está cubierta por
`Scope::criteriaFor()` y las tablas de tareas posteriores no tienen clase todavía.

Entorno: árbol de la Tarea 10 en 192.168.88.4, caché limpiada. Datos creados (se conservan): recurso 5 "Correo
corporativo (demo IAM T10, raiz recursivo)" en la entidad raíz (0), recursivo, grupo dueño 5; rol 7 "Buzon (demo IAM
T10)"; celda 9 (puesto 2 de la entidad 1 × rol 7, `allowed`, entidad 0). Usuarios temporales (borrados al final):
analista de la entidad 1, dueño (entidad 1, grupo 3), analista de la entidad 2 y auditor (entidad 1), todos sin
recursión. Listas por API (`GET /<itemtype>` y `search/<itemtype>`), mismo script antes (árbol anterior) y después:

| Sesión | Antes | Después |
| --- | --- | --- |
| Analista entidad 1 | Roles 1,3,4,6; celdas 4,5,6 (`GET Role/7` y `GET Position_Role/9` = 200) | Roles 1,3,4,6,**7**; celdas 4,5,6,**9** |
| Auditor entidad 1 | Roles 1,3,4,6; celdas 4,5,6 | Roles 1,3,4,6,**7**; celdas 4,5,6,**9** |
| Analista entidad 2 | Recursos 5; roles ninguno (`GET Role/7` = 200); celdas ninguna | Roles **7**; celdas ninguna (el puesto 2 es de la entidad 1; `GET Position_Role/9` = 403) |
| Dueño (grupo 3) | Recursos 1; roles 1,3,4; celdas 4,5,6; otorgamientos 2,3,5,6,7; notas 1,2,4,5,6,7,9,10,11; `GET` de recurso 5 / rol 7 / celda 9 = 403 | Idéntico |
| Super-Admin | Todo | Idéntico |

Sin otras diferencias: recursos, otorgamientos, notas, puestos y asignaciones listan exactamente lo mismo antes y
después en las cinco sesiones.

Desplegable de roles del alta de otorgamiento (`ajax/getDropdownValue.php` con el token IDOR del formulario), analista
de la entidad 1 sobre el recurso 5: antes `count 0` (GLPI recibía `entity_restrict` vacío porque la entidad 0 no está
activa); después ofrece el rol 7. Sobre el recurso 1 sigue ofreciendo los roles 1, 3 y 4.

`/var/log/glpi/php-errors.log` sin entradas nuevas (1386 líneas antes y después). Usuarios temporales 43-46 y sus
filas de perfiles y grupos borrados (verificado 0).

### Revisión 6 - verificación de autorización por perfil, API y web (Tarea 13)

Entorno: GLPI 12.0.2 en 192.168.88.4, árbol de `feat/1.0` en 80443c2 desplegado (sumas md5 de `src/`, `front/`,
`ajax/`, `templates/`, `hook.php` y `setup.php` idénticas al repositorio), datos de demo de la Tarea 15 y
`demo_iam.php --profiles` re-ejecutado con el nuevo usuario `iam.clinica` (perfil IAM - Analista solo en la entidad 2,
Clínica Del Valle, sin recursión; contraseñas y tokens rotados, fuera del repositorio).

Herramienta: `tests/Integration/api_authz.py` (Python 3, solo stdlib; ver `tests/Integration/README.md`). Usuarios:
`iam.analista`, `iam.dueno` (grupo 8, dueño de SAP-FI), `iam.auditor`, `iam.agente`, `iam.tecnico` (perfil por defecto
Self-Service y perfil Technician), `iam.clinica` y un Super-Admin. Casos web con sesión de cookies (formulario de login
de GLPI 12, cambio de perfil por `POST /Session/ChangeProfile`).

Hallazgos:

1. **R-1 (FAIL F4; corregido en la Revisión 7):** tras quitar a `iam.dueno` del grupo dueño, la misma sesión de API sigue viendo el recurso
   7 y sus 10 otorgamientos; la sesión web y una sesión de API nueva ya reciben 403. Reproducción: sesión de API del
   dueño (`initSession` + `changeActiveProfile` 16) → `GET Resource/7` 200; Super-Admin `DELETE /Group_User/<id>?force_purge=1`
   (usuario 48, grupo 8); esperar 1 s; misma sesión del dueño `GET Resource/7` → 200 (esperado 403). La membresía se
   restauró en el bloque `finally` (nuevo `Group_User`, mismas banderas) y se verificó.
2. **R-2 (XFAIL B1; corregido en la Revisión 7):** Super-Admin purga un puesto con un hijo: HTTP 200, el hijo pasa a la raíz. El Analista no puede
   purgar puestos (sin PURGE en CONFIG, B0).
3. El resto (77 casos) pasa: técnico sin acceso por API ni web y sin menú (cierra el pendiente de la Tarea 5), dueño
   limitado a sus recursos y sin datos de "faltantes" en la matriz, servicio compartido (otorgamiento 54) visible solo
   desde la entidad del recurso, analista de la entidad 2 sin filas de Finandina en los 7 itemtypes, auditor solo
   lectura, agente sin activar sin ticket ni revocar, notas inalterables también para Super-Admin, `itemtype=User`
   rechazado e inyección en `searchText` inocua.

Efectos sobre los datos (append-only): cada ejecución agrega un otorgamiento `source=agent` (justificación
`[iam-authz] T13 run ...`) y una nota; en esta revisión se ejecutó 3 veces (otorgamientos 10058-10060, notas 26-28) más
una prueba de depuración de puestos temporales (purgados). Los puestos temporales de cada ejecución se purgan.

Salida de la ejecución final (sin secretos):

```
case                                         user                               expected                           got                                          result
------------------------------------------------------------------------------------------------------------------------------------------------------------------------
T1 list Resource                             iam.tecnico/Technician             401/403 or []                      403                                          PASS
T1 list Role                                 iam.tecnico/Technician             401/403 or []                      403                                          PASS
T1 list Position                             iam.tecnico/Technician             401/403 or []                      403                                          PASS
T1 list Position_Role                        iam.tecnico/Technician             401/403 or []                      403                                          PASS
T1 list Position_User                        iam.tecnico/Technician             401/403 or []                      403                                          PASS
T1 list Grant                                iam.tecnico/Technician             401/403 or []                      403                                          PASS
T1 list Note                                 iam.tecnico/Technician             401/403 or []                      403                                          PASS
T2 GET Grant/10                              iam.tecnico/Technician             401/403/404                        403                                          PASS
T1 list Resource                             iam.tecnico/default                401/403 or []                      403                                          PASS
T1 list Role                                 iam.tecnico/default                401/403 or []                      403                                          PASS
T1 list Position                             iam.tecnico/default                401/403 or []                      403                                          PASS
T1 list Position_Role                        iam.tecnico/default                401/403 or []                      403                                          PASS
T1 list Position_User                        iam.tecnico/default                401/403 or []                      403                                          PASS
T1 list Grant                                iam.tecnico/default                401/403 or []                      403                                          PASS
T1 list Note                                 iam.tecnico/default                401/403 or []                      403                                          PASS
T2 GET Grant/10                              iam.tecnico/default                401/403/404                        403                                          PASS
O1 list Grant = grants of owned resources [7 iam.dueno                          ids == 10,31,32,33,34,35,36,37...( ids=10,31,32,33,34,35,36,37...(10) foreign=[ PASS
O2 GET Grant/22 (other owner)                iam.dueno                          403/404                            403                                          PASS
O3 GET Grant/10 (own resource)               iam.dueno                          200                                200                                          PASS
O4 PUT Grant/10 users_id                     iam.dueno                          users_id unchanged                 HTTP 200 users_id 17->17                     PASS
O5 GET Resource/7                            iam.dueno                          200                                200                                          PASS
O5 GET Resource/6                            iam.dueno                          403                                403                                          PASS
F2 GET Grant/54 + in list                    iam.clinica (entity 2)             200, listed                        200 listed=True                              PASS
F2 GET Grant/54 + in list                    iam.analista (entity 1)            403/404, not listed                403 listed=False                             PASS
F2 GET Grant/54 + in list                    iam.dueno (entity 1, not owner of  403/404, not listed                403 listed=False                             PASS
E1 list Resource: no entity-1 rows           iam.clinica                        no entities_id=1                   HTTP 200 rows=3 entity1=                     PASS
E1 list Role: no entity-1 rows               iam.clinica                        no entities_id=1                   HTTP 200 rows=6 entity1=                     PASS
E1 list Position: no entity-1 rows           iam.clinica                        no entities_id=1                   HTTP 200 rows=5 entity1=                     PASS
E1 list Position_Role: no entity-1 rows      iam.clinica                        no entities_id=1                   HTTP 200 rows=11 entity1=                    PASS
E1 list Position_User: no entity-1 rows      iam.clinica                        no entities_id=1                   HTTP 200 rows=4 entity1=                     PASS
E1 list Grant: no entity-1 rows              iam.clinica                        no entities_id=1                   HTTP 200 rows=6 entity1=                     PASS
E1 list Note: no entity-1 rows               iam.clinica                        no entities_id=1                   HTTP 200 rows=2 entity1=                     PASS
E1 list Grant: own entity visible            iam.clinica                        entity-2 grants listed             rows=6                                       PASS
E2 POST Grant on Finandina resource          iam.clinica                        refused                            HTTP 400 id=None                             PASS
E3 GET Resource/6 (Finandina)                iam.clinica                        403/404                            403                                          PASS
A1 POST Grant                                iam.auditor                        refused                            HTTP 400 id=None                             PASS
A2 GET Grant list + Grant/22                 iam.auditor                        200, rows>0                        HTTP 200 rows=52 GET=200                     PASS
G1 POST Grant without ticket                 iam.agente                         refused                            HTTP 400 id=None                             PASS
G2 POST Grant with ticket                    iam.agente                         201, source=agent                  HTTP 201 id=10060 source=agent               PASS
G3 PUT Grant status=revoked                  iam.agente                         refused, status active             HTTP 400 status=active                       PASS
G4 POST Note on its grant                    iam.agente                         201                                HTTP 201 id=28                               PASS
N1 PUT Note/28                               iam.agente                         refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 DELETE Note/28                            iam.agente                         refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 DELETE force_purge Note/28                iam.agente                         refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 PUT Note/28                               iam.analista                       refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 DELETE Note/28                            iam.analista                       refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 DELETE force_purge Note/28                iam.analista                       refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 PUT Note/28                               glpi (Super-Admin)                 refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 DELETE Note/28                            glpi (Super-Admin)                 refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 DELETE force_purge Note/28                glpi (Super-Admin)                 refused, row unchanged             HTTP 400 unchanged=True                      PASS
X1 POST Resource itemtype=User               iam.analista                       refused                            HTTP 400 id=None                             PASS
X1 POST Resource itemtype=User               admin                              refused                            HTTP 400 id=None                             PASS
X2 GET Grant searchText injection            iam.analista                       200/206, 0 extra rows              HTTP 200 rows=0 (baseline 53)                PASS
X2 GET Grant searchText injection            iam.dueno                          200/206, 0 extra rows              HTTP 200 rows=0 (baseline 10)                PASS
F4 before removal GET Resource/7             iam.dueno                          200                                200                                          PASS
F4 before removal web resource form          iam.dueno (web)                    200                                200                                          PASS
F4 admin removes iam.dueno from group 8      admin                              200                                200                                          PASS
F4 next request after removal                iam.dueno                          Resource 403/404, no SAP-FI grants GET=200 sapfi_grants=10                      FAIL
F4 GET Grant/10 after removal                iam.dueno                          403/404                            200                                          FAIL
F4 next web request after removal            iam.dueno (web)                    403                                403                                          PASS
F4 new API session after removal             iam.dueno (new API session)        403/404                            403                                          PASS
F4 admin restores the membership (finally)   admin                              201                                201                                          PASS
F4 after restore GET Resource/7              iam.dueno (new API session + web)  200, 200                           200, 200                                     PASS
B0 purge Position (analyst: no CONFIG PURGE) iam.analista                       refused, parent kept               HTTP 400 parent_exists=True                  PASS
B1 cleanup temporary positions               admin                              purged                             left=[]                                      PASS
W0 central page has IAM menu (control)       iam.analista                       menu present                       HTTP 200 menu=True                           PASS
W0 matrix SAP-FI has expected counts (contro iam.analista                       members=true, missing cells>0      HTTP 200 members=True missing_cells=23:11,15 PASS
W0 matrixcell lists missing holders (control iam.analista                       iam-chip-miss present              cells=23:11,15:11                            PASS
W1 no IAM menu (default profile)             iam.tecnico                        menu absent                        HTTP 200 menu=False                          PASS
W1 no IAM menu (Technician profile)          iam.tecnico                        menu absent                        profile=200 HTTP 200 menu=False              PASS
W2 front/matrix.php                          iam.tecnico/Technician             403                                403                                          PASS
W2 front/search.php                          iam.tecnico/Technician             403                                403                                          PASS
W2 ajax/matrixcell.php                       iam.tecnico/Technician             403                                403                                          PASS
W2 front/grant.php                           iam.tecnico/Technician             403                                403                                          PASS
W2 front/resource.php                        iam.tecnico/Technician             403                                403                                          PASS
W2 front/position.php                        iam.tecnico/Technician             403                                403                                          PASS
W2 front/grant.form.php                      iam.tecnico/Technician             403                                403                                          PASS
W3 owner matrix: no expected/missing data    iam.dueno                          members=false, no expected, no iam HTTP 200 members=False expected_cells=0 iam- PASS
W4 owner matrixcell on cells with missing pe iam.dueno                          no iam-chip-miss                   cells=2 leaks=[]                             PASS

Known plugin bugs (XFAIL: expected to fail until fixed; XPASS means the bug is fixed)
B1 purge Position with a child position      glpi (Super-Admin)                 refused, parent kept               HTTP 200 parent_exists=False child.parent=0  XFAIL

PASS 77  FAIL 2  XFAIL 1  XPASS 0
```

### Revisión 7 - ronda de corrección 1 (Tarea 13): grupos actuales y purga de puestos con subpuestos

Cambios: `Rights::currentGroupIds()` + `GroupMembership::expand()` reemplazan `$_SESSION['glpigroups']` en
`Resource`, `Grant` y `Note` (R-1); `Position` no se purga con subpuestos (R-2). Desplegado en 192.168.88.4 (md5 de
`src/`, `front/`, `ajax/`, `templates/`, `locales/`, `hook.php`, `setup.php` idénticas al árbol local) y
`bin/console cache:clear`. El caso B1 dejó de ser XFAIL y es un rechazo esperado. `/var/log/glpi/php-errors.log` sin
entradas del plugin.

Datos agregados por esta ejecución (append-only, por diseño): otorgamiento 10061 y nota 29.

Salida (sin secretos):

```
case                                         user                               expected                           got                                          result
------------------------------------------------------------------------------------------------------------------------------------------------------------------------
T1 list Resource                             iam.tecnico/Technician             401/403 or []                      403                                          PASS
T1 list Role                                 iam.tecnico/Technician             401/403 or []                      403                                          PASS
T1 list Position                             iam.tecnico/Technician             401/403 or []                      403                                          PASS
T1 list Position_Role                        iam.tecnico/Technician             401/403 or []                      403                                          PASS
T1 list Position_User                        iam.tecnico/Technician             401/403 or []                      403                                          PASS
T1 list Grant                                iam.tecnico/Technician             401/403 or []                      403                                          PASS
T1 list Note                                 iam.tecnico/Technician             401/403 or []                      403                                          PASS
T2 GET Grant/10                              iam.tecnico/Technician             401/403/404                        403                                          PASS
T1 list Resource                             iam.tecnico/default                401/403 or []                      403                                          PASS
T1 list Role                                 iam.tecnico/default                401/403 or []                      403                                          PASS
T1 list Position                             iam.tecnico/default                401/403 or []                      403                                          PASS
T1 list Position_Role                        iam.tecnico/default                401/403 or []                      403                                          PASS
T1 list Position_User                        iam.tecnico/default                401/403 or []                      403                                          PASS
T1 list Grant                                iam.tecnico/default                401/403 or []                      403                                          PASS
T1 list Note                                 iam.tecnico/default                401/403 or []                      403                                          PASS
T2 GET Grant/10                              iam.tecnico/default                401/403/404                        403                                          PASS
O1 list Grant = grants of owned resources [7 iam.dueno                          ids == 10,31,32,33,34,35,36,37...( ids=10,31,32,33,34,35,36,37...(10) foreign=[ PASS
O2 GET Grant/22 (other owner)                iam.dueno                          403/404                            403                                          PASS
O3 GET Grant/10 (own resource)               iam.dueno                          200                                200                                          PASS
O4 PUT Grant/10 users_id                     iam.dueno                          users_id unchanged                 HTTP 200 users_id 17->17                     PASS
O5 GET Resource/7                            iam.dueno                          200                                200                                          PASS
O5 GET Resource/6                            iam.dueno                          403                                403                                          PASS
F2 GET Grant/54 + in list                    iam.clinica (entity 2)             200, listed                        200 listed=True                              PASS
F2 GET Grant/54 + in list                    iam.analista (entity 1)            403/404, not listed                403 listed=False                             PASS
F2 GET Grant/54 + in list                    iam.dueno (entity 1, not owner of  403/404, not listed                403 listed=False                             PASS
E1 list Resource: no entity-1 rows           iam.clinica                        no entities_id=1                   HTTP 200 rows=3 entity1=                     PASS
E1 list Role: no entity-1 rows               iam.clinica                        no entities_id=1                   HTTP 200 rows=6 entity1=                     PASS
E1 list Position: no entity-1 rows           iam.clinica                        no entities_id=1                   HTTP 200 rows=5 entity1=                     PASS
E1 list Position_Role: no entity-1 rows      iam.clinica                        no entities_id=1                   HTTP 200 rows=11 entity1=                    PASS
E1 list Position_User: no entity-1 rows      iam.clinica                        no entities_id=1                   HTTP 200 rows=4 entity1=                     PASS
E1 list Grant: no entity-1 rows              iam.clinica                        no entities_id=1                   HTTP 200 rows=6 entity1=                     PASS
E1 list Note: no entity-1 rows               iam.clinica                        no entities_id=1                   HTTP 200 rows=2 entity1=                     PASS
E1 list Grant: own entity visible            iam.clinica                        entity-2 grants listed             rows=6                                       PASS
E2 POST Grant on Finandina resource          iam.clinica                        refused                            HTTP 400 id=None                             PASS
E3 GET Resource/6 (Finandina)                iam.clinica                        403/404                            403                                          PASS
A1 POST Grant                                iam.auditor                        refused                            HTTP 400 id=None                             PASS
A2 GET Grant list + Grant/22                 iam.auditor                        200, rows>0                        HTTP 200 rows=53 GET=200                     PASS
G1 POST Grant without ticket                 iam.agente                         refused                            HTTP 400 id=None                             PASS
G2 POST Grant with ticket                    iam.agente                         201, source=agent                  HTTP 201 id=10061 source=agent               PASS
G3 PUT Grant status=revoked                  iam.agente                         refused, status active             HTTP 400 status=active                       PASS
G4 POST Note on its grant                    iam.agente                         201                                HTTP 201 id=29                               PASS
N1 PUT Note/29                               iam.agente                         refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 DELETE Note/29                            iam.agente                         refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 DELETE force_purge Note/29                iam.agente                         refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 PUT Note/29                               iam.analista                       refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 DELETE Note/29                            iam.analista                       refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 DELETE force_purge Note/29                iam.analista                       refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 PUT Note/29                               glpi (Super-Admin)                 refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 DELETE Note/29                            glpi (Super-Admin)                 refused, row unchanged             HTTP 400 unchanged=True                      PASS
N1 DELETE force_purge Note/29                glpi (Super-Admin)                 refused, row unchanged             HTTP 400 unchanged=True                      PASS
X1 POST Resource itemtype=User               iam.analista                       refused                            HTTP 400 id=None                             PASS
X1 POST Resource itemtype=User               admin                              refused                            HTTP 400 id=None                             PASS
X2 GET Grant searchText injection            iam.analista                       200/206, 0 extra rows              HTTP 200 rows=0 (baseline 54)                PASS
X2 GET Grant searchText injection            iam.dueno                          200/206, 0 extra rows              HTTP 200 rows=0 (baseline 10)                PASS
F4 before removal GET Resource/7             iam.dueno                          200                                200                                          PASS
F4 before removal web resource form          iam.dueno (web)                    200                                200                                          PASS
F4 admin removes iam.dueno from group 8      admin                              200                                200                                          PASS
F4 next request after removal                iam.dueno                          Resource 403/404, no SAP-FI grants GET=403 sapfi_grants=0                       PASS
F4 GET Grant/10 after removal                iam.dueno                          403/404                            403                                          PASS
F4 next web request after removal            iam.dueno (web)                    403                                403                                          PASS
F4 new API session after removal             iam.dueno (new API session)        403/404                            403                                          PASS
F4 admin restores the membership (finally)   admin                              201                                201                                          PASS
F4 after restore GET Resource/7              iam.dueno (new API session + web)  200, 200                           200, 200                                     PASS
B0 purge Position (analyst: no CONFIG PURGE) iam.analista                       refused, parent kept               HTTP 400 parent_exists=True                  PASS
B1 purge Position with a child position      glpi (Super-Admin)                 refused, parent kept, child unchan HTTP 400 parent_exists=True child.parent=277 PASS
B1 cleanup temporary positions               admin                              purged                             left=[]                                      PASS
W0 central page has IAM menu (control)       iam.analista                       menu present                       HTTP 200 menu=True                           PASS
W0 matrix SAP-FI has expected counts (contro iam.analista                       members=true, missing cells>0      HTTP 200 members=True missing_cells=23:11,15 PASS
W0 matrixcell lists missing holders (control iam.analista                       iam-chip-miss present              cells=23:11,15:11                            PASS
W1 no IAM menu (default profile)             iam.tecnico                        menu absent                        HTTP 200 menu=False                          PASS
W1 no IAM menu (Technician profile)          iam.tecnico                        menu absent                        profile=200 HTTP 200 menu=False              PASS
W2 front/matrix.php                          iam.tecnico/Technician             403                                403                                          PASS
W2 front/search.php                          iam.tecnico/Technician             403                                403                                          PASS
W2 ajax/matrixcell.php                       iam.tecnico/Technician             403                                403                                          PASS
W2 front/grant.php                           iam.tecnico/Technician             403                                403                                          PASS
W2 front/resource.php                        iam.tecnico/Technician             403                                403                                          PASS
W2 front/position.php                        iam.tecnico/Technician             403                                403                                          PASS
W2 front/grant.form.php                      iam.tecnico/Technician             403                                403                                          PASS
W3 owner matrix: no expected/missing data    iam.dueno                          members=false, no expected, no iam HTTP 200 members=False expected_cells=0 iam- PASS
W4 owner matrixcell on cells with missing pe iam.dueno                          no iam-chip-miss                   cells=2 leaks=[]                             PASS

PASS 80  FAIL 0  XFAIL 0  XPASS 0
```
