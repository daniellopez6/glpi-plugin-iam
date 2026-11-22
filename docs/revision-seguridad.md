# Revisión de seguridad (OWASP ASVS 4.0 L2)

Documento en construcción: se completa en la Tarea 13. Por ahora solo contiene el registro de pruebas.

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
