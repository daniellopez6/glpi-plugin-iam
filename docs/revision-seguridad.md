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
