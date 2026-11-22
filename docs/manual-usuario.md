# Manual de usuario del plugin IAM (versión 1.0)

IAM es el plugin de GLPI 12 para gobernar **quién tiene acceso a qué**, con el criterio de
ISO/IEC 27001:2022. Registra los puestos de la organización, las personas que los ocupan, los
recursos que se protegen (aplicaciones, equipos, bases de datos), sus roles, lo que cada puesto
espera de cada rol (la matriz) y los accesos que realmente se otorgaron.

El plugin **registra accesos ya otorgados**: el pedido y su aprobación siguen en el ticket de GLPI;
aquí queda la evidencia y se detecta lo que no coincide con lo esperado.

Esta ayuda también está dentro de la aplicación: menú **Gobierno de accesos (IAM) > Ayuda y
glosario**, y en cada pantalla un recuadro plegable «¿Qué es esto?» y ayuda en los campos.

## 1. Conceptos en un minuto

| Concepto | Qué es | Control ISO 27001:2022 |
|---|---|---|
| Puesto | Función de la organización, agrupada en áreas. Una persona puede tener varios (titular, suplencia, temporal). | A.5.15 |
| Recurso | Lo que se protege, enlazado a un elemento del inventario, con dueño (persona o grupo) y criticidad. | A.5.15, A.5.18 |
| Rol | Conjunto de permisos de un recurso, con nivel estándar, sensible o privilegiado. | A.5.15, A.8.2 |
| Matriz | Qué espera cada puesto de cada rol: permitido, a pedido o prohibido. Sin celda no hay expectativa. | A.5.15 |
| Otorgamiento | Un acceso concedido a una persona sobre un rol, con ticket, aprobador, vencimiento y MFA. No se borra: se revoca. | A.5.18, A.5.3 |
| Nota permanente | Entrada de bitácora que nadie puede editar ni borrar. | A.5.18 |

El acceso esperado de una persona es la suma de los roles permitidos de **todos** sus puestos
vigentes. Lo que tiene y no está esperado, o lo que tiene estando prohibido, se marca en la matriz.

## 2. Puesta en marcha (analista, una sola vez)

Sigue este orden:

1. **Puestos.** Menú *Puestos* > *Añadir*. Crea primero las áreas y luego los puestos dentro de
   cada área (el puesto padre es el área).
2. **Asignar personas.** Abre un puesto, pestaña *Asignaciones*, o la ficha de la persona, pestaña
   *Puestos (IAM)*: elige persona o puesto, tipo, principal, fechas y ticket.
3. **Recursos y roles.** Menú *Recursos* > *Añadir*: enlaza el elemento del inventario, indica
   dueño (persona o grupo) y criticidad. Guarda y abre la pestaña *Roles* para crear los roles con su
   nivel.
4. **Matriz.** En *Matriz de accesos*, activa *Modo edición* y define cada celda.
5. **Cargar los accesos que ya existen** desde sus tickets (sección 3.4).
6. **Leer la matriz** y corregir lo que no coincide.

## 3. Analista de accesos

Perfil **IAM - Analista**: ve y configura todo el catálogo y el registro, no revisa ni aprueba.

### 3.1 Definir puestos y asignar personas

- Un puesto puede vincularse a un cargo y a un grupo de GLPI (opcional) y estar *Activo* o no. Un puesto
  con personas asignadas o con sub-puestos no se puede eliminar: desactívalo.
- **Una persona, varios puestos.** Solo un puesto principal vigente a la vez (si no, error
  `primary_duplicate`: «La persona ya tiene un puesto principal activo»).
- **Tipos:** titular, suplencia (cubre a otra persona) o temporal. Usa fechas de inicio y fin.
- **Cambio de puesto:** no se edita la asignación; se cierra con fecha de fin (solo se pueden corregir
  la fecha de fin y el ticket) y se crea la nueva. La historia queda a la vista (alta, cambio y baja,
  A.5.16).
- Cada asignación tiene una página con su registro permanente (pestaña *Bitácora (IAM)*).

### 3.2 Crear recursos y roles

- El **dueño** (persona o grupo) es quien verá y pedirá cambiar los accesos del recurso. Sin dueño nadie
  responde por él. Si el dueño es un grupo, cualquier integrante actúa como dueño y queda registrado
  quién.
- **Criticidad** (baja, media, alta, crítica) y **frecuencia de revisión** (trimestral, semestral,
  anual).
- **Roles:** nombre y nivel. *Estándar* es uso normal; *Sensible* afecta datos o dinero;
  *Privilegiado* administra el sistema; por política debería tener justificación, vencimiento y MFA (A.8.2), pero en 1.0 el plugin no lo bloquea (la 1.1 lo marcará como desvío). Marca
  *Emergencia (break-glass)* en las cuentas de emergencia, que solo se usan cuando falla el procedimiento normal.
- Un rol con otorgamientos o celdas de la matriz no se puede quitar: nada se borra.
- Desde la ficha de un elemento del inventario (pestaña *Accesos (IAM)*) puedes crear o ver su recurso.

### 3.3 Definir la matriz

1. Abre **Matriz de accesos** y activa *Modo edición* (requiere permiso de configuración).
2. Haz clic en un recurso para expandir sus roles y en la celda de un puesto y un rol para fijar la
   expectativa: **Permitido** (esperado), **A pedido** (solo con aprobación del dueño en un ticket),
   **Prohibido** (nunca) o **Sin expectativa** (quita la celda).
3. Cada cambio queda en el historial del puesto y del rol.

Criterio: define pocos roles por puesto; lo que no se prevé se deniega por defecto. Marca como
*Prohibido* lo que contradice la segregación de funciones (A.5.3), por ejemplo cargar proveedores y
liberar pagos.

### 3.4 Registrar un acceso desde un ticket

1. Abre el ticket, pestaña *Otorgamientos (IAM)* y pulsa *Registrar un otorgamiento* (o usa el menú *Otorgamientos* >
   *Añadir*). El ticket y, desde la ficha de la persona, la persona vienen rellenados.
2. Paso 1: elige el **recurso**. Paso 2: completa el formulario.

| Campo | Qué poner |
|---|---|
| Persona | Quien recibe el acceso. No puede ser quien registra (nadie registra su propio acceso). |
| Rol | Solo los del recurso elegido. No cambia después. |
| Fecha de inicio / fin | Vigencia. Por política, los privilegiados deberían tener fin (no se valida en 1.0). |
| Ticket | El ticket donde se pidió y aprobó. Es la evidencia. |
| Aprobador | Quien aprobó (normalmente el dueño). No puede ser la persona ni quien registra. |
| Aprobador de seguridad | Solo para quien tenga ese derecho; se registra siempre a su nombre. |
| Cuenta | Cuenta de Accounts Inventory (si está instalado). Por política, un privilegiado debería usar una cuenta separada (no se valida en 1.0). |
| MFA | Sí, No o No aplica. |
| Estado | Activo (por defecto) o Pendiente. |
| Justificación | Por qué se concede. |

El **origen** (*Manual*, *API* o *Agente*) lo fija el servidor.

**Corregir un otorgamiento.** La persona, el recurso y el rol no se cambian. Revoca el otorgamiento
(estado *Revocado*, con *Motivo de revocación*, obligatorio) y registra uno nuevo; deja una nota
que enlace ambos. Otros campos (fechas, MFA, aprobadores) se pueden corregir y quedan en el historial.

**Estados.** Activo, Pendiente, Revocación pendiente, Modificación pendiente, Revocado y Vencido.
*Revocado* y *Vencido* son finales. Desde *Activo* se puede pasar a *Revocación pendiente*,
*Modificación pendiente*, *Revocado* o *Vencido*; desde las pendientes, a *Activo* o *Revocado*.

**Segregación de funciones.** Nadie registra ni edita su propio acceso; el aprobador no es el
beneficiario ni quien registra; la aprobación de seguridad nunca se atribuye a otra persona.

### 3.5 Leer la matriz y los desvíos

La matriz tiene un puesto por fila y un recurso por columna. Haz clic en un recurso para ver sus roles y
en una celda para ver a las personas en el panel lateral.

| Símbolo | Significado |
|---|---|
| Tilde | **Permitido**: el puesto debe tenerlo. |
| Círculo medio lleno | **A pedido**: solo con aprobación del dueño en un ticket. |
| Círculo con barra | **Prohibido**: el puesto nunca debe tenerlo. |
| Punto | Sin expectativa. |
| `3/4` | De 4 personas esperadas, 3 tienen todo lo esperado. |
| Triángulo con número | Personas con un acceso no previsto por ninguno de sus puestos vigentes. |
| Círculo con barra y número | …incluyendo un acceso prohibido: lo más urgente. |
| Punto con número | Personas a las que les falta un acceso esperado. |
| Escudo | Rol privilegiado (A.8.2). |

La fila **Sin puesto activo** reúne a quienes tienen accesos pero ningún puesto vigente: todos sus
accesos son no previstos. Los filtros permiten limitar por área, recurso, *Solo desvíos* y
*Privilegiados*, y el cuadro de texto filtra puestos y recursos al instante.

Qué hacer con cada situación:

| Situación | Causa probable | Qué hacer |
|---|---|---|
| Acceso no previsto | Falta asignar el puesto, la matriz no lo contempla o el acceso sobra | Revisa el ticket; si es legítimo, ajusta la matriz o el puesto; si no, revoca con motivo |
| Prohibido en poder | Acceso concedido contra la matriz o por un cambio de puesto no cerrado | Revoca con motivo o corrige la matriz con la aprobación que corresponda |
| Acceso faltante | Alta no registrada o acceso nunca otorgado | Registra el otorgamiento si ya existe en el sistema; si no, el ticket de alta sigue abierto |

### 3.6 Notas permanentes

En la pestaña *Bitácora (IAM)* de un otorgamiento, un recurso o una asignación se anota qué se hizo y por qué.
Las entradas no se editan ni se borran, ni siquiera un administrador. Para corregir, agrega otra y
elige cuál corrige. No pegues contraseñas ni datos personales innecesarios.

### 3.7 Búsqueda rápida

Menú *Búsqueda de casos*. Una caja para todo:

| Escribe | Busca |
|---|---|
| `#1234` o `ticket:1234` | Otorgamientos y asignaciones del ticket 1234 |
| `G-123` o `grant:123` | El otorgamiento 123 |
| `EXC-2026-001` | Una excepción (disponible en una versión posterior; hoy lo indica) |
| Cualquier palabra | Personas, recursos y roles por nombre |

Se pueden combinar: `#4567 pérez`. Solo ves lo que tu perfil y tus entidades permiten.

## 4. Dueño de activo

Perfil **IAM - Dueño de activo**: ves únicamente los recursos de los que eres persona dueña o integrante
del grupo dueño, y todo lo que cuelga de ellos.

Tareas habituales:

1. **Ver quién accede a tus recursos.** En la *Matriz de accesos* ves tus recursos y a las personas que
   tienen acceso con su rol. Las personas que *deberían* tener un acceso y no lo tienen solo las ven
   quienes leen todo el registro.
2. **Detectar accesos que ya no corresponden** (cambio de área, fin de proyecto, baja).
3. **Pedir una revocación o modificación.** Abre el otorgamiento, elige *Revocación pendiente* (o
   *Modificación pendiente*) y escribe la **justificación**, obligatoria. No revocas tú: el analista
   ejecuta el cambio en el sistema real y lo cierra con el ticket. Solo puedes pedir sobre otorgamientos
   activos y nunca sobre tu propio acceso.
4. **Dejar notas** cuando una decisión merece explicación.
5. **Buscar casos** por ticket, persona o rol dentro de tus recursos.

No puedes crear ni cambiar puestos, recursos, roles ni la matriz. Las campañas de recertificación
llegan en una versión posterior; mientras tanto revisa tus recursos al menos una vez por trimestre.

## 5. Auditor

Perfil **IAM - Auditor**: lectura de todo el registro y del catálogo.

1. Revisa la *Matriz de accesos* y los totales de la entidad (personas con desvíos, otorgamientos
   desviados, prohibidos en poder, personas con faltantes).
2. Abre un otorgamiento y comprueba ticket, aprobador, justificación, origen, fechas, MFA y el
   historial de cambios (pestaña *Historial* de GLPI).
3. Lee el registro permanente de un otorgamiento, un recurso o una asignación.
4. Comprueba que cada recurso crítico tiene dueño y que los roles privilegiados están identificados.
5. Usa la búsqueda rápida para pedir evidencia sobre un caso concreto.

No puedes cambiar nada. Las entradas del registro son evidencia y no se pueden alterar.

## 6. Perfiles y derechos

Se crean al instalar el plugin y se reconocen por la marca `[iam:clave]` al final del comentario.

| Perfil | Ve | Puede |
|---|---|---|
| IAM - Analista | Todo | Configurar puestos, recursos, roles y matriz; registrar otorgamientos y notas; ver los tickets para registrar desde ellos. No revisa ni aprueba |
| IAM - Dueño de activo | Solo sus recursos | Ver quién accede; pedir revocación o modificación; anotar |
| IAM - Auditor | Todo, solo lectura | Leer registro, catálogo y notas |
| IAM - Agente | Según su entidad | Por API: leer el catálogo, crear otorgamientos con ticket y notas. Nunca aprueba ni revoca. Ver `docs/api-agente.md` |

Un técnico sin derechos IAM no ve el menú ni las pestañas. El menú *Ayuda y glosario* lo ve cualquiera
que pueda abrir alguna pantalla de IAM; muestra primero la guía del rol del perfil activo (si el
perfil no es un perfil IAM, la del analista).

## 7. Varias entidades

La entidad de un otorgamiento es la de su recurso: la visibilidad sigue al dueño de la aplicación, no a
la entidad de la persona. Un analista de una entidad solo ve los recursos y otorgamientos de sus
entidades activas (con subentidades si están incluidas).

## 8. Límites de la versión 1.0

La versión 1.0 incluye catálogos, matriz, otorgamientos, notas permanentes, matriz visual con panel
nominal, búsqueda, perfiles, API para el agente y esta ayuda. **Todavía no incluye:**

- el motor completo de desvíos (la matriz marca accesos no previstos, prohibidos y faltantes, pero sin
  severidad, estados ni tablero de desvíos),
- reglas de segregación de funciones entre roles,
- excepciones (integración con GRC Manager),
- campañas de recertificación y la vista «Mis activos» del dueño,
- reportes y evidencia exportable,
- la validación de los requisitos de A.8.2 para accesos privilegiados (vencimiento, MFA, cuenta separada, aprobación de seguridad): en 1.0 no se validan ni se bloquean; la 1.1 los marcará como desvío,
- el ciclo de vida automático de altas, cambios y bajas, y la importación CSV.

Llegan en las versiones 1.1 a 1.3. Hasta entonces, un desvío se resuelve corrigiendo el acceso o la matriz.

## 9. Preguntas frecuentes

Las preguntas frecuentes completas están en la pantalla *Ayuda y glosario*. Las más pedidas:

- **¿Por qué no puedo borrar un otorgamiento o una nota?** Porque el registro es evidencia de auditoría.
  Se revoca o se corrige con otra entrada.
- **¿Puedo registrar mi propio acceso?** No (segregación de funciones, A.5.3).
- **¿Quién registró este acceso: una persona o el agente?** El campo *Origen* lo dice y lo fija el servidor.
- **¿No veo un recurso, una persona o un otorgamiento?** Depende de tu perfil y entidades; el dueño solo
  ve sus recursos.
