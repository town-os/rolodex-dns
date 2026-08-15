# Diseño y referencia de la API de Rolodex DNS

> Idiomas: [English](DESIGN.md) | [繁體中文](DESIGN.zh-TW.md) | [简体中文](DESIGN.zh-CN.md) | **Español (España)** | [Español (México)](DESIGN.es-MX.md) | [日本語](DESIGN.ja-JP.md)

Rolodex DNS es un servidor DNS de horizonte partido y un resolutor recursivo/reenviador con gestión remota por gRPC. Resuelve iterativamente desde los servidores raíz por defecto, y va cayendo por upstreams cifrados y en claro. Está escrito en Rust y licenciado bajo AGPL-3.0-only.

Este documento es la especificación funcional: arquitectura, semántica de resolución y todas las superficies de gestión (gRPC, CLI, cliente Go, cliente JavaScript, métricas, configuración). Las reglas de desarrollo —cómo cambiar este código y cómo validar un cambio— viven en `CLAUDE.md`. `README.md` es la referencia de cara al usuario, `CONFIGURATION.md` la guía de configuración orientada a tareas, y `CHANGELOG.md` el historial.

## Disposición del código

| Módulo | Responsabilidad |
| ------ | --------------- |
| `src/main.rs` | Arranque del proceso: carga de la configuración, construcción de escuchas (incluido `sync_ingress_listeners`), tareas de fondo (sondas, barrido de concesiones, sonda de recuperación) |
| `src/lib.rs` | Raíz del crate; `#![deny(dead_code)]` / `#![deny(unsafe_code)]` viven aquí y en `main.rs` |
| `src/dns_server.rs` | La ruta de consulta — `resolve_query` y el orden de resolución de abajo, clasificación de origen, reescritura de ingreso, el filtro de respuestas, `handle_query_proto` |
| `src/resolver.rs` | Resolución iterativa desde las raíces: recorrido de delegaciones, selección de servidor, jurisdicción, presupuestos |
| `src/delegation_cache.rs` / `src/record_cache.rs` / `src/key_cache.rs` | Las tres cachés *dentro* del resolutor (zona → servidores de nombres, `(nombre,tipo)` → registros, zona → claves validadas) |
| `src/dns_cache.rs` | La caché de respuestas a nivel de answer, positiva y negativa |
| `src/secure_client.rs` | Upstreams cifrados para el nivel `secure` (DoH `:443`, DoT `:853`) |
| `src/doh_proxy.rs` | Reenvío upstream a través de un proxy HTTP CONNECT / SOCKS5 / DoH |
| `src/dnssec.rs` / `src/dnssec_validate.rs` | Firmar nuestras propias zonas / validar respuestas upstream — deliberadamente no comparten código |
| `src/db.rs` | SQLite: registros, ámbitos, concesiones, claves, material de CA, y las cachés en memoria de zonas/TLD/lista de permitidos reflejadas desde ahí |
| `src/dnsbl.rs` | Consultas DNSBL, clasificación de rechazos, rotación de proveedores |
| `src/dot_server.rs` / `src/doh_server.rs` / `src/doq_server.rs` | Los transportes cifrados |
| `src/tls.rs` | `TlsManager`: carga de certificados, generación autofirmada, recarga |
| `src/acme.rs`, `src/acme_server.rs`, `src/acme_jose.rs`, `src/ca.rs`, `src/portal.rs`, `src/dane.rs` | El emisor ACME, su capa JOSE, la jerarquía de CA, el portal de inscripción y la generación de TLSA |
| `src/dhcp.rs` | Servidor DHCPv4 e IPAM |
| `src/grpc_service.rs` | La implementación de la API de gestión |
| `src/metrics.rs` | El registro Prometheus hecho a mano y el renderizador del formato de exposición en texto |
| `src/config.rs` | Tipos de configuración, valores por defecto, y las validaciones de arranque que rechazan una configuración insegura |
| `src/cidr.rs` / `src/probe.rs` / `src/edns.rs` / `src/ttl_drift.rs` | Clasificación de origen, sondeo de enrutabilidad por familia de direcciones, contexto EDNS, deriva de TTL |
| `src/bin/rolodex-dns-cli.rs` | El cliente de línea de órdenes |

## Resolución DNS

Rolodex DNS sirve consultas DNS sobre UDP, TCP, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH) y DNS-over-QUIC (DoQ) en direcciones de escucha configurables (por defecto `0.0.0.0:53` para UDP/TCP). TCP y DoT usan el enmarcado estándar con prefijo de longitud de 2 bytes. El tamaño máximo de mensaje UDP es de 4096 bytes; el de TCP, 65535 bytes.

### Límites de los transportes de flujo

Las conexiones TCP y DoT están acotadas, porque `dns.bind` es `0.0.0.0:53` por defecto y un escucha sin cota en una interfaz enrutable es un agotamiento de recursos previo a la autenticación: un cliente que conecta y no envía nada retiene una tarea y un descriptor de fichero, y una vez agotados los descriptores `accept` falla para todos.

| Cota | Valor | Se aplica a |
| ---- | ----- | ----------- |
| `TCP_IDLE_TIMEOUT` | 10 s | Esperar el prefijo de longitud del siguiente mensaje |
| `TCP_MESSAGE_TIMEOUT` | 5 s | El cuerpo de un mensaje cuya longitud ya se anunció |
| `TLS_HANDSHAKE_TIMEOUT` | 10 s | Solo DoT: esperar el ClientHello y el resto del saludo |
| `MAX_TCP_CONNECTIONS` | 1024 | Conexiones concurrentes por escucha; una conexión por encima del tope se descarta en el accept |

El tiempo de inactividad se mide desde la **última actividad**, no desde la apertura de la conexión, así que la reutilización de conexión del RFC 7766 funciona: un cliente puede mantener una conexión abierta y enviar muchas consultas por ella. Eso importa más en DoT, donde reconectar cuesta un saludo nuevo. Los tiempos de inactividad y de mensaje están separados porque son afirmaciones distintas: «todavía no tengo nada que decir» es legítimo entre consultas, mientras que un mensaje entregado a medias es un cliente que anunció 65535 bytes y se detuvo.

El tiempo límite del saludo DoT es la cota que el TCP plano no necesita. `acceptor.accept()` espera un ClientHello, así que sin él un `connect()` pelado —sin necesidad de implementación TLS alguna— aparca una tarea antes de que se intercambie DNS, donde un tiempo límite sobre el bucle de lectura DNS nunca llega a aplicarse. DoQ pone `max_idle_timeout` (30 s) a través de Quinn y no necesita equivalente.

### Tipos de registro soportados

**Básicos**: A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR.

**Extendidos**: URI (RFC 7553), SSHFP (RFC 4255), DNAME (RFC 6672), ANAME (alias resuelto en el momento de la consulta), ZONEMD (RFC 9156), TLSA (RFC 6698), CERT (RFC 4398), SVCB y HTTPS (RFC 9460).

**DNSSEC**: DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM.

### Comportamiento de horizonte partido

Las consultas DNS se resuelven en el orden siguiente:

0. **Selección de ámbito** — El ámbito de la consulta se elige a partir del escucha por el que llegó y de su IP de origen (véase Clasificación de origen e imposición de ámbito): una consulta en un escucha de ingreso por TLD pertenece al ámbito propietario de ese escucha para **todos** los nombres; en cualquier otro caso solo las IP de origen dentro de `security.overlay_cidrs` tienen ámbito impuesto (sin unirse ⇒ REFUSED) y todo otro origen resuelve el espacio de nombres global sin ámbito.
1. **Comprobación del ámbito de red** — Si se seleccionó un ámbito, los registros con ámbito de ese ámbito se comprueban primero.
2. **Comprobación de lista de bloqueo en búsqueda inversa** — Si la consulta es una búsqueda de DNS inverso (`in-addr.arpa` o `ip6.arpa`), la IP extraída se comprueba contra las entradas de la lista de bloqueo local, bajo el literal IP o bajo el nombre inverso. Si está listada, se devuelve NXDOMAIN. Los nombres y direcciones en la **lista de permitidos de DNSBL** se saltan este paso por completo — véase Lista de permitidos de DNSBL.
3. **Búsqueda en la base de datos local** — Se consulta la base de datos local por el nombre y el tipo pedidos. Si existen registros, se devuelven de inmediato.
4. **Cadena CNAME** — Si no se encuentra localmente una coincidencia exacta de tipo, se intenta una búsqueda CNAME para el nombre consultado. Si existe un CNAME, se devuelve.
5. **Reserva LAN → ámbito propietario** (solo orígenes sin ámbito) — Para un origen local de confianza (loopback / LAN, `scope_name == None`) cuyo nombre no casó con ningún registro global, si el nombre cae bajo un TLD que posee *algún* ámbito de red (`db::find_tld_owner`), se resuelve a partir de los registros de ese ámbito propietario, de modo que **todos los TLD de red son visibles en la LAN**. Esto corre *después* de la búsqueda global, así que un nombre con doble alojamiento (un registro global con IP de LAN más un registro con ámbito con IP de superposición) sigue devolviendo su valor global orientado a la LAN; solo los nombres que existen únicamente con ámbito (por ejemplo el ápice de zona de una red) se sirven desde el ámbito, con su valor almacenado. Si el ámbito propietario no tiene registro, se consultan los reenviadores pares del TLD, y a falta de eso se devuelve un **NXDOMAIN autoritativo**: un TLD de propiedad privada no se reenvía nunca upstream desde la LAN. (Los pares de superposición no se ven afectados: toman la ruta con ámbito en el paso 1, que separa los TLD propios — un par unido a una red ve solo su propio TLD y recibe NXDOMAIN para el TLD de una red hermana o de otro ámbito.)
6. **Autoridad sobre zona gestionada** — Si el nombre consultado cae bajo una zona que tiene registros en la base de datos local (determinada por las dos últimas etiquetas de cualquier FQDN almacenado), pero el nombre concreto no se encontró, se devuelve un NXDOMAIN autoritativo. Esto evita reenviar consultas por nombres que deberían resolverse internamente. Las zonas también se pueden declarar autoritativas explícitamente con `AddAuthoritativeZone`.

    **Cuentan los registros de cualquier punto de la zona, no solo los del ápice.** Una zona cuyos registros están todos en subdominios (`www.example.com` sin nada en `example.com`) es la forma normal de una zona, y exigir un registro en el ápice desactivaría este paso para la mayoría de ellas: el fallo se reenviaría upstream y la representación interna dejaría de tener prioridad. La consecuencia merece enunciarse con claridad: añadir un solo registro bajo un dominio público hace a este servidor autoritativo para **todo** él, así que `foo.example.com` como sustitución local significa que `www.example.com` responde NXDOMAIN en vez de resolverse desde internet. Ese es el trato del horizonte partido, y es la razón de que la pertenencia a una zona la decida la caché `managed_zones` en vez de re-derivarse por consulta.

    **Los árboles inversos están excluidos.** `in-addr.arpa` e `ip6.arpa` son el caso en el que la heurística de las dos últimas etiquetas no nombra una zona que nadie delegó: las zonas inversas se cortan en `1.168.192.in-addr.arpa` o más corto, nunca en dos etiquetas, así que la heurística siempre deriva el propio `in-addr.arpa.`. Registrar eso convertiría un solo PTR almacenado en la autoridad del **árbol inverso global entero**, dando NXDOMAIN a toda búsqueda `in-addr.arpa` — y con `dns.auto_ptr` activo, un único registro A crea el PTR que lo dispara. Así que la heurística no es meramente agresiva ahí, es incorrecta, y `db::extract_zone_from_name` devuelve `None` para cualquier cosa bajo `in-addr.arpa.` o `ip6.arpa.` — **no** para `arpa.` en general, porque `home.arpa` (RFC 8375) es un dominio de uso especial para exactamente estas redes y ahí la heurística acierta (`foo.home.arpa.` deriva `home.arpa.`, la zona real); excluirlo enviaría un fallo upstream, que es lo que el RFC 8375 §4 prohíbe. Un operador que de verdad opere una zona inversa la declara con `AddAuthoritativeZone`, que casa con el corte de zona real en vez de adivinarlo.

    La caché se mantiene por tanto exacta por ambos extremos: `Database::add_record` inserta la zona, y `Database::remove_records` la retira en cuanto `zone_has_records` informa de que no queda nada en ella ni por debajo. La eliminación es la única ruta que borra registros globales, así que ese es el único sitio por donde podría entrar obsolescencia — y una entrada obsoleta no es inerte, seguiría respondiendo NXDOMAIN por una zona que ya no existe.
7. **Comprobación de DNSBL / lista de bloqueo local** — Antes de cualquier resolución externa, el nombre consultado (solo nombres directos; los inversos los maneja el paso 2) se comprueba contra la lista de bloqueo local y, si DNSBL está activo, contra los proveedores DNSBL (listas de bloqueo de dominios) configurados. Si está listado, se devuelve un NXDOMAIN. Los nombres en la **lista de permitidos de DNSBL** (y todo lo que hay bajo ellos) se saltan este paso por completo — véase Lista de permitidos de DNSBL. Como esto corre después de las comprobaciones locales y de zona gestionada pero antes de la caché upstream y del reenviador, las DNSBL tienen precedencia sobre cualquier respuesta resuelta externamente (reenviada, iterativa o cacheada de upstream), mientras que los registros locales siempre ganan.
8. **Síntesis DNS64** — Si DNS64 está activo y la consulta es de AAAA pero upstream solo existen registros A, se sintetizan registros AAAA usando el prefijo NAT64 configurado.
8.5. **Control de acceso a la recursión** — Antes de que nada alcance el exterior de este servidor (la caché upstream, un proveedor de lista de bloqueo, un reenviador, las raíces), el origen debe estar dentro de `security.recursion_cidrs`; de lo contrario la consulta es REFUSED. Los pasos 1–6 no se ven afectados, así que a un desconocido se le siguen sirviendo los datos de los que este servidor es autoritativo. Véase Control de acceso a la recursión.
9. **Resolución upstream** — Las consultas sin coincidencia van a la ruta upstream seleccionada por `resolution.mode` (véase Resolución upstream): la cadena de niveles `auto` por defecto, iterativa-desde-las-raíces bajo `recursive`, o reenvío simple bajo `forward`. Si todos los niveles/reenviadores fallan, se devuelve SERVFAIL.
10. **Filtro de familia de direcciones** — Antes de que salga la respuesta, se descartan los registros A/AAAA de una familia de direcciones que el equipo no puede enrutar (véase Filtrado de respuestas por familia de direcciones). Esto se aplica a toda respuesta, local o upstream.

Este orden garantiza que la representación interna siempre tenga prioridad sobre el DNS externo, lo que permite superposiciones a nivel de TLD y de dominio que se actualizan en tiempo real conforme el plano de control gRPC modifica registros.

### Soporte de EDNS

El contexto EDNS (RFC 6891) se extrae de las consultas entrantes. El servidor respeta el tamaño máximo de payload del cliente, admite el bit DNSSEC-OK (DO) e incluye registros OPT en las respuestas. Solo se admite EDNS versión 0. Las consultas iterativas salientes llevan su propio OPT con DO puesto cuando la validación DNSSEC está activa — véase Validación DNSSEC del upstream.

### Aleatorización de mayúsculas del QNAME

En las consultas reenviadas se usa la codificación 0x20 como resistencia al envenenamiento de caché DNS. Está activa por defecto y es configurable con `security.qname_case_randomization`.

## Resolución upstream

Los nombres que no se satisfacen localmente se resuelven según la estrategia de la sección de configuración `resolution` (`ResolutionMode` en `src/dns_server.rs`). El fichero de configuración es solo la **semilla de arranque**: el modo se puede cambiar en caliente por gRPC (`SetResolutionMode`/`GetResolutionMode`), porque esta máquina suele ser el único resolutor de la red a la que sirve, y reiniciarla para cambiar una palabra de un fichero es un corte de DNS para todo lo que hay detrás:

| Modo | Comportamiento |
| ---- | -------------- |
| `auto` (por defecto) | La cadena de reserva por niveles de abajo. |
| `recursive` | Iterativa desde los servidores raíz únicamente; no se contacta nunca con un resolutor upstream. |
| `forward` | Reenviar solo a los `forwarders` configurados (el comportamiento heredado). |

### El subárbol `arpa.` no se resuelve nunca fuera de esta máquina

**`arpa.` y todo lo que hay bajo él se responde desde datos locales o no se responde.** Ningún nombre de ese subárbol se envía jamás a un servidor raíz, a un reenviador ni a un upstream cifrado, en ningún modo de resolución. Un nombre sin datos locales recibe **REFUSED**: nos estamos negando a responder por un espacio de nombres, no afirmando que el nombre no exista, que es lo que NXDOMAIN afirmaría.

Los datos locales siguen respondiendo primero, porque la regla es una caída y no un bloqueo: un PTR almacenado, un registro con ámbito, una zona inversa gestionada o autoritativa resuelven exactamente igual que antes. Lo que cambia es qué pasa cuando fallan.

La regla se impone en dos capas independientes, deliberadamente redundantes:

- **La ruta de consulta** (`resolve_query` en `src/dns_server.rs`) rechaza en la frontera entre «datos que esta máquina tiene» y «datos que tendría que ir a buscar» — inmediatamente después de la guarda de resolutor abierto y *antes* de la búsqueda en la caché de respuestas, de modo que una respuesta cacheada mientras estaba en vigor otra política no puede servirse ahora.
- **El resolutor iterativo** (`resolve_inner` en `src/resolver.rs`) rechaza sin enviar un paquete, así que ningún llamante puede usarlo para alcanzar el subárbol, y un destino de CNAME o un nombre de servidor NS sin glue que apunte a `arpa.` queda cubierto por la misma comprobación.

`upstream_resolve` —la única función que envía una consulta fuera de la máquina— lleva la misma compuerta una tercera vez, leída directamente del cable por `wire_question_is_arpa` en vez de re-analizando un mensaje que el llamante ya analizó.

La pertenencia se casa en la **frontera de etiqueta**, nunca como sufijo de cadena: un nombre está en el subárbol si y solo si su etiqueta final es exactamente `arpa`, así que `notarpa.` y `arpa.example.com.` son nombres corrientes y resuelven con normalidad. `resolver::is_arpa_subtree` es el único predicado; su gemelo a nivel de cable responde la misma pregunta sobre bytes sin analizar.

**Esto es lo que hace posible DDR, no lo que lo bloquea.** RFC 9462 hace que un cliente descubra los extremos cifrados de su resolutor preguntándole a ese resolutor por `_dns.resolver.arpa. SVCB` — un nombre dentro del subárbol. Como el rechazo es una caída que se sitúa *por debajo* de toda búsqueda local, una designación que este servidor tiene se responde desde sus propios registros, y una que no tiene se rechaza en lugar de ir a buscarse. Las dos mitades son la propiedad que DDR necesita: el resolutor, y solo el resolutor, responde por su propia designación, y ningún tercero puede aportar una. Una máquina publica su designación almacenando registros SVCB en ese nombre (Town OS lo hace en `RebuildDNS`); una que no publica ninguna no anuncia nada, que es la respuesta correcta y no una avería.

Consecuencias que conviene enunciar con claridad: las búsquedas inversas de direcciones de las que esta máquina no tiene datos dejan de resolver —`dig -x 8.8.8.8` es REFUSED en vez de responderse desde internet— y `ipv4only.arpa` (RFC 7050) se rechaza en vez de responderse, lo que un cliente que descubre NAT64 lee como «aquí no hay NAT64». Servir el árbol inverso como es debido a partir de datos locales es un trabajo aparte, aplazado.

Nada de esto es una decisión de DNSSEC. Como el subárbol no llega nunca al validador, el corte de zona raíz/arpa servido conjuntamente que hacía volver `ipv4only.arpa` como Bogus (los servidores raíz son autoritativos para `arpa.` además de para `.`, así que una consulta cruza dos cortes y el NSEC de la derivación está firmado por `arpa.` mientras el recorrido sigue comprobando contra las claves de la raíz) ya no se puede alcanzar en absoluto — véase Validación DNSSEC del upstream para lo que el validador hace con las derivaciones que *sí* ve.

### La cadena de niveles `auto`

Cuatro niveles, ordenados de más preferido/más fiable a menos. El orden numérico es también el orden de confianza, así que moverse a un índice *menor* es una recuperación y a un índice *mayor* es una degradación:

| Nivel | Nombre | Transporte |
| ----- | ------ | ---------- |
| 0 | roots | Resolución iterativa desde los servidores raíz (`src/resolver.rs`) |
| 1 | secure | DoH (`:443`, preferido) o DoT (`:853`) hacia `resolution.secure_upstreams` (`src/secure_client.rs`) |
| 2 | local | Do53 en claro hacia los `forwarders` configurados (el resolutor local/DHCP) |
| 3 | public | Do53 en claro hacia `resolution.public_fallback`, como último recurso |

La cadena existe para que la resolución sobreviva a redes que filtran el `:53` saliente. DoH se prefiere sobre DoT porque `:443` parece HTTPS corriente y sobrevive al DPI que deja pasar el connect TCP de DoT pero tira la sesión TLS. Los upstreams seguros se marcan **por IP** (`addr`) con el certificado TLS validado contra el `hostname` configurado, así que el nivel no necesita DNS previo; el tiempo límite por upstream es de 1,5 s.

- **Solo respuestas definitivas.** Un nivel «gana» solo si el transporte tuvo éxito y el rcode es NoError o NXDOMAIN. SERVFAIL, REFUSED y las respuestas no analizables caen al siguiente nivel.
- **Nivel activo pegajoso.** El nivel ganador se recuerda, así que las consultas no pagan un tiempo de espera en un nivel muerto cada vez.
- **Degradaciones con periodo de gracia, recuperaciones inmediatas.** Que gane un nivel más preferido cambia de inmediato; una degradación se confirma solo tras `resolution.switch_grace_failures` (3 por defecto) consultas desviadas consecutivas, de modo que una consulta inestable no puede hacer oscilar el nivel.
- **Las consultas de cliente no sondean nunca.** El nivel inicial es siempre el nivel confirmado, sin más. Antes esto elegía una consulta por intervalo para reiniciar en el nivel 0, lo que en una red con `:53` filtrado le cobraba a ese llamante el recorrido iterativo entero antes de caer al nivel que iba a responder de todos modos: un atasco de varios segundos una vez por minuto, que un usuario lee como «el DNS se cuelga» y no como un sondeo.
- **Sonda de recuperación asíncrona.** Una tarea de fondo (`recovery_probe_loop`) reevalúa los niveles por encima del confirmado cada `resolution.recovery_probe_secs` (60 por defecto) con su propio canario desechable. Los resultados se descartan —la sonda mueve el nivel y no responde nada— así que desbordarse no le cuesta la respuesta a ningún cliente.
- **Reclamar el nivel 0 exige DNSSEC.** Las raíces se promocionan solo con una resolución `Verdict::Secure` del propio `DNSKEY` de la zona raíz, no con mera alcanzabilidad. Un middlebox interceptor en `:53` es alcanzable y responde con presteza; sin la compuerta, cualquier red que secuestre el puerto 53 podría instalarse en silencio como el nivel más fiable, desplazando al upstream cifrado al que la máquina había caído correctamente. Una respuesta validada es lo único que semejante middlebox no puede falsificar. Con `dnssec.validate: false` no hay veredicto sobre el que decidir (el resolutor informa `Insecure` de todo por diseño), así que se exige en su lugar una respuesta definitiva; de lo contrario una máquina deliberadamente no validadora no podría usar nunca la recursión.
- **Niveles acotados.** El resolutor iterativo se acota por *número* de consultas, no por tiempo, así que el nivel de raíces lleva además un techo de reloj de pared: 8 s en la ruta de consulta (lo bastante holgado como para no hacer fallar un recorrido en frío legítimamente lento) y 2 s para la sonda de recuperación (una consulta, un servidor, sin delegación que seguir).
- **Vaciado de caché al cambiar.** Todo cambio de nivel confirmado llama antes a `flush_upstream_state()`, así que las respuestas de un nivel no pueden quedarse tras un cambio a otro (una guarda contra envenenamiento de caché entre niveles).
- **Precalentamiento en el arranque.** En modo `auto`, `prewarm_auto` lanza consultas canario al arrancar para que la primera consulta *de cliente* no pague el descubrir que `:53` está filtrado.

### Resolutor iterativo (`src/resolver.rs`)

Recorre la cadena de delegaciones desde las raíces: consulta una raíz, sigue la derivación NS a los servidores del TLD, y luego a los servidores autoritativos de la zona. Las consultas se envían con el bit de recursión deseada apagado; las respuestas se validan por identificador de transacción y por nombre de la pregunta contra la suplantación fuera de ruta; UDP primero, con caída automática a TCP ante truncamiento.

- **Pistas de raíz.** Las 13 direcciones raíz de IANA, solo IPv4 (una sola familia de direcciones evita atascarse en raíces IPv6 desde un equipo solo-v4; el glue puede aun así producir servidores autoritativos IPv6, que se prueban de forma oportunista). Sustituibles con `resolution.root_hints`.
- **Cebado de raíces.** En el arranque (nunca en la ruta de consulta) se pregunta a las raíces quiénes son las raíces, y el conjunto NS vivo de `.` se cachea como una delegación con su TTL real. Las pistas codificadas pasan a ser un arranque y la reserva cuando el cebado falla.
- **Selección de servidor.** El menor `hits * ema_latency`: esto empuja el producto hacia la igualdad en el conjunto de servidores, asignando consultas como `hits ∝ 1/latencia`, de modo que los servidores rápidos cargan más y todo servidor sano carga algo (en vez de que una raíz «la más rápida» lo absorba todo y se gane un límite de tasa). Un servidor no consultado puntúa 0, se prueba primero y aprende su latencia de una consulta que iba a ocurrir de todos modos. La latencia es una EMA (α = 0,3).
- **Retroceso ante fallos.** Se rastrea aparte de la latencia como un retroceso exponencial explícito (2 s, duplicando, topado en 300 s, limpiado al primer éxito). Los servidores en retroceso ordenan detrás de los sanos dentro de su familia de direcciones, pero no se eliminan nunca, así que la resolución sigue avanzando cuando todo está fallando.
- **Jurisdicción.** Una derivación se sigue y se cachea solo si baja **estrictamente** desde la zona que respondió *y* cubre el nombre que se está resolviendo (`referral_in_bailiwick`). Sin ello, cualquier servidor de nombres con el que el resolutor hable puede devolver `AUTHORITY: com. NS <atacante>` para una consulta sobre su propia zona y hacer que se cachee — y como `best_match` recorre sufijos y las delegaciones de TTL largo se persisten en SQLite, eso es una toma de control del resolutor que sobrevive a un reinicio. Una derivación que viole la regla hace fallar la búsqueda en vez de saltarse en silencio, así que una delegación hostil no puede hacerse pasar por progreso. El glue se filtra a nombres dentro de la zona **que responde** y no de la delegada, porque una derivación de la raíz para `com.` lleva legítimamente glue para `a.gtld-servers.net.` — fuera de `com.`, dentro de `.`. Los descartes los cuenta `rolodex_dns_resolver_out_of_bailiwick_total`.
- **Cotas.** 1,5 s de tiempo límite por servidor de nombres (corto para que un `:53` agujereado caiga rápido al nivel seguro), máximo 30 derivaciones, 16 saltos CNAME, profundidad 16, 4 servidores de nombres probados por delegación sin glue, y un tope duro de **64 consultas upstream por búsqueda de cliente**. Los límites por eje se multiplican —una zona que sigue derivando sin glue cuesta `O(4^16)` consultas— así que el total se acota de plano para evitar un DoS/amplificador autoinfligido.

### Cachés del resolutor

Dos cachés se sitúan *dentro* del resolutor, por debajo del `DnsCache` a nivel de answer, y guardan lo que una recursión aprende de bajada en vez de descartarlo:

- **Caché de delegaciones** (`src/delegation_cache.rs`) — zona → direcciones de servidores de nombres, poblada desde toda derivación vista. Se consulta antes de recurrir a las pistas de raíz, así que una búsqueda `.com` en caliente se salta el salto a la raíz por completo (sin ella, todo nombre en frío volvía a recorrer raíz → TLD → autoritativo, machacando una raíz hasta el límite de tasa). Los TTL se honran tal como se publican, topados a 7 días como cota de absurdo, sin suelo; máximo 10 000 zonas en memoria. Las entradas cuyo TTL supera `resolution.delegation_persist_min_ttl` (300 s por defecto) las persiste un trabajador de escritura de fondo en la tabla `delegation_cache` y se recargan al arrancar, así que un reinicio vuelve en caliente — los conjuntos NS de raíz y TLD llevan TTL de varios días, así que en la práctica sobreviven exactamente las entradas que merece la pena conservar.
- **Caché de registros** (`src/record_cache.rs`) — `(nombre, tipo)` → registros, en memoria, para glue, búsquedas de nombres NS sin glue y saltos CNAME. Los registros se devuelven con su vida **restante** (sin ese decaimiento, un registro servido se re-cachearía upstream a TTL completo y un registro de 1 h no caducaría nunca). Topada a 50 000 claves y a un techo de TTL de 7 días.

- **Caché de claves** (`src/key_cache.rs`) — zona → conjunto DNSKEY validado o delegación demostradamente insegura, presente solo cuando la validación DNSSEC está activa. Véase Validación DNSSEC del upstream.

Las tres las vacía `flush_upstream_state()` (cambios de nivel) y **no** `flush_cache()`, que se llama desde toda mutación de registro por gRPC — colgar el estado upstream de las mutaciones de registro significaría que cada alta de paquete borra las delegaciones y recrea la caída de arranque en frío.

### Semántica de TTL

Un TTL que está presente se honra exactamente como se envió. El TTL de una respuesta negativa es el `min(SOA MINIMUM, SOA TTL)` del RFC 2308, sin recortar — recortarlo anularía lo que la zona publicó realmente. `resolution.default_ttl` (300 s por defecto) es la única reserva, usada solo donde nada aporta un TTL utilizable: una respuesta negativa sin SOA, o un registro de delegación/glue con TTL cero.

## Filtrado de respuestas por familia de direcciones

Es habitual que una red anuncie una ruta por defecto IPv6 y sin embargo tire en silencio todo el tráfico v6 (y el caso espejo ocurre en NAT solo-v4). Entregarle a un cliente una dirección de una familia que el equipo no puede enrutar hace que el cliente se atasque en la familia muerta en vez de recurrir a la otra — el fallo que traba las descargas de imágenes de contenedor en un enlace con v6 roto.

Por eso la sonda de `src/probe.rs` prueba la alcanzabilidad *real* de internet por familia con un connect TCP simple a resolutores públicos anycast en `:443` (`:443` porque es el puerto que usa el tráfico real y sobrevive al filtrado de `:53`/`:853`; connect TCP porque no requiere privilegio de socket en crudo). Una familia que el equipo no puede alcanzar se suprime en el filtro de respuestas, que descarta los registros A/AAAA de esa familia y los convierte en NODATA.

- `address_family.mode`: `auto` (sondear y suprimir, por defecto), `off` (responder siempre ambas), `force4`, `force6`.
- En `auto` la primera sonda corre **de forma síncrona en el arranque** y es decisiva sin periodo de gracia, así que un arranque en un enlace con una familia muerta suprime esa familia desde la primerísima consulta; la sonda recurrente corre después desacoplada cada `probe_interval_secs`.
- Una familia que estaba operativa se marca como inalcanzable solo tras `fail_threshold` (2 por defecto) ciclos fallidos consecutivos (amortiguación de oscilaciones); la recuperación es inmediata al primer éxito.

## Base de datos local de registros

Los registros se almacenan en SQLite con el modo WAL activado para el rendimiento de lectura concurrente. La ruta de la base de datos es configurable (por defecto `rolodex-dns.db`). Hay un modo en memoria disponible para pruebas.

El fichero de base de datos se crea **`0600`**, y también sus laterales `-wal`/`-shm`. Es el almacén de claves —la clave privada de la CA raíz, todas las claves intermedias por zona, las claves privadas DNSSEC y los secretos HMAC de EAB son filas planas en él—, así que un usuario local que pueda leer el fichero tiene la clave raíz y puede falsificar un certificado para cualquier nombre en el que confían todos los clientes inscritos. El modo lo pone explícitamente `Database::open` (vía `db::restrict_to_owner`) *antes* de que corra el pragma WAL, porque SQLite copia el modo del fichero principal a los laterales que crea; dejarlo al umask produciría `0644` con el valor común por defecto.

Los nombres de dominio se normalizan a minúsculas con un punto final al almacenarse y al buscarse, lo que da coincidencia insensible a mayúsculas. La base de datos tiene índices sobre `name` y `(name, record_type)`.

Los registros constan de: nombre, tipo de registro, valor, TTL (300 segundos por defecto) y prioridad (usada por MX y SRV).

Los valores SOA se almacenan como `"mname rname serial refresh retry expire minimum"`. Los SRV como `"weight port target"`. Los TLSA como `"usage selector matching_type hex_data"`. Los URI como `"priority weight target_uri"`. Los SSHFP como `"algorithm fp_type hex_fingerprint"`. Los ZONEMD como `"serial scheme hash_algorithm hex_digest"`. Los CERT como `"cert_type key_tag algorithm base64_cert_data"`.

### Registros PTR inversos automáticos

Cuando `dns.auto_ptr` está activo (desactivado por defecto), los registros A y AAAA añadidos o eliminados por la interfaz de gestión gRPC (`AddRecord`/`RemoveRecord` y los con ámbito `AddScopedRecord`/`RemoveScopedRecord`) mantienen automáticamente un registro PTR inverso correspondiente. Añadir un registro A crea el PTR `<octetos-invertidos>.in-addr.arpa.`; añadir un registro AAAA crea el PTR `<nibbles-invertidos>.ip6.arpa.` de 32 nibbles. El PTR lleva el TTL del registro directo y apunta de vuelta al nombre directo (normalizado). Eliminar el registro directo elimina el PTR correspondiente; los registros con ámbito crean/eliminan el PTR dentro del mismo ámbito. A y AAAA se tratan de forma equivalente — la única diferencia es la zona inversa (`in-addr.arpa` frente a `ip6.arpa`). El nombre inverso lo construye `db::reverse_ptr_name`, la inversa del analizador de nombres inversos usado para el bloqueo en búsqueda inversa. Esto es independiente del registro A/PTR propio del servidor DHCP, que sigue siendo solo IPv4.

## Caché de respuestas DNS

Rolodex DNS cachea las respuestas DNS en memoria con respaldo en SQLite para persistir entre reinicios. Una vez cacheadas, las consultas se responden sin contactar con resolutores upstream. Es un diseño deliberadamente centrado en la privacidad, para evitar la fuga de consultas DNS a los proveedores upstream.

- Los **registros locales** se cachean con una bandera `local` — el TTL se devuelve tal cual (sin decaimiento) y las entradas no se persisten en la tabla de caché de SQLite.
- Los **registros upstream** llevan el TTL ajustado según el tiempo de caché restante (decaimiento del TTL).
- Las entradas caducadas se desalojan al accederlas.
- La caché lleva contadores de aciertos y fallos, recuperables con `GetCacheStats`.
- Las claves de caché usan el formato `"nombre:tipo"` o `"nombre:*"`.
- Las **respuestas negativas** (NXDOMAIN/NODATA autoritativos) se guardan en un mapa `negatives` aparte, así que las rutas positivas siguen tratando «sin registros» como un fallo. Su vida es el TTL negativo del RFC 2308 calculado por `Resolution::negative_ttl`. Añadir un registro local para un nombre invalida cualquier negativo cacheado para él (`invalidate_negative`), de modo que un nombre recién añadido no queda ensombrecido hasta que el TTL negativo se agote.
- La persistencia hace upsert sobre un índice único de la clave de caché, así que volver a cachear un nombre actualiza su fila en vez de añadir un duplicado. La caché en disco se carga al arrancar con `cache_load_all`.
- La caché se vacía automáticamente cuando se mutan registros por gRPC (alta, baja o las variantes con ámbito) para garantizar la coherencia. Eso es `flush_cache()`, que limpia respuestas y negativos pero deliberadamente **no** las cachés de delegación/registros del resolutor — esas las vacía solo `flush_upstream_state()` en un cambio de nivel del modo `auto`.
- La caché se puede vaciar explícitamente con `FlushDnsCache`.
- Pon `forwarders: []` y `resolution.mode: forward` para operar como servidor puramente autoritativo sin resolución upstream.

## Lista de bloqueo local

Rolodex DNS mantiene una lista respaldada en la base de datos con los nombres y direcciones que un operador bloqueó a mano. Se comprueba antes de consultar a ningún proveedor, y es la única lista que habla de **direcciones**: a un proveedor se le pregunta por el nombre que se está resolviendo, y en una búsqueda inversa ese es un nombre sobre el que nadie publica reputación.

### Entradas locales

Las entradas locales pueden bloquear nombres o IP concretos con un motivo legible, y se gestionan con `AddLocalBlocklistEntry`, `RemoveLocalBlocklistEntry` y `ListLocalBlocklistEntries`. Se cotejan tanto con las búsquedas de IP por DNS inverso (paso 2) como con los nombres de dominio directos (paso 7), tolerando diferencias de punto final y de mayúsculas en la entrada almacenada. En una búsqueda inversa una entrada casa bajo **cualquiera** de las dos grafías —el literal IP (`192.168.1.100`) o el nombre inverso que imprime `dig -x` (`100.1.168.192.in-addr.arpa`)— porque una entrada que se lee como un bloqueo pero no casa calladamente con nada es peor que una que se rechaza. Todo lo que está en la lista de permitidos de DNSBL está exento también de la lista de bloqueo local, bajo ambas compuertas (véase Lista de permitidos de DNSBL).

## Listas de bloqueo de dominios (DNSBL)

Los proveedores DNSBL bloquean por **nombre de dominio**. Una consulta DNSBL antepone las etiquetas del nombre consultado a la zona del proveedor —por ejemplo `googleadservices.com` contra `dbl.spamhaus.org` se consulta como `googleadservices.com.dbl.spamhaus.org`—, reflejando cómo operan las listas de bloqueo de dominios como Spamhaus DBL, SURBL y URIBL.

DNSBL da a las listas de bloqueo **precedencia sobre el DNS externo**: la comprobación corre después de los registros locales y de las zonas gestionadas/autoritativas (así que los datos internos siempre ganan) pero **antes** de la caché de respuestas upstream y del reenviador/resolutor iterativo. Un nombre listado devuelve por tanto NXDOMAIN incluso si antes se había cacheado una respuesta reenviada. Por ejemplo, con DNSBL activo, `googleadservices.com` se rechaza mientras un `gitea.default.home` definido localmente (por ejemplo plantado por un paquete) sigue resolviendo.

**El bloqueo es por nombre consultado, no por sufijo.** Cada nombre se busca contra el proveedor por derecho propio, así que que `doubleclick.net` esté listado no bloquea por sí solo `stats.g.doubleclick.net` — el proveedor tiene que listar también el subdominio, como hacen las listas de bloqueo de dominios reales. Esto es deliberado y es una decisión del operador: bloquear en silencio todo nombre bajo uno listado se llevaría por delante un dominio entero por un único host listado. Nótese la asimetría con la **lista de permitidos** de DNSBL, que *sí* casa por sufijo, porque una salida de emergencia que no cubriera los subdominios no lo sería.

La comprobación DNSBL se puede conmutar globalmente y está **desactivada por defecto, con una lista de proveedores vacía**; los proveedores se pueden activar de forma independiente. Con ella desactivada no se emite consulta de proveedor alguna, así que los nombres consultados no se entregan al operador de la lista de bloqueo. Las listas de bloqueo de dominios estándar que un operador suele añadir son `dbl.spamhaus.org`, `multi.surbl.org` y `multi.uribl.com`. Un DNSBL activado pero vacío no hace nada (no se consulta nada y no se bloquea nada). Los resultados se guardan en una caché en memoria (los positivos durante el TTL del proveedor, los negativos 5 minutos), con manejo de códigos de rechazo — `dbl.spamhaus.org` responde a una consulta por IP con `127.0.1.255`, que es un error y no un listado (véase Códigos de rechazo y rotación de proveedores). Se configura en el arranque con la sección `dnsbl` y en caliente con `SetDnsblConfig`/`GetDnsblConfig`.

**La alcanzabilidad del `:53` saliente se sondea en bucle, no se da por supuesta** (`DnsblChecker::resolver_availability_loop`, lanzado una vez desde `main.rs`). Una consulta a un proveedor es ella misma una consulta DNS a una zona de terceros, así que en una red que filtra el `:53` saliente todas ellas expiran — y como un error de búsqueda se trata deliberadamente como «no listado», una lista de bloqueo que expira en todos los nombres se ve exactamente igual que una que funciona. Por eso una tarea de fondo sondea la alcanzabilidad real del `:53` saliente cada 60 segundos y aparca el camino de los proveedores cuando desaparece. La tarea se lanza **incondicionalmente** y se apoya en la bandera de activación *en tiempo de ejecución* del comprobador y no en `dnsbl.enabled` del fichero de configuración: condicionar el lanzamiento al fichero hacía que una lista de bloqueo activada después por `SetDnsblConfig` —que es como la programa el controlador de Town OS, que ya no escribe el fichero de configuración en absoluto— no recibiera sondeo alguno, así que la bandera se quedaba en su valor por defecto `true` y toda búsqueda expiraba sin que nada dijera por qué. Mientras la lista de bloqueo está apagada no hay nada que sondear *para*, así que el bucle solo vuelve a leer la bandera, y lo hace cada 5 segundos en vez de cada 60: ese sondeo cuesta una carga atómica en vez de un viaje de ida y vuelta UDP, y acota cuánto espera su primer sondeo una lista de bloqueo activada por gRPC.

### Lista de permitidos de DNSBL

Se pueden eximir máquinas concretas de la comprobación de lista de bloqueo por completo. Las entradas de la lista de permitidos se almacenan en la base de datos (tabla `dnsbl_allowlist`) con un motivo legible y se gestionan con `AddDnsblAllowlistEntry`, `RemoveDnsblAllowlistEntry` y `ListDnsblAllowlistEntries` (CLI: `add-dnsbl-allow`, `remove-dnsbl-allow`, `list-dnsbl-allow`).

- **Coincidencia por sufijo.** Una entrada cubre el nombre en sí *y* todo nombre por debajo de él, así que permitir `example.com` exime también `www.example.com`. La coincidencia es en fronteras de etiqueta — `notexample.com` no queda exento. Las búsquedas son O(etiquetas) contra un `DashSet` en memoria reflejado desde la tabla (cargado al arrancar), la misma técnica usada para la coincidencia de zonas.
- **Normalizada al almacenar.** Las entradas se pasan a minúsculas con un punto final, así que `Example.COM`, `example.com` y `example.com.` son una sola entrada y cualquier grafía la elimina. Una entrada vacía o raíz (`.`) se rechaza: eximiría el espacio de nombres entero.
- **La lista de permitidos gana.** La comprobación cortocircuita el paso 7 por completo: un nombre exento no se comprueba ni contra los proveedores DNSBL configurados ni contra la lista de bloqueo local, así que una entrada de la lista de permitidos es la salida de emergencia del operador ante un falso positivo de cualquiera de las dos. Corre *antes* de la consulta al proveedor, así que un nombre exento no emite consulta de lista de bloqueo alguna.
- **Todas las listas, ambas compuertas.** La lista de permitidos controla la comprobación de nombre directo (paso 7) *y* la comprobación de DNS inverso/IP (paso 2), así que ninguna coincidencia positiva de lista de bloqueo la sobrevive: un proveedor DNSBL y la tabla local están ambos sujetos a la misma exención. Las exenciones se cuentan por qué compuerta se disparó — `rolodex_dns_blocklist_allowlisted_total{kind}` es `forward_name`, `reverse_name` o `ip_literal`, las tres *rutas de coincidencia*, no las tres listas: la comprobación cortocircuita antes de que se emita consulta de proveedor alguna, así que en el momento de la exención no se ha preguntado nada y no hay lista que nombrar. Un falso positivo sobre una dirección es tan real como uno sobre un nombre —una IP mal listada rompe `dig -x` para una máquina que va perfectamente— y una salida de emergencia que cubriera solo algunas de las listas no lo sería.
- **Dos grafías para una dirección.** Una consulta inversa queda exenta por una entrada que nombre bien el nombre `in-addr.arpa`/`ip6.arpa`, bien el literal IP que codifica, así que un operador no tiene que invertir octetos a mano. El **nombre** inverso casa por sufijo como cualquier nombre DNS (permitir `1.168.192.in-addr.arpa` levanta el bloqueo de ese /24 entero); el **literal** IP casa de forma *exacta*, porque una dirección va del octeto más significativo al menos, así que `1.100` no es padre de `192.168.1.100` y tratarlo como tal eximiría direcciones que nadie nombró.
- Añadir o eliminar una entrada surte efecto en la siguiente consulta sin necesidad de vaciar la caché, porque el paso de lista de bloqueo corre por delante de la búsqueda en la caché de respuestas DNS.

## Transportes DNS cifrados

Todos los transportes cifrados son opcionales y requieren configuración TLS. Si no se aporta certificado, se genera automáticamente uno autofirmado cuando `auto_self_signed` es `true` (por defecto).

Un certificado generado lleva siempre `localhost`, `127.0.0.1` y `::1`, y por encima de eso lleva **las direcciones de enlace del propio escucha** más cualquier cosa en `<transport>.tls.self_signed_sans`. Las direcciones de enlace se pliegan automáticamente porque son las identidades que los clientes marcan por construcción: a un escucha en `192.168.1.5:853` se llega como `192.168.1.5`, y un certificado que nombre solo `localhost` falla la comprobación de nombre de todo cliente configurado con un nombre de autenticación, que es la única validación que un certificado autofirmado admite más allá del anclaje de clave pública en crudo. Los enlaces comodín (`0.0.0.0`, `::`) no son identidades y se descartan, así que un escucha en el comodín necesita `self_signed_sans` para nombrar la máquina explícitamente. Los duplicados se pliegan entre grafías (`[::1]` y `::1`, `DNS.Home.` y `dns.home`). Nada de esto se aplica cuando `cert_path`/`key_path` están puestos: ese certificado lleva los nombres para los que fue emitido.

#### Reconfiguración en tiempo de ejecución

**Toda escucha cifrada puede abrirse, moverse, recambiar su clave o apagarse con el servidor en marcha.** `SetDotConfig`, `SetDohConfig` y `SetDoqConfig` registraban su petición y devolvían `success: true` sin haber guardado nada, y un orquestador no podía distinguir eso de que funcionara — así que la única forma de configurar el DNS cifrado era escribir el fichero de configuración y reiniciar, y reiniciar el único resolutor de la máquina es una caída de DNS para todo lo que hay en ella.

`TransportSupervisor` (`src/transports.rs`) posee las escuchas y sus gestores TLS durante toda la vida del proceso, y **el camino de arranque y las RPC son el mismo código**: `main.rs` levanta cada transporte con el mismo `apply()` que llama una RPC. Una configuración que funciona al arrancar la aplica por tanto exactamente el código que aplica una que llega después, y las dos no pueden separarse. El `:53` queda intacto en todo esto — son escuchas independientes.

El orden viene forzado por que una escucha no puede arrancar antes de que la anterior suelte su puerto, así que no hay manera de demostrar que una configuración nueva enlaza antes de renunciar a la vieja:

1. Primero se comprueba todo lo comprobable **sin** el puerto: que la lista de enlaces resuelva, que el material TLS cargue o se genere. Una dirección mal escrita o un certificado ilegible se rechazan con la escucha anterior aún sirviendo.
2. Luego se paran las escuchas viejas **y se esperan**. Abortarlas sin esperarlas hace competir el nuevo enlace con el cierre del socket viejo, y falla con `EADDRINUSE` de forma intermitente.
3. Si aun así el enlace falla, se restaura la configuración anterior y se le dice a quien llamó que el transporte está caído. Informar de éxito ahí dejaría una máquina que se cree sirviendo DoT sin hacerlo.

Una lista de enlaces vacía es un apagado, no un error — es lo que ya significa omitir una sección de configuración. `Get*Config` informa de las direcciones realmente **enlazadas**, que difieren de las pedidas siempre que la petición nombrara el puerto 0. Un servidor construido sin supervisor (los arneses de prueba en proceso) responde `FailedPrecondition` en lugar de afirmar que configuró una escucha que no tiene.

**Se puede nombrar un certificado que aún no se ha emitido.** Que `cert_path`/`key_path` apunten a un fichero ausente solo es fatal cuando `auto_self_signed` está desactivado; con él activado, la escucha arranca con material generado y el sondeo de abajo adopta el par real cuando aterriza. Eso es lo que permite configurar una escucha para un certificado que otra cosa no ha emitido — el caso corriente en una máquina cuya CA se crea después de que arranque el resolutor.

#### Recarga de certificados

**Un certificado renovado se sirve sin reiniciar.** Todo escucha TLS sigue un canal `tokio::sync::watch` publicado por su `TlsManager` (`src/tls.rs`) en vez de mantener una instantánea de la configuración, y cada gestor sondea sus ficheros de certificado cada `CERT_RELOAD_INTERVAL` (30 s) y publica una configuración reconstruida cuando su contenido cambia. Una conexión ya establecida termina bajo el certificado con el que hizo el saludo —lo único que TLS permite— y a la siguiente conexión que llegue se le sirve el nuevo. Nada vuelve a enlazar, así que no hay ventana alguna en la que el puerto esté cerrado.

Cómo aplica el cambio cada transporte difiere, porque cada uno guarda su certificado de forma distinta:

| Transporte | Mecanismo |
| ---------- | --------- |
| DoT | `TlsAcceptor` construido por conexión aceptada a partir del canal; un acceptor es un `Arc` alrededor de la configuración, así que esto es gratis |
| DoQ | `Endpoint::set_server_config`, aplicado en el `select!` del bucle de aceptación cuando el canal dispara |
| DoH, ACME, portal | `axum_server::RustlsConfig::reload_from_config`; axum-server carga ese `ArcSwap` por conexión aceptada |

La detección del cambio es un sondeo del *contenido* del fichero, con el hash calculado en la misma pasada que lo analiza, y no una vigilancia inotify ni una comparación de mtime. Una renovación que llega como un renombrado sobre la ruta antigua, o como un enlace simbólico movido a un directorio versionado (la disposición `live/` de certbot), nunca escribe en el inodo sobre el que se puso la vigilancia; releer por nombre atrapa todas las formas. Calcular el hash de lo que se analiza, en vez de hacer stat después, cierra la ventana en la que un fichero podría cambiar entre la carga y la comprobación y dejar al gestor registrando una huella que no describe el certificado que está sirviendo.

Un sondeo que falla deja el certificado anterior sirviendo y reintenta en el siguiente tic, porque la huella se registra solo tras una carga *correcta*. Eso es lo que hace seguro el sondeo sin coordinación alguna con quien escribe los ficheros: un cliente ACME escribe dos de ellos, y un temporizador de 30 segundos acabará cayendo entre las dos escrituras. `rustls` rechaza ese par —`with_single_cert` compara el `SubjectPublicKeyInfo` de la clave privada con el del certificado—, el par antiguo sigue sirviendo, y el par terminado se recoge en el siguiente sondeo.

Los gestores que sirven material **generado** no se sondean en absoluto: no hay fichero detrás de ellos, y regenerar con un temporizador le entregaría a cada cliente un certificado autofirmado distinto dos veces por minuto, lo que es indistinguible de un ataque para cualquier cosa que hubiera fijado el anterior. `src/main.rs` retiene todos los gestores durante la vida del proceso; un gestor descartado es un emisor de watch descartado, y a sus escuchas no se les podría volver a entregar nada.

### DNS-over-TLS (DoT)

RFC 7858. Escucha en un puerto configurable (por defecto `0.0.0.0:853`). Protocolo ALPN: `"dot"`. Usa el mismo enmarcado con prefijo de longitud de 2 bytes que el DNS sobre TCP plano. Cada conexión lanza una tarea nueva. Se configura en la sección `dot`.

El token ALPN se anuncia, no se exige. rustls hace fracasar un saludo solo cuando el cliente ofrece protocolos y ninguno de ellos coincide, así que un cliente que ofrece `dot` recibe `dot`, un cliente que ofrece solo otra cosa es rechazado, y a un cliente que no envía extensión ALPN alguna —el Private DNS de Android y systemd-resolved en modo oportunista, entre ellos— se le sirve con el ALPN sin negociar. Los tres casos están fijados en `tests/dot_test.rs`; un escucha que no anunciara nada satisfaría el primero y el tercero mientras dejaría en silencio a un cliente incapaz de distinguir un escucha DoT de cualquier otro servicio TLS del puerto.

### DNS-over-HTTPS (DoH)

RFC 8484. Escucha en un puerto configurable (por defecto `0.0.0.0:443`) con TLS. Sirve en el endpoint `/dns-query`. Admite ambos:

- **POST**: `Content-Type: application/dns-message` con el cuerpo de la consulta DNS en binario.
- **GET**: parámetro `?dns=<consulta codificada en base64url>`.

Construido con Axum y axum-server para el soporte TLS.

**HTTP/3.** `doh.enable_h3` abre un segundo escucha en la misma dirección y el mismo puerto sobre UDP (`src/doh_h3_server.rs`), que responde las dos mismas formas de petición sobre QUIC. Tiene que ser un escucha aparte porque ninguna configuración de un socket TCP responde también en UDP, y comparte el certificado del escucha TCP en vez de cargar uno propio: la configuración criptográfica de QUIC se deriva de la de ese escucha, con la lista ALPN sustituida por `h3`. Dos gestores sobre el mismo par de ficheros se desviarían hasta que un sondeo notara una renovación, y sobre material generado no coincidirían jamás: cada uno acuñaría su propio certificado autofirmado. Un bind QUIC que falla hace fallar el transporte entero, porque un escucha que prometía HTTP/3 y servía solo h2 en silencio es el estado en el que esta bandera pasó su primera vida.

**Descubrimiento.** Un cliente que ya tiene una conexión h2 se entera del endpoint HTTP/3 por una cabecera `Alt-Svc` en cada respuesta DoH (`h3=":<port>"; ma=86400`, RFC 7838); un cliente que aún no se ha conectado se entera por la designación DDR, que publica `alpn=h2,h3` para ese endpoint. Ninguna alcanza a los clientes de la otra, y por eso hay dos. Con HTTP/3 apagado no se emite ninguna: anunciar un endpoint que no responde le cuesta a todo cliente que se lo crea un tiempo de espera completo antes de volver atrás.

### DNS-over-QUIC (DoQ)

RFC 9250. Escucha en un puerto UDP configurable (por defecto `0.0.0.0:8853`). Protocolo ALPN: `"doq"`. Cada consulta usa un flujo bidireccional nuevo con enmarcado por prefijo de longitud de 2 bytes. Usa la biblioteca QUIC Quinn. El tiempo de inactividad es de 30 segundos.

## DNSSEC

Rolodex DNS firma sus propias zonas y valida las respuestas que resuelve desde upstream — véase más abajo Validación DNSSEC del upstream para la mitad validadora.

Algoritmos de **firma** soportados (del más fuerte al menos):

1. **Ed25519** (RFC 8080, algoritmo 15) — preferido
2. **ECDSA P-384/SHA-384** (RFC 6605, algoritmo 14)
3. **ECDSA P-256/SHA-256** (RFC 6605, algoritmo 13)

**RSA/SHA-256 (algoritmo 8) no está soportado** y `GenerateDnssecKey` lo rechaza: `ring` no puede generar claves RSA. Todo algoritmo de la lista es uno cuyas claves se generan realmente y cuyas firmas se producen realmente — un algoritmo que no se puede honrar de extremo a extremo se rechaza en la generación de claves en vez de sustituirse, porque un DNSKEY que anuncia el algoritmo 13 sobre material de clave Ed25519 produce un DS, un DNSKEY y un conjunto de RRSIG que se contradicen entre sí, y ese fallo aflora en un resolutor validador y no localmente.

### Gestión de claves

Se admiten dos tipos de clave:

- **ZSK** (Zone Signing Key, bandera 256) — firma los registros de datos de la zona.
- **KSK** (Key Signing Key, bandera 257) — firma el RRset DNSKEY.

Las claves se generan, se almacenan en la base de datos y se gestionan por gRPC: `GenerateDnssecKey`, `ListDnssecKeys`, `DeleteDnssecKey`. El nombre de algoritmo almacenado hace ida y vuelta por `DnssecAlgorithm::parse`, y una clave cuyos bytes almacenados no cargan como el algoritmo bajo el que está archivada se salta en el momento de firmar, con un aviso, en vez de firmarse con ella.

### Firma de zonas

`SignZone` vuelve a publicar el RRset DNSKEY del ápice y firma todos los RRset de la zona, guardando los registros RRSIG resultantes en la base de datos local.

- **Agrupación en RRset.** Los registros se agrupan por nombre de propietario y tipo; un RRSIG cubre el conjunto entero. La pertenencia a la zona se casa en fronteras de etiqueta, así que `notexample.com.` no se firma como parte de `example.com.`
- **Forma canónica.** Los bytes firmados son los del RFC 4034 §3.1.8.1: el RDATA del RRSIG hasta la firma, luego cada RR con un nombre de propietario canónico (en minúsculas, sin comprimir), su tipo, clase IN, el TTL **original** y el RDATA canónico — ordenados según el orden canónico del RFC 4034 §6.3 con los duplicados descartados, de modo que el orden en que los registros salen de SQLite no puede cambiar la firma.
- **Papeles de las claves.** El RRset DNSKEY lo firma la KSK y los demás RRset la ZSK (RFC 4035 §2.1). Con un solo tipo de clave presente, esa clave firma ambos. Los RRset de RRSIG nunca se firman a sí mismos.
- **Validez.** La entrada en vigor se retrasa una hora por el desfase de reloj; las firmas caducan a 30 días. El TTL original del RRSIG es el TTL propio del RRset.
- **Los tipos no firmables se saltan, no se aproximan.** NSEC, NSEC3, NSEC3PARAM y ANAME no tienen aquí formato de cable almacenado, y un valor mal formado no tiene codificación canónica; esos RRset se saltan y se nombran en el mensaje de respuesta. Una firma calculada sobre una codificación inventada es peor que ninguna — falla en cerrado en todos los validadores en vez de dejar el nombre sin firmar.
- **La refirma reemplaza.** Los RRSIG existentes en la zona se limpian primero, incluidos los de nombres cuyos registros se borraron desde la última pasada, así que las firmas nunca se acumulan ni sobreviven a sus datos. El RRset DNSKEY se vuelve a publicar igualmente en vez de añadirse. La caché de respuestas se vacía después.

Los valores RRSIG se almacenan como `"type_covered algorithm labels original_ttl expiration inception key_tag signer_name base64_signature"`. La expiración y la entrada en vigor son segundos crudos desde la época Unix y no el formato de presentación `YYYYMMDDHHmmSS`, en línea con cómo cualquier otro tipo de registro aquí guarda sus campos numéricos.

Los registros DS para la delegación desde la zona padre se calculan con SHA-256 y se recuperan con `GetDsRecords`. Las etiquetas de clave se calculan según el RFC 4034 Apéndice B. Las operaciones criptográficas usan el crate `ring`.

`dnssec::verify_rrsig` es la inversa del firmante y existe para que las firmas se puedan comprobar contra algo distinto del código que las produjo. No es el validador de upstream — ese es `src/dnssec_validate.rs`, que trabaja sobre registros de cable y no comparte código con ninguno de los dos (véase Validación DNSSEC del upstream).

### Servicio en el cable de los tipos DNSSEC

DNSKEY, DS y RRSIG se sirven bajo sus propios códigos de tipo, con el RDATA codificado por el mismo codificador canónico que hashea el firmante — así que lo que va por el cable es byte a byte lo que se firmó. URI y ZONEMD se codifican igual. (Antes se servían como registros TXT con la cadena almacenada, lo que responde a una consulta DNSKEY con un TXT y hace inservible cualquier firma publicada.) NSEC, NSEC3 y NSEC3PARAM no se generan nunca y no se sirven.

## Validación DNSSEC del upstream

Rolodex valida DNSSEC en las respuestas que resuelve iterativamente. El validador (`src/dnssec_validate.rs`) es un módulo aparte del firmante (`src/dnssec.rs`) y no comparte código con él: el firmante trabaja sobre filas `DnsRecord` que escribimos nosotros, un validador trabaja sobre registros de cable de una parte cuya honradez es justo lo que está en cuestión, y los dos tienen que poder discrepar.

Se configura con la sección `dnssec` — `validate` (por defecto `true`) y `trust_anchors` (por defecto: las claves raíz de IANA compiladas dentro de hickory). Se aplica a la **ruta iterativa únicamente**: modo `recursive`, y el nivel de raíces de `auto`. Una respuesta reenviada es el resumen de un resolutor recursivo, y validarla significaría volver a resolver la cadena nosotros mismos, que es lo que el nivel de raíces ya es. Una cadena `auto` degradada por debajo del nivel 0 está por tanto sin validar — y lo dice, dejando AD sin poner.

### Los cuatro estados

RFC 4033 §5, y confundir dos cualesquiera de ellos o rompe la internet sin firmar o acepta falsificaciones en silencio:

| Veredicto | Significado | ¿Se sirve? |
| --------- | ----------- | ---------- |
| `Secure` | Las firmas encadenan hasta el ancla de confianza. | Sí, con AD puesto para un cliente que lo pidió. |
| `Insecure` | La cadena **se detiene de forma demostrable**: una delegación del camino no tiene DS, y esa ausencia está ella misma firmada. | Sí, AD sin poner. |
| `Bogus` | Los datos afirman estar firmados y la afirmación no se sostiene. | **Nunca.** SERVFAIL. |
| `Indeterminate` | No pudimos obtener lo necesario para decidir. | **Nunca.** SERVFAIL. |

La distinción que carga con la seguridad es Insecure frente a Bogus. «No hay firma» *no* es Insecure — un atacante en la ruta arranca las firmas de cualquier respuesta. Es Insecure solo cuando un NSEC/NSEC3 firmado demuestra la ausencia del DS en la delegación de arriba, que un atacante no puede falsificar sin la clave del padre. Para eso existe la maquinaria NSEC/NSEC3; saltársela deja un validador que cualquier atacante degrada a ningún validador.

### Cómo se construye la cadena

La validación es **de arriba abajo**, junto al recorrido de delegaciones que el resolutor ya hace, así que la cadena se deriva de las mismas respuestas y no de un segundo juego de consultas:

1. **Raíz.** `root_trust` obtiene el RRset DNSKEY de `.` y exige una clave que case con un ancla configurada, que a su vez debe haber firmado el RRset. Anclar solo demuestra que una clave es legítima; la autofirma es lo que extiende eso al conjunto, de modo que una clave añadida no puede colarse. Un fallo aquí es fatal para la búsqueda — «no pudimos establecer las claves de la raíz» y «la raíz no está firmada» son afirmaciones distintas.
2. **Cada delegación** (`extend_trust`). El RRset DS viaja en la sección de autoridad de la derivación, firmado por el padre cuyas claves ya tenemos. Un DS validado ancla el RRset DNSKEY de la hija, obtenido de los propios servidores de la hija. **Sin** DS, la ausencia debe demostrarse con un NSEC/NSEC3 firmado (`prove_no_ds`) — un NSEC en el nombre de la delegación que afirme NS pero ni DS ni SOA, o el equivalente NSEC3 incluyendo opt-out. Sin demostrar ⇒ Bogus.
3. **Por debajo de una delegación insegura** todo es inseguro sin más comprobaciones: una zona sin firmar no puede firmar un DS para sus hijas.
4. **Respuestas.** Todo RRset de la sección de answer debe verificar, no solo el que responde a la pregunta — un servidor autoritativo no tiene por qué devolver aquí un RRset que no puede firmar, y los registros grapados encima son exactamente lo que añade una inyección. Una respuesta derivada de comodín necesita además una denegación de que el nombre consultado no existe (RFC 4035 §5.3.4), o la firma —válida para todo nombre bajo el envolvente más cercano— podría reproducirse sobre un nombre que sí existe.
5. **Negativos.** NXDOMAIN y NODATA se demuestran a partir de NSEC/NSEC3 en la sección de autoridad (`prove_nxdomain` / `prove_nodata`), después de que las firmas de esos registros verifiquen. Una zona firmada que responde «no» sin demostrarlo es Bogus: un negativo sin demostrar es la falsificación más barata del DNS.
6. **Las cadenas CNAME** se validan salto a salto, cada uno en su propia zona, y los veredictos se combinan — la cadena es solo tan fiable como su salto más débil, así que un CNAME firmado de forma segura hacia una zona sin firmar produce Insecure.

Toda comprobación de `verify_rrset` es una que un atacante se salta si falta: el nombre del firmante debe ser igual a la zona (de lo contrario un atacante firma `www.bank.example` con una zona que posee y para la que aporta el DS/DNSKEY), la ventana de validez se compara con la aritmética de números de serie del RFC 1982 (un `<` simple es incorrecto en el desbordamiento de 2106, e incorrecto en la dirección que hace que toda firma viva se lea como caducada), y la etiqueta de clave se trata como una pista y no como un identificador, así que se prueba cada candidata con etiqueta coincidente.

Los registros validados solo contra algoritmos que esta compilación no puede verificar son **Insecure, no Bogus** (RFC 6840 §5.11) — que a nosotros nos falte un algoritmo no es la caída de la zona. `ring` no puede *generar* claves RSA, que es por lo que la firma rechaza el algoritmo 8, pero verificar es otra pregunta y RSA/SHA-1/256/512 más ambas curvas ECDSA y Ed25519 verifican todos.

Los recuentos de iteraciones NSEC3 por encima de 100 se tratan como inseguros en vez de calcularse (RFC 9276): el hashing es trabajo elegido por el atacante en nuestro lado del cable.

### Cortes de zona que nadie anuncia

El paso 2 de arriba supone que al resolutor se le *dice* que hay una delegación. Normalmente así es: los servidores del padre responden con una derivación y el recorrido cruza el corte deliberadamente. Pero cuando un mismo servidor de nombres es autoritativo para un padre **y** para una hija firmada de él, una consulta por un nombre de la hija se responde desde la zona hija directamente: de forma autoritativa, firmada con la clave de la hija, sin que se envíe derivación alguna. `cdnjs.cloudflare.com.` en los servidores de nombres de `cloudflare.com.` es el ejemplo cotidiano, y hay muchos otros — cualquier proveedor que aloje una subzona en la misma infraestructura tiene este aspecto desde fuera.

Un resolutor que elige su conjunto de claves a partir de «la última zona a la que me derivaron» tiene entonces las claves del padre cuando llegan las firmas de la hija, y rechaza una respuesta perfectamente buena:

```
answer for cdnjs.cloudflare.com. A is bogus: RRSIG over cdnjs.cloudflare.com. A
is signed by cdnjs.cloudflare.com., which is not the zone cloudflare.com.
```

El RFC 4035 §5.3.1 zanja qué claves se aplican: el **nombre del firmante** del RRSIG, no la posición del recorrido. Así que antes de validar una respuesta, un salto CNAME o la denegación de un negativo, `keys_for` comprueba si las firmas de la respuesta nombran una zona por debajo de la actual (`signer_below`), y `descend_to` extiende la cadena hasta ella — un corte cada vez, obteniendo el DS que la derivación nunca entregó. Cada corte se establece exactamente como `extend_trust` establece el de una derivación: el DS debe validar bajo las claves del padre, el RRset DNSKEY de la hija debe casar con él, y un DS ausente debe *demostrarse* ausente. Un corte que no se puede establecer retiene la respuesta; nunca se valida contra las claves de la zona equivocada. `MAX_HIDDEN_CUTS` acota cuántos puede obligarnos a establecer una sola respuesta, y `dnssec_hidden_zone_cuts_total` los cuenta.

El descenso es deliberadamente difícil de dirigir, porque «ve y establece confianza para el nombre de este paquete» es, si no, una instrucción de un atacante. `signer_below` devuelve un nombre solo cuando todas las RRSIG de la sección nombran al mismo firmante, ese firmante está estrictamente dentro de la zona actual, y **contiene a todos los propietarios que firmó**. La última condición es la estructural: sin ella, una respuesta falsificada para `www.example.com.` podría nombrar a `unsigned.example.com.` como su firmante, el padre demostraría con toda verdad que esa delegación no lleva DS, y datos que la zona real sí firma se aceptarían como inseguros. Las dos mitades están probadas — `tests/dnssec_hidden_cut_test.rs` para las respuestas que ahora deben resolver, `tests/security_dnssec_test.rs` para las falsificaciones que siguen sin deber hacerlo.

La posición del propio recorrido se deja en paz: el descenso establece lo que valida *esta* respuesta, mientras `current_zone` sigue rastreando derivaciones, que es contra lo que están escritas las comprobaciones de jurisdicción y de bucle de delegación.

Una hija **sin firmar** servida de la misma manera no se puede resolver, y se cuenta en su lugar. Produce una respuesta sin firma alguna, así que no hay nombre de firmante que perseguir ni nada a lo que apuntar `descend_to`; rechazarla es correcto, porque ese paquete es además exactamente lo que produce arrancar cada RRSIG en tránsito, y los dos son indistinguibles desde aquí. `dnssec_unsigned_responses_total{evidence}` registra cada caso, etiquetado por la única pista disponible: `child_apex_soa` cuando el SOA de la sección de autoridad nombra una zona por debajo de la actual (`soa_below`), que es lo que lleva la respuesta negativa de una hija sin firmar, y `none` en el resto. Ese SOA está sin firmar como todo lo que lo rodea y por tanto es falsificable — sirve para decirle a un operador cuál de los dos casos está viendo probablemente, nunca para decidir un veredicto, y por eso nada fuera de la ruta de métricas lo lee. Sin el contador, una hija sin firmar irresoluble es un SERVFAIL indistinguible de cualquier otro.

### Rechazo en el nivel de las raíces

Al resolver desde las raíces, el DNSSEC inválido se rechaza de plano: nunca se sirve, y nunca se reintenta calladamente en algún sitio que no valide.

- `tier_roots` convierte cualquier veredicto que retenga (`Bogus` o `Indeterminate`) en SERVFAIL y lo devuelve como respuesta **definitiva**, así que el bucle de niveles cortocircuita y la consulta no cae al nivel seguro ni al de reenvío. `cache_from_wire` cachea solo `NoError` con una sección de answer no vacía, así que el SERVFAIL nunca entra en la caché de respuestas, y dentro del resolutor el veredicto se comprueba antes de tocar la caché de registros.
- **Un recorrido rechazado no deja estado.** La delegación aprendida de una derivación se cachea solo *después* de que `extend_trust` devuelva un estado de confianza utilizable, y el glue con ella. Escribirlas primero significaba que una derivación cuya prueba DS/NSEC fallaba ya tenía su conjunto NS confirmado — y la caché de delegaciones se persiste en disco, así que el resolutor conservaba y reutilizaba un conjunto NS que acababa de negarse a verificar, entre reinicios.
- **Una zona raíz que no valida es un veredicto, no un fallo de nivel.** `fetch_dnskeys` distingue `Unreachable` (transporte) de `Invalid` (criptográfico). En la raíz, `Invalid` se convierte en un `Bogus` que retiene —SERVFAIL, la cadena se detiene— mientras que `Unreachable` sigue siendo un error y cae hacia abajo. Aplanar los dos es lo que permitía a un atacante capaz de romper de forma fiable la obtención del DNSKEY de la raíz sacar la validación del camino sin producir jamás un veredicto bogus: el error se leía como «las raíces son inalcanzables» y la consulta se iba al upstream cifrado. Por debajo de la raíz ambas variantes siguen siendo Bogus, como antes: una zona con un DS en su padre que no entrega claves es una cadena rota de cualquier modo.

Dos fronteras que esto deliberadamente no cruza. **Inalcanzable no es inválido** — un tiempo de espera o un fallo de transporte en el nivel de raíces sigue cayendo hacia abajo, o una red desenchufada haría fallar duro toda búsqueda. **Inseguro no es inválido** — una delegación demostradamente sin firmar produce `Insecure`, que se sirve sin AD; solo un *veredicto* que retiene detiene la cadena.

La consecuencia que hay que aceptar, dicha con claridad: un ancla de confianza que esta compilación desconoce (una rotación de KSK) se convierte en una caída total de DNS en vez de una degradación silenciosa a DoH, y el modo auto ya no puede degradarse para huir de una raíz con la validación rota, porque una respuesta retenida cuenta como una victoria del nivel de raíces. Esa es la intención — la salida de emergencia es `dnssec.validate: false`, es decir, configuración, y no una reserva automática.

### Imputar a un servidor raíz que sirve DNSSEC inválido

La regla de arriba trata el fallo de validación de la *zona* raíz. Que un único *servidor* raíz sirva firmas malas —una instancia secuestrada o rota entre pares sanos— se trata omitiéndolo.

- **La señal es estrecha.** La imputación se adhiere solo al RRset DNSKEY de la raíz comprobado contra nuestra ancla de confianza local. Eso es lo único que un servidor raíz nos dice que podamos verificar sin preguntarle a nadie más, lo que hace de «este servidor raíz está mintiendo» una afirmación que podemos sostener y no una inferencia a partir del error de otro. `query_servers` devuelve la dirección que respondió junto al mensaje, para que la afirmación se pueda atribuir siquiera.
- **La imputación omite, con retroceso exponencial.** Una raíz imputada se *elimina del conjunto de candidatas* —filtrada antes de que `order_servers` ordene nada, así que ninguna regla de ordenación puede traerla de vuelta como último recurso— durante 15 minutos en la primera falta, duplicando hasta un tope de 24 horas. La curva es la de `note_failure`; las constantes son propias, porque un tiempo de espera dice «este servidor estaba ocupado» y una firma mala dice «este servidor me contó algo que no es verdad», y lo segundo no tiene por qué recuperarse en una curva de 2 s. `with_blame_backoff` sustituye ambos extremos para las pruebas.
- **La imputación sobrevive al éxito del transporte.** `note_success` limpia solo los campos de transporte y descarta la entrada de salud justo cuando no queda nada en ella — una raíz secuestrada responde con presteza por construcción, así que eliminar la entrada ahí dejaría que el mismísimo servidor del que desconfiamos limpiase su propio expediente.
- **El tiempo por sí solo no perdona nunca.** El contador de escalada lo limpia una respuesta que *valida* y nada más, así que una raíz que ha mentido tres veces y no ha servido nada desde entonces vuelve en el cuarto escalón de la curva y no en el primero. La expiración es a prueba: la raíz se vuelve a consultar por sí sola, sin acción del operador y sin sonda aparte, y nada de lo que diga tiene valor alguno hasta que produzca una respuesta que valide.
- **No omitir nunca la última raíz.** Si el filtro fuera a dejar el conjunto vacío, no se aplica. Que todas las raíces fallen la validación no son trece servidores rebeldes, es la zona o nuestra propia ancla de confianza — y un conjunto de candidatas vacío produce `NameserversUnreachable`, que se lee como *inalcanzable* y cae hacia abajo, reabriendo justo el agujero que cierra el veredicto que retiene. En ese estado la imputación deja de ser la entrada decisiva y gobierna el modo auto: la zona raíz no valida, `tier_roots` responde SERVFAIL, y `roots_validate()` mantiene el nivel 0 irrecuperable hasta que vuelva un DNSKEY de raíz con `Verdict::Secure`. La transición se registra a voz en grito, porque es la forma tanto de un problema de ancla de confianza como de un secuestro total y de otro modo es invisible.
- **Solo servidores raíz.** La imputación no está conectada a la selección de servidores de nombres en general. Por debajo de la raíz, un fallo de validación es casi siempre el error de firma de la propia zona: todos los servidores de esa zona devuelven los mismos bytes, y omitirlos convertiría el error de otro en nuestra caída. Esas búsquedas ya fallan en cerrado por el veredicto.
- La imputación está **en memoria y no sobrevive a un reinicio**: una máquina reiniciada vuelve a confiar en todas las raíces hasta que una se porte mal otra vez. El recuento actual se expone como `dnssec_blamed_roots` — un medidor acotado (trece como mucho, sin etiquetas), porque una exclusión silenciosa y duradera de parte del conjunto de raíces es la única parte de esta maquinaria de la que ningún contador existente informa.

La consulta que provocó la imputación sigue fallando en cerrado. La imputación cambia qué servidores raíz usan las consultas *posteriores*; no convierte la actual en un bucle de reintentos que sigue preguntando a las raíces hasta que una produce una respuesta que valide, lo que le entregaría a un atacante un oráculo contra el que machacar.

### Caché de claves validadas (`src/key_cache.rs`)

Zona → conjunto DNSKEY validado, o demostradamente inseguro, con TTL. Sin ella, toda consulta re-derivaría la cadena desde la raíz, que es el problema de arranque en frío que la caché de delegaciones existe para evitar, reintroducido una capa más arriba. `Insecure` también se cachea —volver a demostrar un DS ausente en cada consulta a cada zona sin firmar pondría un viaje de ida y vuelta NSEC delante de casi toda internet— y es seguro cachearlo porque la prueba que registra la firmó el padre.

Las búsquedas son **por nombre exacto, nunca por sufijo**: las claves de un padre no dicen nada de las de una hija, que es para lo que está el registro DS. Los TTL tienen un suelo de 60 s (una zona que publicara un conjunto DNSKEY con TTL 0 forzaría si no una re-validación por consulta) y un techo de 7 días. Los vacía `flush_upstream_state()` en un cambio de nivel de `auto`, **no** `flush_cache()`.

Entrar en la cadena de delegaciones a medio camino significa saltarse todas las comprobaciones de DS y DNSKEY por encima del punto de entrada, así que `warm_start` solo toma una delegación cacheada como atajo cuando el estado de confianza de su zona está *también* cacheado. En caso contrario el recorrido reinicia en la raíz y re-deriva la cadena, repoblando la caché de claves de bajada.

### En el cable

- Las consultas salientes del resolutor iterativo llevan EDNS0 con **DO puesto y un tamaño de payload de 1232 bytes** cuando se valida (antes no llevaban registro OPT alguno, así que un servidor tenía derecho a recortar las respuestas a 512 bytes — dentro de los cuales una respuesta firmada esencialmente nunca cabe). 1232 es el mayor payload que evita la fragmentación IPv6; cualquier cosa mayor vuelve truncada y se vuelve a pedir por TCP. Con la validación apagada no se envía OPT: DO pide registros que un resolutor no validador solo descartaría.
- **AD se pone solo para `Secure`**, y solo para un cliente que lo pidió — uno que puso DO o AD en su consulta (RFC 6840 §5.7). Las respuestas construidas a partir de datos locales nunca ponen AD, así que las respuestas que este servidor genera él mismo siguen sin hacer afirmación alguna de autenticación.
- **RRSIG/NSEC/NSEC3 se retiran para un cliente que no puso DO** (RFC 4035 §3.2.1), salvo que pidiera ese tipo por su nombre. Un registro A firmado triplica aproximadamente su tamaño, y una respuesta grande a una pregunta pequeña es la forma de amplificación que `security.recursion_cidrs` existe para cerrar. DNSKEY y DS nunca se filtran — son tipos corrientes que resulta que llevan claves.
- Una respuesta bogus **no se cachea nunca**, ni en positivo ni en negativo: un negativo bogus cacheado suprimiría el nombre real durante todo su TTL.
- En modo `auto` una validación fallida es una respuesta **definitiva**, no un fallo de nivel. Caer al nivel seguro o al de reenvío significaría que a toda zona cuyas firmas no cuadren se le vuelve a preguntar calladamente a un upstream que no valida, convirtiendo la validación en algo que un atacante apaga rompiendo una firma.

Validar cuesta aproximadamente una consulta extra por zona del camino (el DS llega dentro de la derivación sin coste), así que el presupuesto de consultas por búsqueda gana un `VALIDATION_QUERY_BUDGET` de 32 sobre la base de 64 cuando la validación está activa — de lo contrario activarla acortaría en silencio la profundidad que un nombre puede alcanzar antes de que el presupuesto lo mate.

## DANE y TLSA

Rolodex DNS genera registros DANE/TLSA (RFC 6698) a partir de certificados:

- **Uso**: 2 (ancla de confianza) y 3 (emitido por el dominio)
- **Selector**: 0 (certificado completo) y 1 (Subject Public Key Info)
- **Tipo de coincidencia**: 0 (exacto), 1 (SHA-256), 2 (SHA-512)

Los nombres DNS de TLSA siguen la convención `_puerto._protocolo.dominio.`.

Se puede generar una CA raíz DANE autofirmada con `GenerateDaneRootCa` para despliegues DANE basados en ancla de confianza.

## Emisor ACME (autoridad de certificación)

Rolodex es él mismo un **servidor ACME / autoridad de certificación** (RFC 8555, lado servidor), no meramente un cliente ACME. Los clientes ACME de estantería (certbot, lego, acme.sh, Caddy) apuntan a la URL del directorio de Rolodex y obtienen certificados emitidos por una CA operada por Rolodex. Como Rolodex es también el servidor DNS, sirve y autovalida el desafío dns-01 contra su propia base de datos.

### Jerarquía de CA

Una única **CA raíz** autofirmada firma una **CA intermedia por zona**; cada intermedia firma los certificados de hoja emitidos por ACME. Todas las claves son **Ed25519**. Las CA se almacenan como PEM en la base de datos (`dane_root_cas` con el nombre reservado `__rolodex_root__`, y `zone_cas`) y se rematerializan en el momento de usarse con `from_ca_cert_pem` de rcgen. Véase `src/ca.rs` (`ensure_root_ca`, `ensure_zone_intermediate`, `issue_leaf`, `intermediate_tlsa`, `responsible_zone`).

### Flujo del protocolo (`src/acme_server.rs`, `src/acme_jose.rs`)

Los endpoints se montan bajo `/acme`: `directory`, `new-nonce`, `new-account`, `new-order`, `order/{id}`, `authz/{id}`, `challenge/{id}`, `finalize/{id}`, `cert/{id}`, `revoke-cert`. Toda respuesta lleva un `Replay-Nonce` fresco. Las peticiones JWS se verifican con `ring` para `EdDSA`, `ES256` y `RS256`; los nonces son de un solo uso (antirrepetición). La identidad de la cuenta usa la huella JWK del RFC 7638.

- **La validación es solo dns-01**, comprobada contra los propios datos DNS de Rolodex. El cliente aprovisiona el TXT `_acme-challenge.<nombre>` (TTL 60 s) por el plano de control de Rolodex — usa el hook incluido `scripts/rolodex-dns01-hook.sh` (admite `exec` de lego y `--manual-auth-hook` de certbot).
- **Autorización**: el registro de cuenta requiere External Account Binding (EAB) por defecto (`require_eab`); las credenciales EAB tienen alcance de zona y las acuña el portal o la CLI. La emisión está restringida a nombres bajo una zona respaldada por una intermedia salvo que `issuance_scope` sea `any`.
- **Emisión**: `finalize` firma la CSR del cliente con la intermedia de la zona y devuelve la cadena `hoja + intermedia`.

### Integración con DANE

Al emitir, la intermedia de la zona se publica automáticamente como registro TLSA **DANE-TA** — `2 1 1` (SHA-256 del SPKI de la intermedia) en `_<puerto>._<proto>.<nombre>` (por defecto `_443._tcp`, configurable). El servidor presenta `hoja + intermedia`, así que un validador DANE-TA casa la intermedia de la cadena. No se publican registros EE por hoja.

### Distribución de la CA por DNS

Cuando se crea (o se reasegura) una CA intermedia por zona, `publish_ca_dns_records` en `src/ca.rs` publica la cadena de CA en la base de datos DNS local para que cualquier cliente que pueda resolver la zona pueda recuperar los certificados raíz e intermedio — sin necesidad de acceso al portal:

- **Registros CERT (RFC 4398)** en `_ca.<zona>.` — un registro por certificado, valor `"1 0 0 <DER en base64>"` (tipo 1 = PKIX, key tag 0, algoritmo 0). Recuperables con cualquier cliente DNS (`dig CERT _ca.<zona>`); la raíz se identifica como el certificado autofirmado.
- **Registros TXT** en `_rolodex-ca.<zona>.` — el mismo DER en base64 partido en trozos de cadena de ≤255 bytes enmarcados como `rolodex-ca:v1:<root|intermediate>:<i>/<n>:<trozo>`. El prefijo único `rolodex-ca:` distingue los trozos de datos TXT ajenos; los trozos llevan números de secuencia explícitos porque el orden de las respuestas DNS no está garantizado. Esta es la reserva para pilas de resolución que no pueden consultar CERT.

La publicación es idempotente (los registros existentes en ambos nombres se reemplazan) y ocurre en todos los puntos de llamada a `ensure_zone_intermediate`: creación de cuenta en el portal, los RPC `EnsureZoneCa`/`CreateEabCredential`, y las rutas de cuenta/finalize de ACME. La caché de respuestas DNS se vacía tras la publicación. Los consumidores prefieren CERT y recurren a TXT — el `extension/ca_dns.js` de la extensión de navegador recupera la cadena por DoH de esta manera y puede verificar la intermedia contra el registro TLSA DANE-TA.

### Superficies de inscripción (red de confianza)

Los usuarios finales no necesitan una CLI. Un **portal web** integrado (`src/portal.rs`, servido en `acme.portal_bind`) y una **extensión de navegador** (`extension/`) comparten una API JSON (`/api/account`, `/api/ca`, `/api/zones`, `/api/certs`); una **biblioteca cliente de JavaScript** para la misma API más la recuperación DANE/TLSA y una interfaz local de inscripción viven en `js/` (véase la sección Biblioteca cliente de JavaScript). La extensión puede además recuperar la cadena de CA del propio DNS por DoH (véase Distribución de la CA por DNS), lo que funciona para cualquier cliente que pueda resolver la zona — sin necesidad de acceso al portal. El portal acuña una cuenta EAB entre bastidores y devuelve configuración de cliente lista para copiar y pegar; los usuarios solo confían en la CA raíz y ejecutan su cliente. **El acceso es solo de red de confianza** — enlaza `portal_bind` a una dirección interna; cualquiera que pueda alcanzarlo puede inscribirse.

Dos límites acompañan a eso, porque «puede inscribirse» no es «puede convertirse en CA de todo el espacio de nombres», y alcanzar el portal debe significar que *el usuario* lo alcanzó:

- **La inscripción se confina a zonas que el servidor gestiona.** `POST /api/account` acepta una zona solo si un ámbito la posee como TLD (lo que cubre el dominio `.home` implícito de un ámbito), tiene registros en la base de datos local, es una zona autoritativa declarada, o ya tiene una CA intermedia por `EnsureZoneCa`. Las cuatro casan por sufijo, así que una subzona de una zona gestionada también se inscribe. `acme.issuance_scope: any` levanta la restricción, igual que hace para el emisor.
- **Las peticiones entre sitios se rechazan.** El endpoint exige un content-type `application/json` —los tres tipos que un POST de formulario entre orígenes puede enviar sin preflight se rechazan, y el portal no responde a ningún preflight— y rechaza cualquier `Origin` que no sea este servidor (comparado por autoridad, así que un proxy que termina TLS funciona). Los orígenes de extensión de navegador están exentos; los clientes que no son navegador no envían `Origin` y no se ven afectados.

### RPC stub heredados

`RequestAcmeCert`/`GetAcmeStatus` permanecen por compatibilidad hacia atrás (fontanería del registro de desafío + estado), superados por el endpoint ACME y los RPC de administración de abajo.

## DNS64

DNS64 sintetiza registros AAAA a partir de registros A para clientes solo-IPv6. Cuando está activo y una consulta de AAAA no da resultados pero existen registros A, el servidor sintetiza registros AAAA empotrando la dirección IPv4 en el prefijo NAT64 configurado.

- Prefijo por defecto: `64:ff9b::`
- Desactivado por defecto.
- Configurable en caliente con `SetDns64Config`/`GetDns64Config`, que almacenan la bandera de activación y el prefijo de forma **independiente**: desactivar la síntesis no descarta el prefijo configurado, así que reactivarla no vuelve en silencio al valor por defecto bien conocido. Un prefijo que no analiza se rechaza en vez de sustituirse.

## Ajuste por deriva de TTL

La deriva de TTL modifica los TTL de los registros cacheados para reducir las tormentas de caducidad de caché en manada. Dos modos:

- **Fijo**: suma o resta una duración fija a los TTL (por ejemplo `"30s"`, `"-10s"`, `"5m"`, `"1h30m"`). Acotado a un mínimo de 1 segundo.
- **Logarítmico**: ajusta los TTL en función de la latencia del servidor upstream con la fórmula `adjusted_ttl = original_ttl * (1 + multiplicador * ln(latencia_media_ms / 50,0))`. Línea base: 50 ms. Más latencia sube los TTL (menos consultas upstream); menos latencia los baja (datos más frescos).

Desactivado por defecto. Configurable en caliente con `SetTtlDriftConfig`/`GetTtlDriftConfig`. `GetTtlDriftConfig` informa del ajuste con la misma grafía compuesta con la que se puso (`1h30m`, no `5400s`) vía `ttl_drift::format_duration_secs`, la inversa de `parse_duration_secs` — la respuesta de configuración es lo que un operador lee de vuelta para confirmar lo que configuró, y tiene que hacer ida y vuelta para que la automatización de leer-modificar-escribir funcione.

### Seguimiento de la latencia

La latencia de los servidores upstream se rastrea con una media móvil exponencial (EMA) con un factor de suavizado configurable. Las estadísticas de latencia y de número de consultas por servidor están disponibles con `GetQueryLatencyStats`.

## Ámbitos de red

Los ámbitos de red proporcionan vistas DNS por red, aislando los registros DNS según la pertenencia a una red.

### Clasificación de origen e imposición de ámbito

La imposición de ámbito no se aplica a todo origen: se confina a los pares de superposición de red (WireGuard), listados en `security.overlay_cidrs` (por defecto `10.64.0.0/10`, el rango de superposición de Town OS; analizado por `src/cidr.rs`). El ámbito de una consulta se elige en este orden:

1. **Llegó por un escucha de ingreso por TLD** → el ámbito propietario del escucha, para **todos** los nombres, sea cual sea la consulta. El escucha está enlazado a la dirección de superposición de la red y es el resolutor dedicado de esa red, así que los TLD propios siguen separados (el TLD de una red hermana sigue siendo un NXDOMAIN autoritativo) mientras todo lo demás cae a la resolución global y al reenvío. Indexar el ámbito por el *nombre* consultado en su lugar mandaría un nombre público como `google.com` a la rama de IP de origen, donde un par de superposición que nunca llamó a `JoinNetwork` es REFUSED — el escucha respondería entonces por su propio TLD y nada más, así que el resolutor propio de la red no podría resolver la internet para la que es el resolutor.
2. **IP de origen unida a un ámbito** (solo las direcciones de superposición se unen alguna vez) → ese ámbito, separado.
3. **IP de origen dentro de `overlay_cidrs` pero unida a nada** → REFUSED: un par de superposición que no es miembro de red alguna.
4. **Todo lo demás** —loopback (el resolutor de la propia máquina), la LAN, los puentes de contenedores— es un **origen local de confianza**: nunca se rechaza, resuelve el espacio de nombres global. Esto es el horizonte partido: los registros globales llevan la dirección de la máquina alcanzable por LAN mientras los registros con ámbito de superposición llevan la dirección de superposición, así que cada lado recibe una dirección a la que realmente puede enrutar.

La dirección de origen (y la IP local del escucha) se **canonicaliza en `handle_query_on` antes de que corra nada de esto**, de modo que un par IPv4 que llega a un escucha de doble pila como `::ffff:10.64.0.1` es la misma dirección que `10.64.0.1` para la prueba de CIDR, la búsqueda de asociación y la coincidencia del escucha de ingreso. Sin ello, `IpCidr::contains` —que deliberadamente no casa entre familias de direcciones— clasifica todo par de superposición IPv4 en un enlace `[::]` como origen local de confianza, así que si un par de WireGuard tiene ámbito impuesto o no dependería de cómo se hubiera enlazado el escucha. Las direcciones compatibles con IPv4 (`::1.2.3.4`, obsoletas) no se pliegan; solo las verdaderamente mapeadas de IPv4.

### Control de acceso a la recursión

La imposición de ámbito decide *qué vista* recibe un origen. Un eje aparte decide si un origen obtiene **resolución upstream** siquiera: `security.recursion_cidrs`.

`dns.bind` es `0.0.0.0:53` por defecto, así que en una interfaz enrutable el escucha es alcanzable desde toda internet, y todo origen fuera de `overlay_cidrs` se clasifica como cliente local de confianza. Sin una segunda comprobación eso hace de un despliegue por defecto un **resolutor recursivo abierto**: el clásico activo de reflexión/amplificación — una consulta pequeña suplantada devuelve una respuesta grande dirigida a la víctima suplantada, y el tráfico de resolución saliente se le factura a esta máquina.

La lista por defecto es todo rango que no es enrutable desde internet —`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `::1/128`, `fe80::/10`, `fc00::/7`—, que cubre loopback, la LAN, los puentes de contenedores y la superposición WireGuard (`10.64.0.0/10` está dentro de `10.0.0.0/8`). Una lista vacía cierra la recursión a todo el mundo, dejando un servidor puramente autoritativo.

- **La comprobación está en la frontera local/remoto** (paso 8.5 de la resolución): después de toda ruta que responde con datos que este servidor tiene, antes de toda ruta que va a por datos que no tiene. Un desconocido sigue por tanto recibiendo las respuestas autoritativas y los NXDOMAIN autoritativos de este servidor —cerrar la recursión no debe convertir la máquina en un agujero negro para sus propias zonas— pero no puede hacer que vaya a preguntarle a otro.
- **Corre antes de la caché de respuestas**, porque una respuesta cacheada amplifica exactamente igual de bien que una recién resuelta, y calentar la caché es como se monta el ataque.
- **El rechazo es REFUSED con la sección de answer vacía**, la respuesta más pequeña disponible: la respuesta nunca es mayor que la pregunta que la provocó, así que una consulta suplantada no le da al atacante nada.
- **Todos los transportes están controlados.** UDP, TCP, DoT y DoQ ya pasan la dirección del par; DoH sirve con información de conexión (`into_make_service_with_connect_info`) para que su par llegue también a la clasificación — de lo contrario `:443` reabriría lo que `:53` cierra.

### Gestión de ámbitos

- Cada ámbito tiene un nombre único (por ejemplo `"office"`, `"lab"`) y un dominio `.home` reservado (por defecto `"<nombre>.home."`) usado como dominio de búsqueda por defecto para los clientes DHCP.
- Los ámbitos se crean, borran y listan con `CreateNetworkScope`, `DeleteNetworkScope` y `ListNetworkScopes`. Borrar un ámbito elimina todos sus registros y asociaciones.

### Asociación de IP

- Las IP de cliente se unen a un ámbito con `JoinNetwork` con un TTL (300 segundos por defecto). La asociación debe refrescarse antes de caducar para mantener la resolución DNS.
- Las IP dejan un ámbito con `LeaveNetwork`.
- Las asociaciones actuales se recuperan con `GetNetworkAssociations`, con filtro opcional por ámbito.
- `GetSearchDomains` devuelve el dominio `.home` del ámbito asociado a una IP.

### Registros con ámbito

- Los registros añadidos con `AddScopedRecord` solo son visibles para las IP asociadas a ese ámbito.
- Los registros se gestionan con `RemoveScopedRecord` y `ListScopedRecords`, que admiten el mismo filtrado por nombre/tipo que los registros globales.

### TLD propios por red

Más allá de su dominio `.home` implícito, un ámbito puede poseer TLD (zonas) adicionales que separan el espacio de nombres DNS entre redes. Cada TLD propio es **globalmente único** para un solo ámbito. Los nombres bajo un TLD propio se resuelven solo dentro de la red propietaria y no se reenvían nunca upstream — un nombre sin coincidencia produce un NXDOMAIN autoritativo (tras consultar opcionalmente los reenviadores pares del TLD, las direcciones de superposición de otros miembros rolodex de la misma red). Los TLD propios se gestionan con `AddScopeTld`, `RemoveScopeTld` y `ListScopeTlds`; los reenviadores pares con `SetScopeTldForwarders`/`ListScopeTldForwarders`. La propiedad la impone una tabla `scope_tlds` con un índice globalmente único, reflejada en un `tld_owner_cache` en memoria para la búsqueda por sufijo O(etiquetas) en la ruta caliente (`db::find_tld_owner`).

**Separación entre extremos WireGuard frente a visibilidad en la LAN.** Para un *par de superposición* (IP de origen unida a un ámbito), los TLD propios están estrictamente separados: el par resuelve solo el TLD de su propia red y recibe un NXDOMAIN autoritativo para el TLD de cualquier otro ámbito — así que `.fart` y `.fart2` nunca son ambos resolubles desde un único extremo WireGuard. Para un *origen local de confianza* (loopback / LAN, asociado a ningún ámbito), la reserva LAN → ámbito propietario (paso 5 de la resolución) resuelve **todos** los TLD propios desde su ámbito propietario, así que todos los TLD de red son visibles en la LAN. Un ámbito se puede crear por tanto puramente para *poseer* un TLD (marcándolo como separado-de-los-pares-de-superposición y resoluble en la LAN) sin atarle nunca una superposición WireGuard — así es como Town OS mantiene `.home` solo en la LAN y oculto a todo par de WireGuard sin darle transporte de superposición alguno.

### Escuchas DNS de ingreso

A un TLD propio se le puede dar una **IP de ingreso** local al registrarlo (`AddScopeTld` con un `listen_ip`). Esto hace tres cosas:

1. **Enlaza un escucha DNS** (UDP + TCP) en esa IP local, en el `dns.ingress_listen_port` configurado en el servidor (53 por defecto). Los escuchas se rastrean en un registro de manejadores de aborto, así que quitar el TLD (`RemoveScopeTld`) desmonta el escucha en cuanto ningún TLD restante referencia esa IP; se vuelven a crear al arrancar desde la base de datos con `sync_ingress_listeners`.
2. **Sirve la vista completa del ámbito propietario.** Una consulta que llega al escucha se resuelve dentro del ámbito propietario de ese TLD para **todos** los nombres, no solo los nombres bajo el TLD propio — véase Clasificación de origen e imposición de ámbito. Los TLD propios siguen separados (el TLD de una red hermana es un NXDOMAIN autoritativo), y todo lo demás cae a la resolución global y al reenvío upstream, así que un par puede usar el escucha como su resolutor de propósito general.
3. **Reescribe las respuestas a la IP de ingreso.** Una consulta por un nombre **programado** bajo el TLD (uno que tiene un registro A/AAAA almacenado — paquetes, páginas, etc.), *cuando llega por ese escucha de ingreso*, tiene su respuesta A/AAAA reescrita a la IP de ingreso, de modo que el controlador de ingreso de la red recibe el tráfico y enruta por Host/SNI. La reescritura es una sustitución total del valor almacenado, casando la familia de direcciones consultada. A diferencia de la selección de ámbito, la reescritura sigue **condicionada al nombre**: un nombre de paso (no bajo el TLD del escucha) conserva su valor resuelto, el mismo nombre en el escucha principal `:53` resuelve a su valor almacenado, y un nombre sin registro almacenado sigue devolviendo NXDOMAIN (sin síntesis de comodín). La IP local del escucha se enhebra por el manejador de consultas (`handle_query_on`); los escuchas comodín principales (`0.0.0.0`) no llevan IP local concreta, así que nunca reescriben y nunca toman el ámbito de ingreso.

**Los enlaces fallidos no envenenan la IP.** El registro anota ambos manejadores de aborto en el momento del lanzamiento, antes de que ninguna de las tareas haya intentado enlazar, así que un escucha que fallara al enlazar dejaría si no una entrada afirmando que la dirección está servida mientras nada escucha en ella. Ese es el caso normal al arrancar: la IP de ingreso de un TLD es una dirección de superposición WireGuard, y `sync_ingress_listeners` la reproduce desde la base de datos antes de que exista la interfaz del túnel, así que ambas tareas fallan con `EADDRNOTAVAIL` y salen. Una entrada cuyas tareas han terminado todas se trata por tanto como **ausente** —se descarta y se relanza—, así que un `AddScopeTld` posterior reintenta de verdad el enlace una vez levantada la interfaz. `has_ingress_listener`/`ingress_listener_count` informan igualmente solo de escuchas vivos.

El mapeo de ingreso por TLD se almacena en una tabla `tld_listeners` y se refleja en un `tld_ingress_cache` en memoria. Los escuchas se listan con `ListScopeTldListeners`.

## Declaraciones de zona autoritativa

Las zonas se pueden declarar autoritativas explícitamente con `AddAuthoritativeZone`. Las consultas por nombres dentro de zonas autoritativas no se reenvían nunca upstream — si el nombre concreto no se encuentra localmente, se devuelve un NXDOMAIN autoritativo. Las zonas se gestionan con `AddAuthoritativeZone`, `RemoveAuthoritativeZone` y `ListAuthoritativeZones`.

## Servidor DHCP

Rolodex DNS incluye un servidor DHCPv4 integrado que proporciona asignación de direcciones IP (IPAM) con registro automático de nombres de máquina en DNS. El servicio DHCP está desactivado por defecto y se activa con la sección de configuración `dhcp`.

### IPAM (gestión de direcciones IP)

Los conjuntos de direcciones DHCP se configuran por ámbito de red. Cada conjunto define un rango de IP, pasarela, máscara de subred y servidores DNS. No hay agregación entre conjuntos: cada conjunto es un único rango contiguo, y cuando el conjunto se agota, la asignación falla (devuelve `None`). Las vinculaciones MAC-a-IP son persistentes (pegajosas): una vez que a una dirección MAC se le asigna una IP, las peticiones posteriores de esa misma MAC reciben la misma IP.

Estados de concesión: `active` (en uso), `expired` (pasada la duración), `released` (el cliente la liberó), `reclaimable` (pasado el tiempo de recuperación, la IP está disponible para reutilizarse).

### Integración con DNS

Cuando un cliente DHCP aporta un nombre de máquina (opción 12), el servidor registra automáticamente los registros de abajo — **siempre que el nombre de máquina sea una etiqueta DNS válida**. La opción 12 llega literalmente de un dispositivo no autenticado de la LAN y se interpola directamente en un nombre de registro, así que `valid_hostname_label` exige una única etiqueta LDH según el RFC 1123 §2.1 (1–63 bytes, letras/dígitos/guion, sin guion inicial ni final) y la pasa a minúsculas. Un nombre de máquina que no pasa se **rechaza, no se sanea** —el registro se salta con un aviso en vez de asignarse en silencio un nombre distinto— y la baja aplica la misma regla, de modo que el nombre que se quita es el nombre que se puso. La comprobación importa sobre todo para `*`: `*.lan.<tld>.` es un comodín real para `lookup_scoped`, así que sin ella un cliente que se llame `*` responde por todos los nombres no registrados de su ámbito.

- Un registro A: `<hostname>.lan.<tld>.` → IP asignada (como registro con ámbito)
- Un registro PTR: `<ip-invertida>.in-addr.arpa.` → `<hostname>.lan.<tld>.` (como registro con ámbito)

Ambos registros tienen el ámbito de red asociado al conjunto DHCP. Al liberarse o caducar la concesión, ambos registros se eliminan.

La asignación DHCP se enlaza con el sistema de ámbitos de red por `JoinNetwork`, creando una superposición DNS de horizonte partido única para la dirección DHCP. La superposición DNS deja pasar cualquier registro que haya cambiado.

### Entrega de certificados

Los certificados se pueden entregar a los clientes DHCP mediante opciones DHCP específicas del sitio (códigos 224-254). Los datos del certificado se almacenan por ámbito y se incluyen en las respuestas DHCP OFFER y ACK. Se gestionan con `SetDhcpCertOption`, `RemoveDhcpCertOption` y `ListDhcpCertOptions`.

### Barrido de concesiones en segundo plano

Una tarea de fondo corre a un intervalo configurable (`sweep_interval`, 60 segundos por defecto) para:

- Caducar las concesiones activas que hayan pasado su duración
- Eliminar los registros DNS y las asociaciones de red de las concesiones caducadas
- Recuperar las IP de las concesiones que hayan pasado el `reclaim_timeout` (24 horas por defecto)

## Configuración de proxy

El reenvío DNS upstream se puede encaminar a través de un proxy. Modos soportados:

- `connect` — proxy HTTP CONNECT (por defecto)
- `socks5` — proxy SOCKS5
- `doh` — reenviar las consultas DNS como peticiones DoH a través de un proxy HTTP

La configuración incluye la URL (por ejemplo `"socks5://127.0.0.1:1080"`), autenticación opcional (`"usuario:clave"`) y el modo. Configurable en caliente con `SetProxyConfig`/`GetProxyConfig`.

## Interfaz de gestión gRPC

La API de gestión está definida en `proto/rolodex_dns.proto` bajo el servicio `RolodexDnsService`. Puede escuchar en TCP (por defecto `127.0.0.1:50051`) y/o en un socket Unix (por defecto `/var/run/rolodex-dns.sock`). Cualquiera de los dos transportes se puede desactivar poniendo su dirección de enlace a la cadena vacía.

### Autenticación

- Las **conexiones TCP** requieren un secreto compartido pasado como `auth_token` en cada petición. El token se compara en **tiempo constante** (`subtle::ConstantTimeEq`); `==` sobre `String` delega en `memcmp`, que vuelve en el primer byte distinto y por tanto filtra cuántos bytes iniciales se acertaron, convirtiendo una búsqueda sobre el secreto entero en una byte a byte. Si el secreto compartido del servidor está vacío, se permiten todas las conexiones sin autenticación — así que un `grpc.shared_secret` vacío combinado con un `grpc.tcp_bind` que resuelva a cualquier dirección que no sea loopback se **rechaza en el arranque** (`config::check_grpc_exposure`).
- **Las autenticaciones fallidas se limitan por dirección de origen.** Un secreto compartido es una contraseña, y un oráculo de adivinación en línea sin retroceso es lo que hace fatal que sea débil. Tras 5 fallos consecutivos un origen queda bloqueado 30 s, duplicando por bloqueo consecutivo hasta un techo de 15 minutos; mientras está bloqueado cada intento se rechaza con `ResourceExhausted` **sin comparar el token en absoluto**, de modo que el bloqueo no es él mismo un oráculo. Una autenticación correcta limpia el historial del origen, y una racha de fallos que se queda callada 5 minutos se reinicia — así que a la automatización legítima no se la limita nunca (el contador va sobre fallos, no sobre peticiones) y un token mal tecleado de vez en cuando nunca se acumula. Indexar por dirección de origen en vez de globalmente significa que un atacante no puede dejar al operador fuera de su propio plano de gestión. La tabla está topada a 65536 orígenes: por encima del tope se podan las entradas inactivas y no bloqueadas, y si eso no basta los orígenes nuevos dejan de rastrearse en vez de que la tabla crezca sin cota. Esa combinación es un plano de gestión sin autenticar en un puerto enrutable; en loopback sigue siendo la configuración de desarrollo documentada. `0.0.0.0` y `::` no son loopback, y un enlace `interfaz:puerto` queda condenado por una única dirección enrutable en la interfaz.
- Las **conexiones por socket Unix** se saltan la autenticación por completo, así que el modo del fichero del socket *es* el control de acceso. Se crea `0660` en vez de bajo el umask (que lo dejaría en `0755` y le daría a todo usuario local control administrativo sin autenticar). El escucha se enlaza en una ruta hermana temporal, se restringe, y luego se renombra a su sitio — un renombrado atómico conserva el mismo inodo, así que la ruta publicada no existe nunca en un modo permisivo. `0660` en vez de `0600` para que un despliegue pueda dar acceso a un grupo administrativo dedicado cambiando el grupo del socket.

### Operaciones

#### Gestión de registros

| RPC | Descripción |
| --- | ----------- |
| `AddRecord`    | Añade un registro DNS a la base de datos local. El TTL es 300 por defecto si se pone a 0. |
| `RemoveRecord` | Elimina registros por nombre, con filtros opcionales de tipo y valor. Devuelve el número de registros eliminados. |
| `ListRecords`  | Consulta la base de datos local con filtro opcional de nombre (admite el prefijo comodín `*.` para casar subdominios) y filtro opcional de tipo de registro. |

#### Ámbitos de red

| RPC | Descripción |
| --- | ----------- |
| `CreateNetworkScope`     | Crea un nuevo ámbito de red con un dominio `.home` reservado. |
| `DeleteNetworkScope`     | Borra un ámbito y todos sus registros y asociaciones. |
| `ListNetworkScopes`      | Recupera todos los ámbitos de red configurados. |
| `JoinNetwork`            | Asocia una IP de cliente con un ámbito (basado en TTL, 300 s por defecto). |
| `LeaveNetwork`           | Elimina la asociación de una IP con su ámbito. |
| `GetNetworkAssociations` | Recupera las asociaciones IP-a-ámbito, con filtro opcional por ámbito. |
| `AddScopedRecord`        | Añade un registro DNS dentro de un ámbito de red concreto. |
| `RemoveScopedRecord`     | Elimina registros DNS de un ámbito concreto. |
| `ListScopedRecords`      | Consulta los registros DNS de un ámbito con filtros opcionales. |
| `GetSearchDomains`       | Recupera los dominios de búsqueda para una dirección IP de cliente. |

#### Zonas autoritativas

| RPC | Descripción |
| --- | ----------- |
| `AddAuthoritativeZone`    | Declara una zona como autoritativa (impide el reenvío upstream). |
| `RemoveAuthoritativeZone` | Quita una zona de la lista de autoritativas. |
| `ListAuthoritativeZones`  | Recupera todos los nombres de zona autoritativa. |

#### Métricas

| RPC | Descripción |
| --- | ----------- |
| `SetTrackedTlds`   | Reemplaza la lista de TLD rastreados del operador para las métricas de consultas por TLD. `common` se expande al conjunto integrado; una entrada raíz (`.`) se rechaza con `InvalidArgument`. Devuelve el conjunto efectivo completo. |
| `ListTrackedTlds`  | Devuelve la lista almacenada (`common` sin expandir), el conjunto efectivo (almacenados ∪ configuración ∪ propios, expandido) y el subconjunto de los propios. |

#### Reenvío y listas de bloqueo

| RPC | Descripción |
| --- | ----------- |
| `SetForwarders`       | Reemplaza la lista de reenviadores DNS upstream en caliente sin reiniciar. |
| `SetResolutionMode`   | Cambia en caliente, sin reiniciar, cómo se resuelven los nombres para los que este servidor no es autoritativo: `auto`, `recursive` o `forward`. No distingue mayúsculas; un modo no reconocido se rechaza con `InvalidArgument` en lugar de caer callando en el valor por defecto. Entrar *en* `auto` lanza el sondeo de precalentamiento para que la cadena no arranque en frío. |
| `GetResolutionMode`   | Devuelve el modo actualmente en vigor, que es el que de verdad está resolviendo consultas y no el que nombra `resolution.mode` en el fichero de configuración: difieren tras una llamada a `SetResolutionMode`. |
| `SetDnsblConfig`      | Reemplaza la configuración DNSBL (lista de bloqueo de dominios) en caliente: bandera global de activación, lista de proveedores y manejo de rechazos. |
| `GetDnsblConfig`      | Devuelve la configuración DNSBL actual, con los códigos de rechazo resueltos y los proveedores fuera de rotación. |
| `FlushCache`          | Limpia la caché de resultados de la lista de bloqueo y devuelve a la rotación a todos los proveedores que estaban fuera. |
| `AddLocalBlocklistEntry`    | Añade una entrada a la lista de bloqueo local (nombre/IP y motivo). |
| `RemoveLocalBlocklistEntry` | Elimina una entrada de la lista de bloqueo local por nombre. |
| `ListLocalBlocklistEntries` | Recupera todas las entradas de la lista de bloqueo local. |
| `AddDnsblAllowlistEntry`     | Exime a un nombre (y a sus subdominios) de la comprobación de lista de bloqueo basada en nombre. |
| `RemoveDnsblAllowlistEntry`  | Elimina una entrada de la lista de permitidos de DNSBL por nombre. |
| `ListDnsblAllowlistEntries`  | Recupera todas las entradas de la lista de permitidos de DNSBL. |

#### Caché DNS

| RPC | Descripción |
| --- | ----------- |
| `GetCacheStats` | Devuelve estadísticas de la caché: entradas totales, número de aciertos, número de fallos. |
| `FlushDnsCache` | Limpia la caché de respuestas DNS. |

#### Deriva de TTL y latencia

| RPC | Descripción |
| --- | ----------- |
| `SetTtlDriftConfig`    | Ajusta el modo de deriva de TTL, el ajuste fijo y el multiplicador logarítmico. |
| `GetTtlDriftConfig`    | Devuelve la configuración actual de deriva de TTL. |
| `GetQueryLatencyStats` | Devuelve estadísticas de latencia de consultas upstream por servidor (servidor, latencia media, número de consultas). |

#### Configuración de los transportes cifrados

| RPC | Descripción |
| --- | ----------- |
| `SetDotConfig` / `GetDotConfig`     | Configura DNS-over-TLS (dirección de enlace, ajustes TLS). |
| `SetDohConfig` / `GetDohConfig`     | Configura DNS-over-HTTPS (dirección de enlace, ajustes TLS). |
| `SetDoqConfig` / `GetDoqConfig`     | Configura DNS-over-QUIC (dirección de enlace, ajustes TLS). |
| `SetProxyConfig` / `GetProxyConfig` | Configura el transporte por proxy upstream (URL, autenticación, modo). |

#### DNSSEC

| RPC | Descripción |
| --- | ----------- |
| `GenerateDnssecKey` | Genera un par de claves DNSSEC para una zona (algoritmo + tipo de clave). |
| `ListDnssecKeys`    | Recupera las claves DNSSEC de una zona. |
| `DeleteDnssecKey`   | Borra una clave DNSSEC por ID. |
| `GetDsRecords`      | Recupera los registros DS para la delegación desde la zona padre. |
| `SignZone`          | Firma una zona con sus claves DNSSEC. |

#### DANE y TLSA

| RPC | Descripción |
| --- | ----------- |
| `GenerateTlsaRecord` | Genera un registro TLSA a partir de un certificado PEM (dominio, puerto, protocolo, uso, selector, tipo de coincidencia). |
| `ListTlsaRecords`    | Recupera los registros TLSA de un dominio. |
| `GenerateDaneRootCa` | Genera un certificado de CA raíz autofirmado para DANE. |

#### ACME

| RPC | Descripción |
| --- | ----------- |
| `RequestAcmeCert` | Heredado: aprovisiona un registro de desafío dns-01 (superado por el emisor). |
| `GetAcmeStatus`   | Recupera el estado del certificado ACME (estado, caducidad, dominio). |

#### Administración del emisor ACME

| RPC | Descripción |
| --- | ----------- |
| `EnsureZoneCa`         | Crea la CA intermedia de la zona si no existe; devuelve el PEM de raíz + intermedia. |
| `CreateEabCredential`  | Acuña una credencial EAB (kid + HMAC en base64url) con alcance de zona. |
| `RemoveEabCredential`  | Elimina una credencial EAB por kid. |
| `ListAcmeAccounts`     | Lista las cuentas registradas del servidor ACME. |
| `ListAcmeCertificates` | Lista los certificados emitidos, con filtro opcional por zona. |

#### DNS64

| RPC | Descripción |
| --- | ----------- |
| `SetDns64Config` | Fija la configuración de síntesis DNS64 (activación, prefijo). |
| `GetDns64Config` | Devuelve la configuración DNS64 actual. |

#### Gestión de conjuntos DHCP

| RPC | Descripción |
| --- | ----------- |
| `AddDhcpPool`    | Añade un conjunto de direcciones DHCP para un ámbito (rango, pasarela, máscara de subred, servidores DNS). |
| `RemoveDhcpPool` | Elimina un conjunto DHCP por ID. |
| `ListDhcpPools`  | Lista los conjuntos DHCP, con filtro opcional por ámbito. |

#### Gestión de concesiones DHCP

| RPC | Descripción |
| --- | ----------- |
| `ListDhcpLeases`  | Lista las concesiones DHCP, con filtro opcional por ámbito. |
| `DeleteDhcpLease` | Borra una concesión DHCP por dirección MAC. |

#### TLD propios por red

| RPC | Descripción |
| --- | ----------- |
| `AddScopeTld`             | Registra un TLD globalmente único como propiedad de un ámbito. Un `listen_ip` opcional además arranca un escucha DNS de ingreso en esa IP. |
| `RemoveScopeTld`          | Quita la propiedad de un TLD a un ámbito (el `home_domain` implícito no se puede quitar así) y desmonta su escucha de ingreso en cuanto ningún TLD restante usa esa IP. |
| `ListScopeTlds`           | Lista los TLD que posee un ámbito. |
| `SetScopeTldForwarders`   | Reemplaza los reenviadores pares del TLD de un ámbito (las direcciones de superposición de otros miembros rolodex de la red). |
| `ListScopeTldForwarders`  | Lista los reenviadores pares del TLD de un ámbito. |
| `ListScopeTldListeners`   | Lista los escuchas DNS de ingreso enlazados a los TLD de un ámbito. |

#### Opciones de certificado por DHCP

| RPC | Descripción |
| --- | ----------- |
| `SetDhcpCertOption`    | Fija un certificado que se entregará por DHCP para un ámbito. |
| `RemoveDhcpCertOption` | Elimina una opción de certificado DHCP de un ámbito. |
| `ListDhcpCertOptions`  | Lista las opciones de certificado DHCP de un ámbito. |

Todos los cambios hechos por gRPC surten efecto de inmediato y se reflejan en la resolución DNS posterior.

## Cliente de línea de órdenes

El binario `rolodex-dns-cli` es un cliente de línea de órdenes para la interfaz de gestión gRPC. Admite todas las operaciones gRPC como subórdenes y puede conectar por TCP o por socket Unix.

### Opciones globales

| Opción | Corta | Por defecto | Descripción |
| ------ | ----- | ----------- | ----------- |
| `--address`     | `-a`  | `127.0.0.1:50051` | Dirección del servidor gRPC (host:puerto). Se ignora cuando se indica `--unix-socket`. |
| `--unix-socket` | `-u`  | —                 | Ruta al socket de dominio Unix. Anula `--address`. |
| `--auth-token`  | `-t`  | (vacío)           | Token de autenticación para las conexiones TCP. Se ignora para el socket Unix. |

### Subórdenes

#### Gestión de registros

| Orden | Descripción |
| ----- | ----------- |
| `add-record`    | Añade un registro DNS. Toma `--name` (obligatorio), `--record-type` (por defecto `a`), `--value` (obligatorio), `--ttl` (por defecto 300) y `--priority` (por defecto 0, usado para MX/SRV). |
| `remove-record` | Elimina uno o varios registros DNS. Toma `--name` (obligatorio), con filtros opcionales `--record-type` y `--value`. |
| `list-records`  | Lista registros DNS. Toma filtros opcionales `--name` (admite el prefijo comodín `*.`) y `--record-type`. |

#### Ámbitos de red

| Orden | Descripción |
| ----- | ----------- |
| `create-scope`         | Crea un ámbito de red. Toma `--name` (obligatorio) y `--home-domain` opcional. |
| `delete-scope`         | Borra un ámbito de red y todos sus registros/asociaciones. Toma `--name`. |
| `list-scopes`          | Lista todos los ámbitos de red. |
| `join-network`         | Asocia una IP con un ámbito. Toma `--ip`, `--scope` y `--ttl` opcional (por defecto 300). |
| `leave-network`        | Elimina la asociación de ámbito de una IP. Toma `--ip`. |
| `list-associations`    | Lista las asociaciones IP-a-ámbito. Toma el filtro opcional `--scope`. |
| `add-scoped-record`    | Añade un registro DNS a un ámbito. Toma `--scope`, `--name`, `--record-type`, `--value`, `--ttl`, `--priority`. |
| `remove-scoped-record` | Elimina registros de un ámbito. Toma `--scope`, `--name`, y `--record-type` y `--value` opcionales. |
| `list-scoped-records`  | Lista los registros de un ámbito. Toma `--scope`, y `--name` y `--record-type` opcionales. |
| `get-search-domains`   | Obtiene los dominios de búsqueda de una IP. Toma `--ip`. |

#### Zonas autoritativas

| Orden | Descripción |
| ----- | ----------- |
| `add-auth-zone`    | Declara una zona como autoritativa. Toma `--zone`. |
| `remove-auth-zone` | Quita una zona autoritativa. Toma `--zone`. |
| `list-auth-zones`  | Lista todas las zonas autoritativas. |

#### Métricas

| Orden | Descripción |
| ----- | ----------- |
| `set-tracked-tlds`  | Reemplaza la lista de TLD rastreados para las métricas de consultas por TLD. Toma `--tld` repetible (omítelo para limpiar); `--tld common` añade el conjunto integrado de TLD comunes. Imprime el conjunto efectivo resultante, ya que la lista almacenada por sí sola no dice qué series aparecerán. |
| `list-tracked-tlds` | Muestra la lista almacenada, los TLD propios rastreados automáticamente, y el conjunto efectivo. |

#### Reenvío y listas de bloqueo

| Orden | Descripción |
| ----- | ----------- |
| `set-forwarders`   | Fija los reenviadores DNS upstream. Toma `--forwarders` (una o más direcciones `host:puerto`). |
| `set-resolution-mode` | Cambia el modo de resolución upstream en caliente. Toma `--mode` (`auto`, `recursive` o `forward`; no distingue mayúsculas). |
| `get-resolution-mode` | Imprime el modo actualmente en vigor, que no es necesariamente el que nombra `resolution.mode`. |
| `set-dnsbl-config` | Configura los ajustes de DNSBL (lista de bloqueo de dominios). Toma `--enabled`, `--providers` (`zona:activo`), `--refusal-codes` (`zona=código,código`), `--provider-cooldown` (`zona=segundos`) y `--refusal-cooldown`. |
| `get-dnsbl-config` | Muestra la configuración DNSBL actual, incluidos los códigos de rechazo y los proveedores fuera de rotación. |
| `flush-cache`      | Limpia la caché de resultados de la lista de bloqueo. |
| `add-local-blocklist` | Añade una entrada a la lista de bloqueo local. Toma `--name` y `--reason` opcional. |
| `remove-local-blocklist` | Elimina una entrada de la lista de bloqueo local. Toma `--name`. |
| `list-local-blocklist` | Lista todas las entradas de la lista de bloqueo local. |
| `add-dnsbl-allow`    | Exime a un nombre (y a sus subdominios) de la comprobación DNSBL/lista de bloqueo. Toma `--name` y `--reason` opcional. |
| `remove-dnsbl-allow` | Elimina una entrada de la lista de permitidos de DNSBL. Toma `--name`. |
| `list-dnsbl-allow`   | Lista todas las entradas de la lista de permitidos de DNSBL. |

#### Caché DNS

| Orden | Descripción |
| ----- | ----------- |
| `flush-dns-cache` | Limpia la caché de respuestas DNS. |
| `cache-stats`     | Muestra las estadísticas de la caché DNS (entradas, aciertos, fallos). |

#### Deriva de TTL y latencia

| Orden | Descripción |
| ----- | ----------- |
| `set-ttl-drift` | Fija la configuración de deriva de TTL. Toma `--mode` (`disabled`/`fixed`/`logarithmic`), `--adjustment` (por ejemplo `"+5m"`, `"-30s"`), `--log-multiplier`. |
| `get-ttl-drift` | Muestra la configuración actual de deriva de TTL. |
| `latency-stats` | Muestra las estadísticas de latencia de consultas upstream por servidor. |

#### DNS64

| Orden | Descripción |
| ----- | ----------- |
| `set-dns64` | Fija la configuración DNS64. Toma `--enabled` y `--prefix` (por defecto `64:ff9b::`). |
| `get-dns64` | Muestra la configuración DNS64 actual. |

#### DNSSEC

| Orden | Descripción |
| ----- | ----------- |
| `generate-dnssec-key` | Genera un par de claves DNSSEC. Toma `--zone`, `--algorithm` (por defecto `ed25519`), `--key-type` (por defecto `ZSK`). |
| `list-dnssec-keys`    | Lista las claves DNSSEC de una zona. Toma `--zone`. |
| `sign-zone`           | Firma una zona con DNSSEC. Toma `--zone`. |

#### DANE y ACME

| Orden | Descripción |
| ----- | ----------- |
| `generate-tlsa`     | Genera un registro TLSA de DANE. Toma `--domain`, `--port`, `--protocol` (por defecto `tcp`), `--cert-path`, `--usage` (por defecto 3), `--selector` (por defecto 0), `--matching-type` (por defecto 1). |
| `request-acme-cert` | Solicita un certificado ACME. Toma `--domain` y `--provider-url` (por defecto: Let's Encrypt). |
| `acme-status`       | Obtiene el estado del certificado ACME. Toma `--domain`. |

#### Administración del emisor ACME

| Orden | Descripción |
| ----- | ----------- |
| `ensure-zone-ca`     | Asegura que existe la CA intermedia de la zona. Toma `--zone`. Imprime el PEM de raíz + intermedia. |
| `create-eab`         | Acuña una credencial EAB con alcance de zona. Toma `--zone`. Imprime kid + clave HMAC. |
| `remove-eab`         | Elimina una credencial EAB. Toma `--kid`. |
| `list-acme-accounts` | Lista las cuentas registradas del servidor ACME. |
| `list-acme-certs`    | Lista los certificados emitidos. Toma `--zone` opcional. |

El `scripts/rolodex-dns01-hook.sh` incluido aprovisiona/elimina el TXT `_acme-challenge` mediante `rolodex-dns-cli` para clientes ACME que hacen dns-01 (`exec` de lego y `--manual-auth-hook` de certbot).

#### DHCP

| Orden | Descripción |
| ----- | ----------- |
| `add-dhcp-pool`     | Añade un conjunto de direcciones DHCP. Toma `--scope`, `--range-start`, `--range-end`, `--gateway`, `--subnet-mask` (por defecto `255.255.255.0`), `--dns-servers`. |
| `remove-dhcp-pool`  | Elimina un conjunto DHCP. Toma `--pool-id`. |
| `list-dhcp-pools`   | Lista los conjuntos DHCP. Toma el filtro opcional `--scope`. |
| `list-dhcp-leases`  | Lista las concesiones DHCP. Toma el filtro opcional `--scope`. |
| `delete-dhcp-lease` | Borra una concesión DHCP. Toma `--mac`. |
| `add-scope-tld`     | Registra un TLD propio de un ámbito. Toma `--scope`, `--tld`, y `--listen-ip` opcional (arranca un escucha DNS de ingreso en esa IP). |
| `remove-scope-tld`  | Quita un TLD propio de un ámbito. Toma `--scope`, `--tld`. |
| `list-scope-tlds`   | Lista los TLD que posee un ámbito (el dominio home primero). Toma `--scope`. |
| `set-scope-tld-forwarders`  | Reemplaza los reenviadores pares del TLD de un ámbito. Toma `--scope`, `--tld`, `--forwarder host:puerto` repetible (omítelo para limpiar). |
| `list-scope-tld-forwarders` | Lista los reenviadores pares del TLD de un ámbito. Toma `--scope`, `--tld`. |
| `list-scope-tld-listeners`  | Lista los escuchas DNS de ingreso enlazados a los TLD de un ámbito. Toma `--scope`. |
| `set-dhcp-cert`     | Fija una opción de certificado DHCP. Toma `--scope`, `--option-code`, `--cert-path`, `--description`. |
| `remove-dhcp-cert`  | Elimina una opción de certificado DHCP. Toma `--scope`, `--option-code`. |
| `list-dhcp-certs`   | Lista las opciones de certificado DHCP. Toma `--scope`. |

Las subórdenes `list-records` y `list-scoped-records` muestran los resultados en formato tabular con columnas para nombre, tipo, valor, TTL y prioridad. La suborden `get-dnsbl-config` muestra el estado global de activación y una tabla de proveedores.

## Biblioteca cliente de Go

En el directorio `go/` se proporciona una biblioteca cliente de Go, importable como `gitea.com/town-os/rolodex-dns/go`. Envuelve la API gRPC con tipos Go idiomáticos y admite los mismos modos de transporte y autenticación que la CLI.

### Conexión

La función `Dial` establece una conexión y devuelve un `Client`:

- **TCP**: `Dial(ctx, "host:puerto", WithAuthToken("secreto"))` — conecta por TCP con autenticación por secreto compartido.
- **Socket Unix**: `Dial(ctx, "/ruta/al/socket", WithUnixSocket())` — conecta por socket de dominio Unix, saltándose la autenticación del lado servidor.

Una opción adicional `WithGRPCDialOption` permite pasar valores `grpc.DialOption` propios para configurar TLS o interceptores.

### Métodos del cliente

#### Gestión de registros

| Método | Descripción |
| ------ | ----------- |
| `AddRecord(ctx, record)`        | Añade un registro DNS. |
| `RemoveRecord(ctx, name, opts)` | Elimina registros por nombre con `RemoveRecordOptions` opcional (filtros de tipo y valor). Devuelve el número eliminado. |
| `ListRecords(ctx, opts)`        | Consulta registros con `ListRecordsOptions` opcional (filtro de nombre con soporte de comodín `*.`, filtro de tipo). |

#### Ámbitos de red

| Método | Descripción |
| ------ | ----------- |
| `CreateNetworkScope(ctx, scope)`                     | Crea un ámbito de red. |
| `DeleteNetworkScope(ctx, name)`                      | Borra un ámbito y todos sus registros/asociaciones. |
| `ListNetworkScopes(ctx)`                             | Recupera todos los ámbitos. |
| `JoinNetwork(ctx, ipAddress, scopeName, ttlSeconds)` | Asocia una IP con un ámbito. |
| `LeaveNetwork(ctx, ipAddress)`                       | Elimina la asociación de ámbito de una IP. |
| `GetNetworkAssociations(ctx, scopeName)`             | Recupera las asociaciones IP-a-ámbito. |
| `AddScopedRecord(ctx, scopeName, record)`            | Añade un registro dentro de un ámbito. |
| `RemoveScopedRecord(ctx, scopeName, name, opts)`     | Elimina registros de un ámbito. |
| `ListScopedRecords(ctx, scopeName, opts)`            | Consulta registros dentro de un ámbito. |
| `GetSearchDomains(ctx, ipAddress)`                   | Devuelve los dominios de búsqueda de una IP. |

#### Zonas autoritativas

| Método | Descripción |
| ------ | ----------- |
| `AddAuthoritativeZone(ctx, zone)`    | Declara una zona como autoritativa. |
| `RemoveAuthoritativeZone(ctx, zone)` | Quita una zona autoritativa. |
| `ListAuthoritativeZones(ctx)`        | Recupera todos los nombres de zona autoritativa. |

#### Métricas

| Método | Descripción |
| ------ | ----------- |
| `SetTrackedTlds(ctx, tlds)`     | Reemplaza la lista de TLD rastreados; devuelve el conjunto efectivo resultante. `nil` la limpia. |
| `ListTrackedTlds(ctx)`          | Devuelve un `TrackedTlds` con los conjuntos almacenado, efectivo y propio. |

#### Reenvío y listas de bloqueo

| Método | Descripción |
| ------ | ----------- |
| `SetForwarders(ctx, forwarders)`        | Reemplaza la lista de reenviadores upstream. |
| `SetResolutionMode(ctx, mode)`          | Cambia en caliente el modo de resolución (`auto`, `recursive`, `forward`). |
| `GetResolutionMode(ctx)`                | Devuelve el modo actualmente en vigor.                     |
| `SetDnsblConfig(ctx, enabled, providers)` | Reemplaza la configuración DNSBL (lista de bloqueo de dominios). |
| `SetDnsblConfigWithRefusalCooldown(ctx, enabled, providers, secs)` | Lo mismo, con la duración de salida de rotación de DNSBL. |
| `GetDnsblConfig(ctx)`                   | Devuelve un `DnsblStatus` con la configuración DNSBL actual. |
| `FlushCache(ctx)`                       | Limpia la caché de resultados de la lista de bloqueo. |
| `AddLocalBlocklistEntry(ctx, entry)`    | Añade una entrada a la lista de bloqueo local. |
| `RemoveLocalBlocklistEntry(ctx, name)`  | Elimina una entrada de la lista de bloqueo local. |
| `ListLocalBlocklistEntries(ctx)`        | Recupera todas las entradas de la lista de bloqueo local. |
| `AddDnsblAllowlistEntry(ctx, entry)`    | Exime a un nombre (y a sus subdominios) de la comprobación de lista de bloqueo. |
| `RemoveDnsblAllowlistEntry(ctx, name)`  | Elimina una entrada de la lista de permitidos de DNSBL. |
| `ListDnsblAllowlistEntries(ctx)`        | Recupera todas las entradas de la lista de permitidos de DNSBL. |

#### Caché DNS

| Método | Descripción |
| ------ | ----------- |
| `GetCacheStats(ctx)` | Devuelve las estadísticas de la caché. |
| `FlushDnsCache(ctx)` | Limpia la caché de respuestas DNS. |

#### Deriva de TTL y latencia

| Método | Descripción |
| ------ | ----------- |
| `SetTtlDriftConfig(ctx, config)` | Fija la configuración de deriva de TTL. |
| `GetTtlDriftConfig(ctx)`         | Devuelve la configuración de deriva de TTL. |
| `GetQueryLatencyStats(ctx)`      | Devuelve las estadísticas de latencia por servidor. |

#### Configuración de los transportes cifrados

| Método | Descripción |
| ------ | ----------- |
| `SetDotConfig(ctx, config)` / `GetDotConfig(ctx)`     | Configura DNS-over-TLS. |
| `SetDohConfig(ctx, config)` / `GetDohConfig(ctx)`     | Configura DNS-over-HTTPS. |
| `SetDoqConfig(ctx, config)` / `GetDoqConfig(ctx)`     | Configura DNS-over-QUIC. |
| `SetProxyConfig(ctx, config)` / `GetProxyConfig(ctx)` | Configura el transporte por proxy. |

#### DNSSEC

| Método | Descripción |
| ------ | ----------- |
| `GenerateDnssecKey(ctx, zone, algorithm, keyType)` | Genera un par de claves DNSSEC. |
| `ListDnssecKeys(ctx, zone)`                        | Lista las claves DNSSEC de una zona. |
| `DeleteDnssecKey(ctx, keyID)`                      | Borra una clave DNSSEC por ID. |
| `GetDsRecords(ctx, zone)`                          | Recupera los registros DS para la delegación. |
| `SignZone(ctx, zone)`                              | Firma una zona con sus claves DNSSEC. |

#### DANE, ACME y DNS64

| Método | Descripción |
| ------ | ----------- |
| `GenerateTlsaRecord(ctx, opts)`                       | Genera un registro TLSA a partir de un certificado. |
| `ListTlsaRecords(ctx, domain)`                        | Recupera los registros TLSA de un dominio. |
| `GenerateDaneRootCa(ctx, name)`                       | Genera un certificado de CA raíz DANE. |
| `RequestAcmeCert(ctx, domain, providerURL)`           | Solicita un certificado ACME vía DNS-01. |
| `GetAcmeStatus(ctx, domain)`                          | Recupera el estado del certificado ACME. |
| `SetDns64Config(ctx, config)` / `GetDns64Config(ctx)` | Configura la síntesis DNS64. |
| `EnsureZoneCa(ctx, zone)`                             | Asegura que existe la CA intermedia de la zona. |
| `CreateEabCredential(ctx, zone)`                      | Acuña una credencial EAB con alcance de zona. |
| `RemoveEabCredential(ctx, kid)`                       | Elimina una credencial EAB por kid. |
| `ListAcmeAccounts(ctx)`                               | Lista las cuentas registradas del servidor ACME. |
| `ListAcmeCertificates(ctx, zone)`                     | Lista los certificados emitidos, opcionalmente por zona. |

#### DHCP

| Método | Descripción |
| ------ | ----------- |
| `AddDhcpPool(ctx, pool)`                             | Añade un conjunto de direcciones DHCP para un ámbito. |
| `RemoveDhcpPool(ctx, poolID)`                        | Elimina un conjunto DHCP por ID. |
| `ListDhcpPools(ctx, scopeName)`                      | Lista los conjuntos DHCP, con filtro opcional por ámbito. |
| `ListDhcpLeases(ctx, scopeName)`                     | Lista las concesiones DHCP, con filtro opcional por ámbito. |
| `DeleteDhcpLease(ctx, mac)`                          | Borra una concesión DHCP por dirección MAC. |
| `AddScopeTld(ctx, scopeName, tld)`                   | Registra un TLD propio globalmente único para un ámbito. |
| `AddScopeTldWithListener(ctx, scopeName, tld, listenIP)` | Registra un TLD propio y enlaza un escucha DNS de ingreso en `listenIP`. |
| `RemoveScopeTld(ctx, scopeName, tld)`                | Quita un TLD propio de un ámbito. |
| `ListScopeTlds(ctx, scopeName)`                      | Lista los TLD que posee un ámbito. |
| `SetScopeTldForwarders(ctx, scopeName, tld, forwarders)` | Reemplaza los reenviadores pares del TLD de un ámbito. |
| `ListScopeTldForwarders(ctx, scopeName, tld)`        | Lista los reenviadores pares del TLD de un ámbito. |
| `ListScopeTldListeners(ctx, scopeName)`              | Lista los escuchas DNS de ingreso de los TLD de un ámbito. |
| `SetDhcpCertOption(ctx, opt)`                        | Fija una opción de certificado DHCP para un ámbito. |
| `RemoveDhcpCertOption(ctx, scopeName, optionCode)`   | Elimina una opción de certificado DHCP. |
| `ListDhcpCertOptions(ctx, scopeName)`                | Lista las opciones de certificado DHCP de un ámbito. |

| Otros | Descripción |
| ----- | ----------- |
| `Close()` | Libera la conexión gRPC subyacente. |

El cliente incluye automáticamente el token de autenticación en todas las llamadas RPC. Todos los métodos aceptan `context.Context` para cancelación y plazos.

### Tipos exportados

- `RecordType` — enumeración de tipos de registro DNS (constantes: `RecordTypeA`, `RecordTypeAAAA`, `RecordTypeCNAME`, `RecordTypeMX`, `RecordTypeTXT`, `RecordTypeNS`, `RecordTypeSOA`, `RecordTypeSRV`, `RecordTypePTR`, `RecordTypeURI`, `RecordTypeSSHFP`, `RecordTypeDNAME`, `RecordTypeANAME`, `RecordTypeZONEMD`, `RecordTypeTLSA`, `RecordTypeDNSKEY`, `RecordTypeDS`, `RecordTypeRRSIG`, `RecordTypeNSEC`, `RecordTypeNSEC3`, `RecordTypeNSEC3PARAM`, `RecordTypeCERT`).
- `DnsRecord` — registro DNS con nombre, tipo de registro, valor, TTL y prioridad.
- `DnsblConfig` — configuración de un proveedor DNSBL (lista de bloqueo de dominios): zona, bandera de activación, códigos de rechazo, enfriamiento de rechazo por proveedor.
- `DnsblStatus` — estado DNSBL devuelto por `GetDnsblConfig` (bandera global de activación, lista de proveedores, enfriamiento de rechazo de toda la lista, proveedores fuera de rotación).
- `RotatedProvider` — un proveedor de lista de bloqueo actualmente fuera de la rotación de consultas (zona, código de rechazo, segundos restantes).
- `RemoveRecordOptions` — filtros opcionales para `RemoveRecord` (tipo de registro, valor).
- `ListRecordsOptions` — filtros opcionales para `ListRecords` (filtro de nombre, tipo de registro).
- `NetworkScope` — ámbito de red con nombre y dominio home.
- `NetworkAssociation` — asociación IP-a-ámbito con TTL.
- `RemoveScopedRecordOptions` — filtros opcionales para `RemoveScopedRecord`.
- `ListScopedRecordsOptions` — filtros opcionales para `ListScopedRecords`.
- `CacheStats` — estadísticas de la caché DNS (entradas totales, aciertos, fallos).
- `TtlDriftConfig` — configuración de deriva de TTL (modo, ajuste fijo, multiplicador logarítmico).
- `QueryLatencyStats` — estadísticas de latencia por servidor.
- `LocalBlocklistEntry` — entrada de la lista de bloqueo local (nombre y motivo).
- `DnsblAllowlistEntry` — entrada de la lista de permitidos de DNSBL (nombre y motivo); cubre el nombre y todo lo que hay debajo.
- `DotConfig` / `DohConfig` / `DoqConfig` — configuraciones de los transportes cifrados.
- `TlsConfig` — configuración del certificado TLS (ruta del certificado, ruta de la clave, autofirmado automático).
- `ProxyConfig` — configuración del transporte por proxy (URL, autenticación, modo).
- `DnssecKey` — clave DNSSEC con zona, algoritmo, tipo de clave, etiqueta de clave, marcas de tiempo y bandera de activa.
- `DsRecord` — representación en cadena de un registro DS.
- `TlsaRecord` — representación en cadena de un registro TLSA.
- `DaneRootCa` — certificado de CA raíz codificado en PEM.
- `AcmeStatus` — estado del certificado ACME (estado, caducidad, dominio).
- `Dns64Config` — configuración DNS64 (activación, prefijo).
- `DhcpPool` — conjunto de direcciones DHCP (ámbito, rango, pasarela, máscara de subred, servidores DNS).
- `DhcpLease` — concesión DHCP (MAC, IP, ámbito, nombre de máquina, inicio/duración de la concesión, estado).
- `DhcpCertOption` — opción de certificado DHCP (ámbito, código de opción, datos del certificado, descripción).
- `TldListener` — escucha DNS de ingreso por TLD (ámbito, TLD, IP de escucha).
- `TrackedTlds` — los conjuntos de TLD rastreados devueltos por `ListTrackedTlds` (almacenado, efectivo, propio).
- `ZoneCa` — PEM de raíz + intermedia devuelto por `EnsureZoneCa`.
- `EabCredential` — credencial EAB (kid, clave HMAC, zona) devuelta por `CreateEabCredential`.
- `AcmeAccount` / `AcmeCertificate` — cuentas ACME registradas y certificados emitidos.
- `GenerateTlsaRecordOptions` — parámetros de generación de TLSA.
- `Option` — opción funcional para configurar `Dial`.

### Código protobuf generado

Los enlaces Go generados de protobuf y gRPC están en `go/rolodexdnspb/`, producidos a partir de `proto/rolodex_dns.proto`. La biblioteca cliente reexporta los tipos clave para que los consumidores no tengan que importar el paquete generado directamente.

## Biblioteca cliente de JavaScript

En el directorio `js/` se proporciona un cliente JavaScript para el emisor ACME (`rolodex-ca-client`, ESM, Node 20+, sin dependencias de ejecución). Apunta a las superficies HTTP del emisor y no a gRPC.

### Cliente del portal (`js/src/portal.js`)

`PortalClient` envuelve la API JSON del portal de inscripción de red de confianza (la misma API que usan el portal web integrado y la extensión de navegador):

| Método | Endpoint | Descripción |
| ------ | -------- | ----------- |
| `createAccount(zone)`    | `POST /api/account`       | Acuña una credencial EAB con alcance de zona (crea la CA intermedia). |
| `getCaPem()`             | `GET /api/ca`             | Descarga el PEM de la CA raíz. |
| `listZones()`            | `GET /api/zones`          | Lista las zonas inscribibles (respaldadas por una intermedia). |
| `listCertificates(zone)` | `GET /api/certs[?zone=]`  | Lista los certificados emitidos. |

El escucha del portal sirve por defecto un certificado autofirmado autogenerado, así que el constructor acepta `ca` (PEM en el que confiar) o `insecure: true` (solo red de confianza). Las respuestas que no son 2xx lanzan `PortalError` con el estado HTTP.

### Módulo DANE (`js/src/dane.js`)

Implementa la recuperación del protocolo DANE directamente sobre el formato de cable de DNS (el resolutor de Node no expone TLSA):

- `fetchTlsaRecords(domain, {port, protocol, dnsServer, dnsPort, transport})` — consulta `_<puerto>._<protocolo>.<dominio>.` por TLSA sobre UDP con caída automática a TCP ante truncamiento (o TCP forzado). NXDOMAIN produce `[]`; otros rcodes lanzan `DnsError`.
- `certAssociationData(certPem, selector, matchingType)` — calcula los datos de asociación del RFC 6698 a partir de un certificado PEM vía `node:crypto` (selector 0 = certificado DER completo, 1 = SPKI; coincidencia 0/1/2 = exacta/SHA-256/SHA-512), reflejando el `dane::generate_tlsa_record` de Rust.
- `verifyCertAgainstTlsa(certPem, record)` / `matchDane(records, chainPem)` — verifican los registros recuperados contra un certificado o contra una cadena `hoja + intermedia` (con la publicación DANE-TA de Rolodex la intermedia es la coincidencia esperada).
- Los ayudantes del códec de cable (`encodeQuery`, `decodeMessage`, `encodeResponse`, `parseTlsaRdata`, …) se exportan y son simétricos, y los reutilizan los servidores DNS simulados de las pruebas.

### Interfaz local de inscripción (`js/bin/rolodex-ca-ui.js`, `js/src/ui_server.js`, `js/ui/`)

`rolodex-ca-ui` sirve una consola web local (HTTP plano en un enlace de loopback) que hace de proxy de la API del portal sobre su TLS autofirmado —así el navegador nunca necesita confiar en el certificado del portal— y añade un endpoint `POST /api/dane` que realiza búsquedas TLSA en vivo (algo que un navegador no puede hacer) con verificación opcional de una cadena PEM pegada. Banderas: `--portal`, `--bind`, `--dns`, `--ca`, `--insecure`.

### Pruebas de JavaScript

- **Pruebas unitarias** (`js/test/*.test.js`, `node:test`) — ida y vuelta del códec de cable DNS (incluidos punteros de compresión y rechazo de bucles de punteros), recuperación TLSA contra servidores DNS UDP/TCP simulados en proceso (caída por truncamiento, NXDOMAIN, SERVFAIL, tiempo de espera), cliente del portal contra un portal HTTPS autofirmado simulado, y los endpoints de proxy y DANE del servidor de la interfaz. El módulo `ca_dns.js` de la extensión de navegador se prueba aquí también (`extension.test.js`): interoperabilidad del códec contra el codificador de Node, extracción de campos DER X.509 contrastada con `node:crypto`, reensamblado de trozos TXT (barajados/incompletos/datos ajenos), recuperación con preferencia por CERT y reserva a TXT, y verificación DANE-TA — todo con DoH simulado. Los datos de asociación de certificado se contrastan con fixtures Ed25519 generados con openssl en `js/test/fixtures/`, cuyos digest esperados de SPKI/certificado se calcularon con openssl — un oráculo independiente de `node:crypto`.
- **Pruebas de integración** (`js/test/integration.test.js`, `js/test/ca_dns_integration.test.js`, arnés compartido en `js/test/server_helper.js`) — condicionadas a `ROLODEX_DNS_BINARY`; lanzan un servidor real con el emisor ACME (y DoH) activados en un directorio temporal aislado con puertos aleatorios. Ejercitan el flujo del portal (acuñación de EAB, listado de zonas, descarga de la CA raíz) y una comprobación DANE entre implementaciones: el lado Rust publica un registro TLSA DANE-TA para la intermedia de la zona (mediante `ensure-zone-ca` + `generate-tlsa` por la CLI del socket Unix), y el cliente JS lo recupera sobre DNS UDP y TCP reales y recalcula independientemente el SHA-256 del SPKI a partir del PEM de la intermedia. Las dos implementaciones deben coincidir. La batería de CA-por-DNS recupera la cadena publicada mediante registros CERT sobre DoH y UDP plano, reensambla la reserva TXT, compara ambas byte a byte con la salida de `ensure-zone-ca` y con la CA raíz del portal, y ejecuta la verificación DANE-TA de extremo a extremo.

## Métricas de Prometheus

Una sección de configuración `metrics` opcional arranca un endpoint de raspado en HTTP plano en `/metrics` (por defecto `127.0.0.1:9153`; `/` sirve un enlace a él). La sección está **ausente por defecto**, así que no se arranca escucha alguno y una actualización no abre ningún puerto nuevo.

**HTTP plano, loopback por defecto.** El endpoint no está autenticado y lleva solo recuentos agregados — sin nombres de consulta, sin valores de registro, sin material de certificados. TLS aquí significaría distribuir el certificado autofirmado a todos los raspadores para un endpoint que debería estar enlazado a una dirección privada de todos modos, así que el enlace por defecto es loopback en su lugar.

### Implementación (`src/metrics.rs`)

El registro está hecho a mano sobre las mismas primitivas sin cerrojos que el resto del servidor —contadores/medidores `AtomicU64`, `DashMap` para las dimensiones de etiqueta conocidas solo en tiempo de ejecución— y renderiza el formato de exposición en texto directamente. **Sin dependencia de ningún crate de métricas.** Incrementar un contador en la ruta caliente es un `fetch_add` relajado sobre una serie ya reservada: sin hashing, sin reservas, sin cerrojos.

- **Registro global.** La instrumentación llama a `metrics()`, un `LazyLock<Metrics>`. Enhebrar un `Arc<Metrics>` por la ruta de consulta, ambas cachés, el resolutor, las listas de bloqueo, DHCP, el emisor ACME y el servicio gRPC habría supuesto cambiar todos los constructores y todos los puntos de llamada de las pruebas. Consecuencia para las pruebas: los contadores se acumulan a lo largo de un binario de pruebas, así que las aserciones son diferencias tomadas bajo un cerrojo serializador (`tests/metrics_test.rs`).
- **Cardinalidad acotada.** Toda etiqueta es una enumeración fija (`Proto`, `RCODES`, `ANSWER_SOURCES`, `TIERS`, `FAMILIES`, …) o está acotada por la configuración (direcciones de servidores upstream, nombres de método gRPC, TLD rastreados). Las dos dimensiones que un cliente controla se pliegan ambas en un cajón de sastre: el *tipo* de consulta pliega los tipos no reconocidos en `OTHER`, y el *TLD* pliega cualquier cosa no rastreada en `other`, así que ni una inundación de consultas `TYPE4242` ni un barrido de TLD basura pueden acuñar series. Los **nombres de consulta nunca son etiquetas** — solo el sufijo TLD, y solo uno al que el operador ya se ha adherido.
- **Separación por subsistemas.** DHCP etiqueta sus dimensiones como `message_type` y `lease_state` en vez de los genéricos `type` y `state`, así que una agregación que abarque ambos subsistemas no puede mezclar un recuento de DHCP con uno de DNS, y los agregados de DNS (`queries_total`, `traffic_bytes_total`, `records_served_total`, `queries_by_tld_total`) cuentan solo DNS — el tráfico de `:67` de DHCP nunca es tráfico DNS, y un nombre registrado por DHCP llega a estas métricas solo cuando alguien lo resuelve.
- **Empuje frente a tirón.** Los contadores se empujan donde ocurre el trabajo. Los medidores sin punto natural de empuje (recuentos de filas, tamaños de caché, nivel activo, latencia por servidor de nombres) los tira una vez por raspado `metrics::collect`, que lee todos los recuentos de la base de datos en una sola llamada a `Database::metrics_counts` con una única adquisición de cerrojo, en vez de una docena de llamadas `list_*` que materializarían zonas enteras para tomar un `.len()`.
- Los **histogramas** guardan las observaciones en una unidad nativa entera (nanosegundos, bytes) para que la suma acumulada no necesite un CAS de coma flotante, dividiendo por una escala en el momento de renderizar; los recuentos de bucket se acumulan en la forma acumulativa `le` al renderizar.

### Atribución de consultas

`rolodex_dns_answers_total{source}` informa de qué etapa del orden de resolución produjo cada respuesta — `cache`, `local`, `scoped`, `scope_fallback`, `tld_peer`, `blocklist`, `reverse_blocklist`, `dns64`, `upstream`, `authoritative_nxdomain`, `refused`, `error`. Esto es lo que hace legible desde fuera la tubería de horizonte partido, y su total es igual al total de consultas.

`resolve_query` tiene aproximadamente treinta salidas. En vez de instrumentar cada una —donde un nuevo retorno temprano se escaparía en silencio de las métricas— se enhebra un `QueryTag` y cada salida que no es upstream se etiqueta a sí misma; el valor inicial es `upstream`, que es como termina la función por caída. La observación se registra entonces en **una** salida instrumentada, `DnsServer::handle_query_proto`, por la que embudan todos los transportes, *después* del filtro de familia de direcciones, así que el rcode y el tamaño de respuesta registrados son los que el cliente recibe realmente. La etiqueta `proto` (`udp`/`tcp`/`dot`/`doh`/`doq`) solo etiqueta métricas y nunca afecta a la resolución; los envoltorios preexistentes `handle_query`/`handle_query_from`/`handle_query_on` conservan sus firmas e informan `udp`.

El `QueryTag` lleva la etiqueta `tld` por la misma razón: se resuelve una vez, en `resolve_query`, donde el nombre de la pregunta decodificado ya está a mano, en vez de en la salida — que solo tiene los bytes de cable, donde el nombre son etiquetas con prefijo de longitud que habría que decodificar por segunda vez. Un nombre no rastreado no pone nada y se lee de vuelta como `other`, así que el caso común no cuesta ninguna reserva.

`rolodex_dns_traffic_bytes_total{direction}` y `rolodex_dns_records_served_total` viajan en esa misma observación única, así que no se puede contar una consulta sin que se cuenten también sus bytes. Los recuentos de registros vienen del campo ANCOUNT de la cabecera de respuesta y no de reanalizar un mensaje que el servidor acaba de serializar.

### Aislamiento por TLD

`rolodex_dns_queries_by_tld_total{tld}` separa el flujo de consultas por TLD — lo que hace distinguibles entre sí, y de la internet pública, las redes de un despliegue de horizonte partido. El conjunto rastreado tiene tres fuentes, unidas:

1. **TLD propios, automáticamente** — todo TLD de `scope_tlds`, incluido el dominio `.home` implícito de cada ámbito, leído de `tld_owner_cache` y no de SQLite. El espacio de nombres propio de una red es lo que más merece aislarse, y exigir que se nombre dos veces (poseído, luego rastreado) es una trampa que se manifiesta como una serie que falta en silencio.
2. **`metrics.tracked_tlds`** en el fichero de configuración, fijado: sobrevive a los reinicios y no se puede quitar por la API.
3. **La lista almacenada**, reemplazada por `SetTrackedTlds` y leída de vuelta por `ListTrackedTlds`.

La entrada mágica `common` se expande a `metrics::COMMON_TLDS`. Se almacena **sin expandir**, así que una relectura informa de lo que pidió el operador y un cambio posterior de la constante surte efecto sin que cada despliegue reemita la llamada — la misma forma que `none` en `dnsbl.providers[].refusal_codes`.

`Metrics::tld_label` recorre los sufijos del nombre consultado de más específico a menos contra el conjunto y devuelve una **porción del nombre**, así que un despliegue que rastree `home.` y `lab.home.` atribuye `box.lab.home.` al más específico, y un nombre no rastreado no reserva nada. La entrada raíz `.` se rechaza con `InvalidArgument`, porque es sufijo de todo nombre: rastrearla colapsaría todas las series en una y haría inalcanzable `other`.

`refresh_tracked_tlds` recalcula la unión y se llama al arrancar, desde todos los puntos de mutación de ámbito/TLD del servicio gRPC, y desde `collect` como red de seguridad — así que una mutación perdida se autocorrige en el siguiente raspado en vez de quedarse mal hasta un reinicio. Un fallo de base de datos ahí deja el conjunto anterior en su sitio en vez de limpiarlo.

### Qué se expone

82 familias de métricas, todas con el prefijo `rolodex_dns_`:

| Área | Métricas |
| ---- | -------- |
| Proceso | `build_info{version}`, `start_time_seconds`, `uptime_seconds`, `metrics_scrapes_total` |
| Consultas | `queries_total{proto,rcode}`, `queries_by_type_total{qtype}`, `queries_by_tld_total{tld}`, `answers_total{source}`, `traffic_bytes_total{direction}` (`rx`/`tx`), `records_served_total`, `query_duration_seconds{proto}` (histograma), `query_size_bytes`, `response_size_bytes`, `responses_truncated_total`, `malformed_queries_total`, `edns_unsupported_version_total`, `edns_do_queries_total`, `ingress_rewrites_total`, `answers_family_filtered_total{family}` |
| Caché de respuestas | `cache_hits_total`, `cache_misses_total`, `cache_negative_hits_total`, `cache_expired_total`, `cache_flushes_total{reason}` (`mutation`/`explicit`/`tier_switch`), `cache_entries`, `cache_negative_entries` |
| Listas de bloqueo | `blocklist_blocks_total{kind}` (`local`/`dnsbl_provider`), `blocklist_allowlisted_total{kind}` (`forward_name`/`reverse_name`/`ip_literal`), `blocklist_lookups_total{kind,result}` (`listed`/`not_listed`/`error`/`refused`), `blocklist_skipped_total`, `blocklist_cache_entries`, `blocklist_refusals_total{kind}`, `blocklist_rotated_out` |
| Upstream | `upstream_active_tier`, `upstream_tier_attempts_total{tier}`, `_wins_total{tier}`, `_failures_total{tier}`, `upstream_tier_switches_total{direction}`, `upstream_recovery_probes_total`, `upstream_duration_seconds{tier}`, `upstream_queries_total{server}`, `upstream_exhausted_total` |
| Resolutor | `resolver_lookups_total`, `_referrals_total`, `_cname_hops_total`, `_budget_exhausted_total`, `_tcp_retries_total`, `resolver_priming_total{result}`, `resolver_nameserver_latency_milliseconds{server}`, `delegation_cache_entries`, `record_cache_entries` |
| DNSSEC | `dnssec_verdicts_total{verdict}` (`secure`/`insecure`/`bogus`/`indeterminate`), `dnssec_servfail_total`, `dnssec_dnskey_lookups_total`, `dnssec_insecure_delegations_total`, `dnssec_hidden_zone_cuts_total`, `dnssec_unsigned_responses_total{evidence}` (`child_apex_soa`/`none`), `dnssec_blamed_roots`, `key_cache_entries` |
| Horizonte partido | `records`, `scoped_records`, `scopes`, `scope_associations`, `authoritative_zones`, `managed_zones`, `owned_tlds`, `ingress_listeners`, `address_family_reachable{family}` |
| DHCP | `dhcp_messages_total{message_type}`, `dhcp_leases{lease_state}`, `dhcp_pools`, `dhcp_allocation_failures_total`, `dhcp_sweeps_total` |
| ACME | `acme_accounts`, `acme_certificates`, `acme_issued_total`, `acme_validations_total{result}` |
| gRPC | `grpc_requests_total{method}`, `grpc_auth_failures_total` |
| Bloqueo del runtime | `blocking_duration_seconds{site}` (histograma), `blocking_stalls_total{site}` |

`dhcp_messages_total` deliberadamente no tiene etiqueta `nak`: el servidor nunca envía uno, y una serie clavada en cero para siempre se lee como una señal cuando solo es una rama sin implementar. Su etiqueta es `message_type`, y `dhcp_leases` usa `lease_state`, en vez de los genéricos `type`/`state` — véase Separación por subsistemas más arriba.

#### Bloqueo del runtime

El único par de familias que trata del proceso en vez de tratar del DNS. El servidor es `async` de principio a fin, pero varias de las cosas que tiene que hacer son síncronas: SQLite vive detrás de un único `std::sync::Mutex<Connection>`, los ficheros de certificado se leen del disco, y la aritmética de firmas es aritmética. Cada una de ellas ocupa el hilo en el que corre durante toda su duración, y en un worker de Tokio eso es un hilo que no está sondeando nada más — una consulta lenta no solo hace esperar a quien la lanzó, hace esperar a todas las consultas que ese worker estaba multiplexando. Ese acoplamiento es invisible en `query_duration_seconds`, que reparte el síntoma entre nombres que no tienen nada que ver y no da forma de atribuirlo.

`site` es un enum fijo, al que se añade por el final y en el que nunca se inserta, porque los valores son posiciones dentro de un array preasignado:

| `site` | Región | Hilo |
| ------ | ------ | ---- |
| `db_lock_wait` | Esperar a adquirir el mutex de la conexión SQLite | Worker |
| `db_locked` | Tenerlo: la sentencia, más la decodificación de filas | Worker |
| `db_open` | Apertura, migración y carga de cachés al arrancar | Antes del listener |
| `metrics_collect` | El muestreo de gauges de un scrape | Worker |
| `tls_reload` | Relectura del certificado, hash y parseo de PEM | Pool de bloqueo |
| `dnssec_sign` | Generar un RRSIG | Worker |
| `dnssec_verify` | Verificar los RRSIG de un RRset, con todas las claves candidatas | Worker |
| `config_load` | Leer y parsear el fichero de configuración | Antes del listener |

`db_lock_wait` y `db_locked` están separados porque significan cosas opuestas: el tiempo de espera es lo que te cuestan *otros* llamantes, el tiempo de tenencia es lo que tú les cuestas a ellos. Hay exactamente una conexión, así que los dos son el cuadro completo de la contención, y ambos se registran desde `Database::lock` — el único cuello de botella por el que pasa cada método que toca SQLite, que es la razón de que un método añadido más tarde quede instrumentado sin que nadie se acuerde de instrumentarlo. El tiempo de tenencia se toma en el `Drop` de la guarda, de modo que un retorno de error temprano se mide durante todo el tiempo que realmente tuvo la conexión.

`blocking_stalls_total` cuenta las observaciones iguales o superiores a 10ms (`metrics::BLOCKING_STALL_NANOS`). El histograma ya lleva la distribución entera; el contador existe para que una alerta pueda decir "con qué frecuencia" sin tener que reescribir el límite de un bucket. 10ms está un orden de magnitud por encima de una respuesta local en caliente y un orden de magnitud por debajo del timeout upstream por servidor de nombres — el rango en el que un worker bloqueado empieza a costar consultas que no tenían nada que ver con el trabajo que se estaba haciendo.

Tres sitios están deliberadamente fuera de un hilo worker: `tls_reload` corre en el pool de bloqueo (el directorio de datos puede ser un medio extraíble), y `db_open` y `config_load` corren antes de que se ate ningún listener. Se miden igualmente, porque "esto es lo bastante rápido como para no importar" es una afirmación que merece una serie en vez de un comentario que la asegure.

### PromQL habitual

El README lleva un recetario de consultas (tasa de consultas por transporte, atribución de respuestas, tasa de aciertos de caché, factor de amplificación, porcentaje bloqueado, tasas por TLD, degradación de nivel, DNSSEC bogus, estados de las concesiones DHCP). Esas consultas están **probadas**: `tests/promql_docs_test.rs` extrae todos los bloques ```promql de `README.md` y `DESIGN.md`, saca los nombres de métrica y los emparejadores de etiqueta, y resuelve cada uno contra la salida de exposición en vivo. Una consulta documentada que nombre una serie o un valor de etiqueta que no existe hace fallar la batería — que es lo que mantiene honesta la documentación a través de un renombrado como `{type}` → `{message_type}`. El mismo fichero afirma además que el **recuento de familias** documentado coincide con lo que `render` emite realmente, así que el número de estos documentos no puede volver a derivar.

Una segunda capa pasa las mismas consultas por un Prometheus real: `make prometheus-test` arranca el servidor, ejecuta el contenedor `quay.io/prometheus/prometheus` contra él, y ejecuta cada consulta documentada por la API HTTP, así que una consulta mal formada *como PromQL* —y no meramente una que nombre una serie inexistente— también se caza. `make test` depende de ello. Sin podman salta ruidosamente en vez de fallar, así que una máquina sin contenedores sigue obteniendo una ejecución en verde; `ROLODEX_PROMETHEUS_REQUIRED=1` hace ese salto fatal para CI.

## Configuración

La configuración se carga desde un fichero YAML (ruta por defecto `rolodex-dns.yml`, sustituible con la bandera `-c`/`--config` de la CLI). Si el fichero no existe, se usan valores por defecto razonables.

### Sintaxis de las direcciones de enlace

Las cadenas de dirección de enlace (usadas por `dns.bind`, `dot.bind`, `doh.bind`, `doq.bind`, `grpc.tcp_bind`, `dhcp.bind`) aceptan cuatro formas:

| Forma | Ejemplo | Descripción |
| ----- | ------- | ----------- |
| `ip:puerto` | `192.168.1.1:53` | Enlazar a una dirección IPv4 y puerto concretos |
| `[ipv6]:puerto` | `[::1]:53` | Enlazar a una dirección IPv6 y puerto concretos (los corchetes son obligatorios) |
| `primary:puerto` | `primary:53` | Detectar la IP saliente de la ruta por defecto del SO y enlazar a ella |
| `interfaz:puerto` | `eth0:53` | Resolver todas las direcciones IP de la interfaz de red nombrada y enlazar a cada una |

La palabra clave `primary` detecta qué dirección IP usaría el SO para alcanzar la internet pública (mediante un connect UDP que no envía datos a `8.8.8.8:53`) y enlaza un único escucha en esa dirección. La palabra clave es insensible a mayúsculas.

El enlace por interfaz crea un escucha por cada dirección IP asignada a la interfaz. Por ejemplo, si `eth0` tiene tanto `192.168.1.5` como `fe80::1`, entonces `eth0:53` crea dos escuchas: `192.168.1.5:53` y `[fe80::1]:53`.

El campo `dns.bind` es una lista de pares protocolo/dirección. Cada entrada es un mapa de una sola clave con `udp` o `tcp` como clave y una dirección de enlace como valor:

```yaml
dns:
  bind:
    - udp: "eth0:53"
    - udp: "127.0.0.1:53"
    - tcp: "eth0:53"
    - tcp: "primary:53"
```

### Campos de configuración

| Campo | Por defecto | Descripción |
| ----- | ----------- | ----------- |
| `dns.bind`                          | `[{udp: "0.0.0.0:53"}, {tcp: "0.0.0.0:53"}]` | Escuchas DNS; lista de entradas `{udp: dir}` / `{tcp: dir}` |
| `dns.auto_ptr`                      | `false`                        | Mantener automáticamente registros PTR inversos para A/AAAA añadidos por gRPC (véase Registros PTR inversos automáticos) |
| `dns.ingress_listen_port`           | `53`                           | Puerto UDP/TCP para los escuchas de ingreso por TLD (la IP de enlace es por TLD; véase Escuchas DNS de ingreso) |
| `dns.udp_shards`                    | `0` (uno por núcleo)           | Sockets `SO_REUSEPORT` enlazados por dirección de escucha UDP; `1` restaura el escucha de socket único (véase Modelo de concurrencia) |
| `grpc.tcp_bind`                     | `127.0.0.1:50051`              | Escucha TCP de gRPC; admite interfaz:puerto (vacío para desactivar) |
| `grpc.unix_socket`                  | `/var/run/rolodex-dns.sock`    | Ruta del socket Unix de gRPC (vacía para desactivar) |
| `grpc.shared_secret`                | (vacío)                        | Secreto compartido para la autenticación gRPC por TCP |
| `forwarders`                        | `["8.8.8.8:53", "8.8.4.4:53"]` | Resolutores DNS upstream (el nivel `local` en modo `auto`; el único upstream en modo `forward`) |
| `resolution.mode`                   | `auto`                         | Estrategia upstream: `auto` (cadena de niveles), `recursive` (solo raíces), `forward` (solo reenviadores) |
| `resolution.root_hints`             | `[]` (raíces IANA integradas)  | Sustituye las pistas de servidor raíz usadas en modo `recursive`/`auto` |
| `resolution.secure_upstreams`       | Cloudflare + Google sobre DoH  | Upstreams cifrados para el nivel `secure`; cada entrada es `{transport: https\|tls, addr, hostname, path}` |
| `resolution.public_fallback`        | `["1.1.1.1:53", "8.8.8.8:53"]` | Resolutores públicos en claro, probados los últimos en modo `auto` |
| `resolution.switch_grace_failures`  | `3`                            | Consultas desviadas consecutivas antes de confirmar una degradación de nivel en `auto` |
| `resolution.recovery_probe_secs`    | `60`                           | Cada cuánto la sonda de fondo reevalúa los niveles por encima de una cadena `auto` degradada |
| `resolution.delegation_persist_min_ttl` | `300`                      | TTL mínimo para que una delegación aprendida se persista en SQLite |
| `resolution.default_ttl`            | `300`                          | TTL de reserva donde un registro/respuesta no aporta ninguno; un TTL presente siempre se honra |
| `dnssec.validate`                   | `true`                         | Validar DNSSEC en las respuestas resueltas iterativamente; los datos bogus se convierten en SERVFAIL (véase Validación DNSSEC del upstream) |
| `dnssec.trust_anchors`              | `[]` (claves raíz de IANA)     | Anclas de confianza como `"<flags> <protocol> <algorithm> <clave base64>"` (los campos RDATA de un DNSKEY, tal como los imprime `dig`); cada campo se valida en el arranque y uno malo es un fallo duro. Una sustitución **reemplaza** las claves de IANA en vez de sumarse a ellas |
| `database_path`                     | `rolodex-dns.db`               | Ruta del fichero de base de datos SQLite |
| `dnsbl.providers[].refusal_codes`   | `[]` (conjunto integrado)      | Códigos que significan «consulta rechazada» y no «listado»; `none` desactiva la detección para ese proveedor |
| `dnsbl.enabled`                     | `false`                        | Bandera global de activación de DNSBL (lista de bloqueo de dominios) |
| `dnsbl.providers`                   | `[]` (vacía)                   | Lista de proveedores DNSBL; cada entrada toma `zone`, `enabled` y opcionalmente `refusal_codes` / `refusal_cooldown_secs` |
| `dnsbl.refusal_cooldown_secs`       | `3600`                         | Segundos que un proveedor que rechaza permanece fuera de rotación, para los proveedores que no fijan ninguno |
| `dot.bind`                          | `0.0.0.0:853`                  | Escucha DoT; admite interfaz:puerto (sección opcional) |
| `dot.tls.cert_path`                 | (ninguna)                      | Ruta del certificado TLS |
| `dot.tls.key_path`                  | (ninguna)                      | Ruta de la clave privada TLS |
| `dot.tls.auto_self_signed`          | `true`                         | Autogenerar certificado autofirmado |
| `dot.tls.self_signed_sans`          | `[]` (vacía)                   | Nombres alternativos del asunto adicionales para un certificado generado; el conjunto de loopback y las direcciones de enlace del escucha se añaden automáticamente |
| `doh.bind`                          | `0.0.0.0:443`                  | Escucha DoH; admite interfaz:puerto (sección opcional) |
| `doh.tls.*`                         | (igual que DoT)                | Ajustes TLS para DoH |
| `doh.enable_h3`                     | `false`                        | Activar el transporte HTTP/3 (QUIC) para DoH |
| `doq.bind`                          | `0.0.0.0:8853`                 | Escucha DoQ; admite interfaz:puerto (sección opcional) |
| `doq.tls.*`                         | (igual que DoT)                | Ajustes TLS para DoQ |
| `proxy.url`                         | (vacía)                        | URL del proxy (por ejemplo `socks5://127.0.0.1:1080`) |
| `proxy.auth`                        | (ninguna)                      | Autenticación del proxy (`usuario:clave`) |
| `proxy.mode`                        | `connect`                      | Modo del proxy (`connect`, `socks5` o `doh`) |
| `ttl_drift.mode`                    | `disabled`                     | Modo de deriva de TTL (`disabled`, `fixed`, `logarithmic`) |
| `ttl_drift.fixed_adjustment`        | `0s`                           | Duración del ajuste fijo de TTL |
| `ttl_drift.log_multiplier`          | `0.1`                          | Sensibilidad de la deriva logarítmica |
| `dns64.enabled`                     | `false`                        | Activar la síntesis AAAA de DNS64 |
| `dns64.prefix`                      | `64:ff9b::`                    | Prefijo NAT64 para la síntesis |
| `security.qname_case_randomization` | `true`                         | Codificación 0x20 como resistencia al envenenamiento de caché |
| `security.overlay_cidrs`            | `["10.64.0.0/10"]`             | Rangos de origen tratados como pares de superposición no fiables y con ámbito impuesto; todo otro origen es de confianza |
| `security.recursion_cidrs`          | loopback, RFC 1918, enlace local, ULA, CGNAT | Rangos de origen a los que se permite dirigir la resolución **upstream**; los demás reciben solo datos locales y son REFUSED para lo demás (véase Control de acceso a la recursión) |
| `address_family.mode`               | `auto`                         | `auto` (sondear y suprimir una familia no enrutable), `off`, `force4`, `force6` |
| `address_family.probe_interval_secs`| `30`                           | Segundos entre sondas de enrutabilidad en modo `auto` |
| `address_family.fail_threshold`     | `2`                            | Ciclos de sonda fallidos consecutivos antes de marcar una familia como caída (la recuperación es inmediata) |
| `address_family.probe_timeout_secs` | `2`                            | Tiempo límite del connect TCP por destino en cada sonda |
| `address_family.targets_v4` / `targets_v6` | Cloudflare/Google en `:443` | Destinos de sonda por familia (IP literales) |
| `dhcp.bind`                         | `0.0.0.0:67`                   | Escucha DHCP; admite interfaz:puerto (sección opcional) |
| `dhcp.default_lease_duration`       | `3600`                         | Duración por defecto de la concesión DHCP en segundos |
| `dhcp.reclaim_timeout`              | `86400`                        | Segundos tras la caducidad antes de recuperar la IP |
| `dhcp.sweep_interval`               | `60`                           | Intervalo del barrido de concesiones en segundo plano, en segundos |
| `dhcp.tld`                          | (obligatorio)                  | TLD para el registro DNS de nombres de máquina (por ejemplo `example.com`) |
| `acme.bind`                         | `0.0.0.0:8555`                 | Escucha HTTPS de ACME de cara al cliente; admite interfaz:puerto |
| `acme.portal_bind`                  | `127.0.0.1:8500`               | Escucha del portal de inscripción de red de confianza (portal + `/api`) |
| `acme.tls.*`                        | (igual que DoT)                | Ajustes TLS para los escuchas de ACME y del portal |
| `acme.directory_url`                | `https://localhost:8555/acme`  | URL externa del directorio ACME anunciada a los clientes (ponla) |
| `acme.root_ca_cn`                   | `Rolodex Root CA`              | Common name de la CA raíz creada al arrancar |
| `acme.leaf_validity_days`           | `90`                           | Validez de los certificados de hoja emitidos |
| `acme.tlsa_port` / `acme.tlsa_proto`| `443` / `tcp`                  | Dónde se publica el registro TLSA DANE-TA por nombre |
| `acme.tlsa_endpoints`              | `[]`                           | Endpoints `"<puerto>/<protocolo>"` extra para el registro DANE-TA. Un certificado que sirve DoT (`853/tcp`) y DoQ (`853/udp`) necesita un registro por endpoint; una entrada malformada detiene el arranque. Un endpoint que un escucha sirve con sus propios ficheros de certificado se descarta al arrancar, con el motivo: la asociación de ACME fijaría un certificado que ese endpoint nunca presenta |
| `acme.require_eab`                  | `true`                         | Exigir External Account Binding para el registro de cuentas |
| `acme.issuance_scope`               | `managed_zones`                | `managed_zones` (la zona debe tener una CA) o `any` |
| `metrics.bind`                      | `127.0.0.1:9153`               | Escucha HTTP `/metrics` de Prometheus; admite interfaz:puerto (sección opcional) |
| `metrics.tracked_tlds`              | `[]`                           | TLD a los que se da su propia etiqueta `tld` en las métricas de consultas por TLD. Los TLD propios se rastrean automáticamente; la entrada `common` se expande al conjunto integrado de TLD comunes; cualquier cosa no rastreada se pliega en `other` (véase Aislamiento por TLD) |

Las secciones `dot`, `doh`, `doq`, `proxy`, `acme` y `metrics` son opcionales. Cuando se omiten, el transporte/servicio correspondiente no se arranca. Cuando `acme` está presente, la CA raíz se crea al arrancar y arrancan tanto el escucha de ACME como el del portal.

## Sistema de compilación

El proyecto usa un Makefile de nivel superior con los siguientes objetivos:

| Objetivo | Descripción |
| -------- | ----------- |
| `help`                | Imprime todos los objetivos con sus descripciones, agrupados por sección. Es el objetivo por defecto, así que un `make` pelado lo muestra. Las descripciones vienen de anotaciones `##` en las líneas de objetivo; las líneas `##@` inician secciones. |
| `build`               | Compila los binarios para `TARGET`: un `cargo build` de depuración de forma nativa, o una compilación de release cruzada cuando `TARGET` es una arquitectura ajena. |
| `test`                | Ejecuta todas las pruebas: lint, pruebas de integración de Go, pruebas unitarias de Go, pruebas de Rust (`cargo test`) y pruebas de JavaScript. |
| `test-log`            | Igual que `test`, con la salida duplicada a un fichero de registro con marca de tiempo bajo `/tmp/rolodex-dns/log` (sustituible con `LOG_DIR`). La ruta del registro se imprime al final incluso cuando la ejecución falla. |
| `rust-test`           | Ejecuta los ficheros de pruebas de integración de Rust, y luego `cargo test`. |
| `rust-integration-test` | Compila y luego ejecuta explícitamente cada fichero de pruebas de integración de Rust (`integration_test`, `new_features_test`, `cli_integration_test`, `dhcp_integration_test`, `acme_issuer_test`, `auto_resolution_test`, `metrics_test`, `blocking_metrics_test`, `promql_docs_test`, `prometheus_integration_test`, `blocklist_refusal_test`, `dnssec_signing_test`, `dnssec_validation_test`, `dnssec_hidden_cut_test`, `arpa_refusal_test`, `blocklist_nxdomain_test`, `zonemd_test`, `dot_test`, `doq_test`, `proxy_test`, `tls_reload_test`, `acme_admin_test`, `acme_tlsa_endpoints_test`, más las baterías `security_*`). |
| `lint`                | Ejecuta `translation-check`, `cargo fmt -- --check` y `cargo clippy --all-targets -- -D warnings`. |
| `prometheus-test`     | Ejecuta cada consulta PromQL documentada contra un Prometheus en contenedor (`quay.io/prometheus/prometheus`, sustituible con `ROLODEX_PROMETHEUS_IMAGE`). Es prerrequisito de `test`. Necesita podman; sin él la prueba **salta ruidosamente** en vez de fallar, así que una máquina sin runtime de contenedores sigue obteniendo un `make test` en verde. `ROLODEX_PROMETHEUS_REQUIRED=1` convierte ese salto en un fallo, que es lo que CI debería poner. |
| `deps`                | Instala las dependencias de compilación: la cadena de herramientas de compilación cruzada de Rust (`cross-deps`), las dependencias de desarrollo de JavaScript (`npm install` en `js/`) y `python-deps`. |
| `cross-deps`          | Instala la cadena cruzada de Rust: `rustup target add` para ambos triples, `cargo-zigbuild` y zig. Sin root — véase Compilación cruzada. |
| `python-deps`         | Comprueba que `python3` está en el PATH. Es prerrequisito tanto de `deps` como de `translation-check`. Al ser un intérprete del sistema, este paso lo comprueba y lo nombra en vez de instalarlo. |
| `js-lint`             | Ejecuta eslint sobre el paquete JavaScript (depende de `deps`). |
| `js-test`             | Ejecuta las pruebas unitarias de JavaScript (depende de `js-integration-test`). |
| `js-integration-test` | Compila los binarios de Rust, pasa el lint, y luego ejecuta las pruebas de integración de JavaScript con `ROLODEX_DNS_BINARY` apuntando al servidor compilado. |
| `bench`               | Ejecuta los benchmarks de criterion (`cargo bench --bench dns_perf`). Los benchmarks cubren la aleatorización de QNAME, la generación de claves de caché, las búsquedas en la BD, la coincidencia de zonas y las operaciones de caché. |
| `clean`               | Limpia los artefactos de compilación (`cargo clean`). |
| `go-test`             | Ejecuta las pruebas unitarias de Go (depende de `go-integration-test`). |
| `go-integration-test` | Compila los binarios de Rust, y luego ejecuta las pruebas de integración de Go con la etiqueta de compilación `integration`, pasando la ruta del binario del servidor compilado por `ROLODEX_DNS_BINARY`. |
| `install`             | Instala los binarios de Rust en el directorio bin de Cargo (`cargo install --path .`). |
| `dev`                 | Compila el proyecto Rust en modo depuración y luego arranca un servidor de desarrollo usando `dev.yml`. |
| `dev-release`         | Compila el proyecto Rust en modo release y luego arranca un servidor de desarrollo usando `dev.yml`. |
| `image`               | Compila una imagen de contenedor para `TARGET` (por defecto: la arquitectura del equipo) usando `make/build.sh release`: compilación cruzada, preparación y luego `podman build --platform`. Etiqueta con el sufijo `BUILD_ARCH` (`-x86_64`/`-aarch64`). Acepta `IMAGE_TAG` (por defecto `latest`). |
| `push` / `push-rc`    | Compila y sube la imagen candidata a release de la arquitectura `TARGET` a `quay.io/town/rolodex`. Autoetiqueta `rc.YYYYMMDD-<arch>` + `rc.latest-<arch>` (por ejemplo `rc.latest-x86_64`/`rc.latest-aarch64`) salvo que se ponga `IMAGE_TAG`. |
| `push-arch`           | Compila y sube SOLO la etiqueta por arquitectura de `TARGET` (`<IMAGE_TAG\|latest>-<arch>`) a `quay.io/town/rolodex`. Sin alias de fecha/`rc`/`latest`, sin manifiesto. |
| `push-release`        | Compila y sube la imagen de release de la arquitectura `TARGET` a `quay.io/town/rolodex`. Autoetiqueta `release.YYYYMMDD-<arch>` + `latest-<arch>` salvo que se ponga `IMAGE_TAG`. |
| `image-amd64`         | Alias de `make image TARGET=x86_64`. |
| `push-rc-amd64` / `push-release-amd64` | Alias de `make push-rc TARGET=x86_64` / `make push-release TARGET=x86_64`. |
| `push-rc-all` / `push-release-all` | Publica **ambas** arquitecturas desde un único equipo de cualquiera de las dos (ambas compiladas de forma cruzada), y luego ensambla el manifiesto. |
| `manifest` / `manifest-rc` | Ensambla y sube una lista de manifiestos multiarquitectura de RC (`rc.YYYYMMDD`, `rc.latest` o `IMAGE_TAG`) a partir de las etiquetas por arquitectura que ya están en el registro. La lista `rc.latest` se ensambla a partir de las etiquetas con sufijo `uname -m` (`rc.latest-x86_64`, `rc.latest-aarch64`). |
| `manifest-release`    | Ensambla y sube una lista de manifiestos multiarquitectura de release (`release.YYYYMMDD`, `latest` o `IMAGE_TAG`) a partir de las etiquetas por arquitectura que ya están en el registro. |
| `quay-login`          | Inicia sesión en Quay.io usando `QUAY_USERNAME` y `QUAY_PASSWORD` del entorno o de `.env`. |
| `clean-containers`    | Elimina las imágenes de contenedor por arquitectura construidas localmente. |

El Makefile está diseñado para extenderse a escenarios ajenos a cargo. Los enlaces de protocol buffers se generan en tiempo de compilación con `build.rs` usando `tonic-prost-build`. Las imágenes de contenedor se construyen con Podman usando identificadores de instancia únicos derivados de la ruta del directorio de trabajo.

### Compilaciones de contenedor multiarquitectura

Las imágenes se publican en `quay.io/town/rolodex` como listas de manifiestos multiarquitectura que cubren `linux/amd64` y `linux/arm64` (los nombres de plataforma OCI que podman empotra en el manifiesto). Las compilaciones son **nativas**: cada arquitectura se compila en un equipo de esa arquitectura (sin compilación cruzada dentro del contenedor).

#### `TARGET` — seleccionar la arquitectura

`TARGET` selecciona la arquitectura para **todos** los objetivos de contenedor (`image`, `push-arch`, `push-rc`, `push-release`), reflejando el modelo del repo `install` para que un mismo valor de `TARGET=` se pueda pasar entre los repos de town-os. Vacío (el valor por defecto) es una compilación nativa para la arquitectura del equipo. Valores reconocidos:

| `TARGET` | Resuelve a |
| -------- | ---------- |
| *(vacío)* | la arquitectura del equipo (`uname -m`, normalizada) |
| `x86_64`, `x86`, `amd64` | `x86_64` |
| `aarch64`, `arm64` | `aarch64` |
| `rpi` | `aarch64` |
| `rg35xxpro`, `rg35xx-pro`, `rg35xx`, `anbernic` | `aarch64` |

Cualquier otra cosa es un `$(error)` duro en tiempo de análisis que enumera los valores válidos. Los sabores de placa (`rpi`, `rg35xxpro`, …) no acarrean diferencias de imagen aquí — rolodex-dns distribuye una imagen de contenedor por arquitectura, no por placa. Se aceptan para que un `TARGET=rg35xxpro` que construye una imagen de disco específica de placa en `install` resuelva aquí a la imagen de contenedor aarch64 en vez de fallar por un valor que es válido un repo más allá.

De él se derivan dos variables, ninguna de las cuales es una perilla de usuario:

- **`BUILD_ARCH`** — la arquitectura de la imagen, y por tanto el sufijo de toda etiqueta con sufijo de arquitectura (`latest-<arch>`, `rc.latest-<arch>`, `release.YYYYMMDD-<arch>`). El Makefile lo exporta y `make/build.sh` lo lee, recurriendo a `host_arch` cuando se invoca directamente. Los equipos de despliegue pueden seguir bajando `` <etiqueta>-`uname -m` `` sin ningún mapeo de nombres OCI.
- **`CROSS`** — se pone cuando `BUILD_ARCH` difiere de `HOST_ARCH`. Todas las arquitecturas se compilan de forma cruzada de cualquier modo, así que esto solo decide si `make build` ejecuta un `cargo build` de depuración simple o la cadena cruzada. **Cualquier equipo puede construir cualquier arquitectura** — no hay combinación rechazada. Pon `TARGET`, no `CROSS`.

`ARCHES` en `make/lib.sh` contiene los nombres de máquina `x86_64 aarch64` usados como sufijos de manifiesto (nota: se asigna incondicionalmente, así que no se puede sustituir desde el entorno). El ayudante `build_manifest` ensambla una lista de manifiestos a partir de las etiquetas por arquitectura usando `podman manifest add docker://…`, así que las imágenes por arquitectura solo tienen que existir en el registro, no localmente.

#### Compilación cruzada (`make/cross.sh`)

Ambas arquitecturas se **compilan de forma cruzada en el equipo que ejecute `make`** — no hay VM constructora ni emulación. La arquitectura nativa y la ajena toman exactamente la misma ruta de código, así que las dos imágenes publicadas difieren solo en su triple objetivo y no en cómo se produjeron.

**Por qué hace falta una cadena cruzada de verdad.** `rustup target add` por sí solo no basta: `rusqlite` se compila con la característica `bundled` (compila las fuentes C de SQLite) y `ring` compila C y ensamblador, así que la compilación muere en el paso `cc` sin un compilador **C** cruzado. `cargo-zigbuild` aporta uno usando zig como compilador cruzado de C y enlazador.

**Por qué zig y no un cross-gcc de la distribución.** La cadena entera se instala sin root —`rustup target add`, `cargo install cargo-zigbuild` y un tarball de zig extraído bajo `.cache/zig/`— así que `make deps` la puede aprovisionar en cualquier máquina en vez de depender de paquetes específicos de la distribución (`gcc-aarch64-linux-gnu` y compañía difieren por distribución y necesitan root). zig además enlaza contra una **glibc fijada**: el triple objetivo lleva como sufijo `GLIBC_VERSION` (por defecto `2.36`, coincidiendo con `debian:bookworm`), así que el binario corre sobre la imagen base de ejecución independientemente de la glibc del equipo de compilación. Fijaciones: `ZIG_VERSION`, `ZIGBUILD_VERSION`, `GLIBC_VERSION`.

**La imagen de ejecución no tiene pasos `RUN`.** Esta es la restricción que elimina la VM en vez de reubicar el problema. `podman build --platform linux/<arch>` solo necesita *ejecutar* algo de la arquitectura objetivo si existe una instrucción `RUN`; un `RUN` ajeno requiere emulación en espacio de usuario, que es justo lo que no está disponible en equipos como Fedora Asahi (su emulación x86 pasa por FEX + `binfmt-dispatcher` + `muvm`, inutilizable dentro de un sandbox de `podman build` — incluso un `podman run --platform linux/amd64` pelado falla ahí). El `Containerfile` por tanto solo hace `COPY`: los binarios compilados de forma cruzada y un bundle de CA tomado del equipo de compilación (los certificados son datos independientes de la arquitectura, así que no necesitan `apt-get`). Con cero pasos `RUN`, una imagen de arquitectura ajena es puro ensamblado de ficheros y no necesita emulación en absoluto.

`make/cross.sh` tiene tres subórdenes: `deps` (aprovisionar la cadena de herramientas), `build ARCH` (compilar de forma cruzada y despojar los binarios de release en `target/<triple>/release`) y `stage ARCH` (ensamblar `.cache/stage/<arch>` —los binarios más el bundle de CA— como contexto de compilación del contenedor).

**Red de compilación.** Ya nada en la compilación de la imagen resuelve DNS, así que `--network=host` ya no se pasa por defecto. `BUILD_NETWORK=<nombre>` se sigue respetando si necesitas una red concreta de podman.

El flujo de publicación multiarquitectura de extremo a extremo, desde **un solo equipo de cualquiera de las dos arquitecturas**:

```bash
make push-release-all   # compila de forma cruzada ambas arquitecturas, sube ambas y luego el manifiesto
```

O paso a paso, que es también como lo repartes entre equipos si lo prefieres:

1. `make push-release TARGET=x86_64` → sube `…:latest-x86_64` (+ etiqueta de fecha).
2. `make push-release TARGET=aarch64` → sube `…:latest-aarch64` (+ etiqueta de fecha).
3. `make manifest-release` → sube la lista de manifiestos `…:latest`.

`push-rc-all` es el equivalente de RC.

### Etiquetado de imágenes de contenedor

Las imágenes se publican en `quay.io/town/rolodex`. Dos variables controlan la etiqueta: `IMAGE_TAG` elige la etiqueta en sí, y `TARGET` elige el sufijo de arquitectura que se le añade (vía `BUILD_ARCH`). Las imágenes por arquitectura llevan el sufijo de arquitectura; los objetivos de manifiesto producen la etiqueta multiarquitectura sin sufijo.

**Subir con etiquetas autogeneradas** (por defecto):

```bash
make push-rc          # sube rc.YYYYMMDD-<arch> y rc.latest-<arch>
make push-release     # sube release.YYYYMMDD-<arch> y latest-<arch>
make manifest-rc      # sube las listas de manifiestos rc.YYYYMMDD y rc.latest
make manifest-release # sube las listas de manifiestos release.YYYYMMDD y latest
```

**Elige la arquitectura** con `TARGET` (por defecto: la arquitectura del equipo). Cualquier equipo construye cualquier arquitectura compilando de forma cruzada:

```bash
make push-release TARGET=x86_64     # sube release.YYYYMMDD-x86_64 y latest-x86_64
make push-release TARGET=aarch64    # sube release.YYYYMMDD-aarch64 y latest-aarch64
make image TARGET=rg35xxpro         # sabor de placa -> imagen de contenedor aarch64
```

**Subir una etiqueta concreta**:

```bash
make IMAGE_TAG=v1.2.3 push-release      # sube quay.io/town/rolodex:v1.2.3-<arch>
make IMAGE_TAG=v1.2.3 manifest-release  # sube la lista de manifiestos quay.io/town/rolodex:v1.2.3
make IMAGE_TAG=v1.2.3-rc1 push-rc       # sube quay.io/town/rolodex:v1.2.3-rc1-<arch>

# IMAGE_TAG y TARGET se componen: la etiqueta, con el sufijo de esa arquitectura.
make IMAGE_TAG=v1.2.3 TARGET=x86_64 push-release   # -> quay.io/town/rolodex:v1.2.3-x86_64
```

Cuando `IMAGE_TAG` está puesto, solo se sube esa etiqueta exacta (por arquitectura, luego manifiesto) — no se crean etiquetas por fecha ni `latest`.

**Reetiquetar y subir a otro registro**:

```bash
sudo podman tag quay.io/town/rolodex:latest registry.example.com/myorg/rolodex:v1.2.3
sudo podman push quay.io/town/rolodex:latest registry.example.com/myorg/rolodex:v1.2.3
```

### Servidor de desarrollo

El objetivo `make dev` arranca una instancia de desarrollo local configurada con `dev.yml`:

- Escuchas DNS en `127.0.0.1:5300` y en la IP saliente principal en el puerto `5300` (UDP y TCP) — un puerto no privilegiado que no requiere root.
- Gestión gRPC solo por socket Unix en `/tmp/rolodex-dns.sock` (gRPC por TCP desactivado).
- Base de datos en `/tmp/rolodex-dns-dev.db`.
- Sin autenticación (secreto compartido vacío).
- Lista de bloqueo desactivada.
- Reenviadores de Google DNS (`8.8.8.8:53`, `8.8.4.4:53`).

El objetivo `make dev-release` hace lo mismo pero compila con `--release` para un rendimiento optimizado.

## Pruebas

### Pruebas de Rust

Las pruebas de Rust (`cargo test`) incluyen pruebas unitarias y de integración que cubren las operaciones gRPC, la resolución DNS (UDP y TCP), el comportamiento de horizonte partido, la imposición de la autenticación, el salto de autenticación por socket Unix, la persistencia en base de datos, la serialización de la configuración, el manejo de EDNS, los cálculos de deriva de TTL, el seguimiento de latencia y el IPAM.

### Pruebas unitarias de rendimiento

Las pruebas unitarias relacionadas con el rendimiento cubren el código optimizado de la ruta caliente:

- **Aleatorización de QNAME** (`src/dns_server.rs`): pruebas de `extract_qname` (nombres simples, subdominios, etiquetas únicas, etiqueta raíz, entrada truncada, entrada vacía) y de `randomize_qname_case` (preservación de la estructura, cambios solo alfabéticos, coherencia del nombre en la ida y vuelta, rechazo de entradas cortas).
- **Búsquedas en BD por lotes** (`src/db.rs`): pruebas de `lookup_with_fallbacks` que cubren el acierto exacto, la reserva por comodín con sustitución del qname, la reserva por CNAME, la reserva por ANAME, los resultados mixtos de una sola vez, el fallo completo, y la prioridad de lo exacto sobre el CNAME.
- **Coincidencia de zonas** (`src/db.rs`): pruebas de `matches_zone_suffix` (coincidencia exacta, subdominio, subdominio profundo, sin coincidencia, caché vacía, nivel de TLD), de `find_managed_zone` (coincidencia y fallo) y de `find_authoritative_zone` (coincidencia, exacta, fallo).
- **Generación de claves de caché** (`src/dns_cache.rs`): pruebas de `cache_key` con tipos concretos, tipo comodín, varios tipos de registro y coherencia.
- **Caché basada en Arc** (`src/dns_cache.rs`): pruebas de la inserción local sin decaimiento de TTL, el no-op del vector vacío, y varios registros bajo la misma clave.
- **Pool de conexiones DoH** (`src/doh_proxy.rs`): pruebas de la imposición del tope del pool (máximo 8), la creación de conexión nueva y la reutilización de una conexión del pool.

### Pruebas de métricas

- **Pruebas unitarias del registro** (`src/metrics.rs`): semántica de contadores/medidores/vectores, incluidos los índices de etiqueta fuera de rango (que no deben provocar nunca un pánico en la ruta de consulta), el agrupamiento acumulativo de histogramas, el renderizado de nanosegundos→segundos y de bytes, la creación dinámica de series, el escapado de valores de etiqueta, el formateo de flotantes que evita la notación científica, el plegado de rcode/qtype desconocidos, y una guarda de que toda serie emitida va precedida de su propio `# HELP`/`# TYPE`.
- **Pruebas de documentación** (`tests/promql_docs_test.rs`): se analiza cada bloque ```promql de `README.md` y `DESIGN.md`, se extraen sus nombres de métrica y emparejadores de etiqueta, y cada uno se resuelve contra la salida de exposición en vivo. La documentación es la única parte de un cambio de métricas que nada más verifica — renombrar `{type}` a `{message_type}` deja el código compilando y todas las demás pruebas en verde mientras convierte en silencio cada consulta documentada de cuadro de mando en una que no devuelve datos, y el operador se entera cuando un panel se queda en blanco a mitad de incidencia. El mismo fichero fija el **recuento de familias** documentado contra lo que emite `render` (ya había derivado, 73 documentadas contra 74 emitidas) y protege la propia valla, porque un bloque reetiquetado como ` ```bash ` haría que el fichero entero dejara de comprobar nada. El analizador está hecho a mano en vez de arrastrar `regex`, y es deliberadamente permisivo con la sintaxis que no entiende y estricto con los identificadores que sí.
- **Pruebas de ejecución de PromQL** (`tests/prometheus_integration_test.rs`): las mismas consultas documentadas pasan por un Prometheus real que raspa un servidor vivo, porque un escáner de subcadenas no puede distinguir una consulta bien formada de `rate(sum(x)[5m])` — esa nombra solo series reales y se rechaza en el momento en que un operador la pega. Se ejecuta desde `make prometheus-test`, del que `make test` depende, así que las consultas se ejecutan en toda pasada completa. La compuerta mantiene eso honesto en ambas direcciones: hay que poner `ROLODEX_PROMETHEUS_TEST=1` (así un `cargo test` pelado nunca arranca contenedores a tus espaldas), y un podman ausente **salta ruidosamente** en vez de fallar — un `make test` en verde en una máquina sin runtime de contenedores, pero nunca uno silencioso, porque una comprobación saltada y una comprobación superada son indistinguibles en un resumen de pruebas y la segunda es lo que asume el lector. `ROLODEX_PROMETHEUS_REQUIRED=1` asciende el salto a fallo para CI. Las dos capas son complementarias: esta es autoritativa sobre la sintaxis, la otra sobre si las series existen.
- **Pruebas del endpoint y de la atribución** (`tests/metrics_test.rs`): el enrutador se sirve en un puerto efímero y se raspa por un socket TCP real con una petición HTTP/1.1 escrita a mano — estado, tipo de contenido, y que toda línea que no es comentario analiza como `nombre[{etiquetas}] valor` con un valor numérico, ya que una sola línea mal formada hace que Prometheus rechace el raspado entero. Las pruebas de la ruta de consulta afirman que un acierto local, un acierto de caché, un NXDOMAIN autoritativo, una consulta mal formada y un tipo de consulta desconocido aterrizan cada uno en la serie correcta, que los medidores se muestrean en el momento del raspado (una fila añadida después de arrancar el escucha aparece), que los tres motivos de vaciado de caché siguen siendo distintos, y que un rechazo de lista de bloqueo avanza `blocklist_refusals_total` y el resultado de búsqueda `refused` **sin** avanzar también `listed`. Como el registro es un global del proceso, cada prueba retiene un cerrojo compartido y afirma diferencias exactas — serializar en vez de relajar a `>=` es lo que caza que una observación se registre *dos veces*. Los casos más nuevos cubren las dimensiones añadidas desde entonces: un TLD rastreado obteniendo su propia serie **y** el control de que uno no rastreado no acuña ninguna (la cota de cardinalidad es todo el asunto, y una prueba que solo comprobara lo positivo pasaría con la cota retirada), un TLD propio siendo rastreado sin haberse configurado nunca, los bytes de tráfico coincidiendo con las longitudes exactas del cable en ambas direcciones y con los registros servidos leyendo ANCOUNT en vez de contar uno por consulta, y cada compuerta de la lista de permitidos avanzando sin las otras dos.
- **Pruebas de las regiones de bloqueo** (`tests/blocking_metrics_test.rs`): cada ruta instrumentada se afirma junto a un control que no debe registrar nada. El caso de la base de datos conduce un `Database` real — una inserción y una búsqueda por los métodos de siempre, porque la propiedad bajo prueba es que `Database::lock` es el cuello de botella por el que pasa un método añadido después, se acordara alguien de instrumentarlo o no — y lo empareja con una lectura servida enteramente desde la caché de asociaciones en memoria, que no debe mover ninguna de las dos series: una muestra de `db_locked` para una lectura que nunca tomó el cerrojo informa de una contención que nadie está sufriendo. El umbral se comprueba por los dos lados, un nanosegundo por debajo de 10ms y exactamente encima, ya que `>=` y `>` se diferencian precisamente en el caso que golpea una alerta escrita contra ese límite de bucket. Los índices de los sitios se fijan nombre a índice con una afirmación de longitud al lado: las constantes `BLOCK_SITE_*` son posiciones dentro de un array preasignado, así que una inserción reetiqueta en silencio cada muestra ya registrada contra los sitios posteriores, y un sitio añadido sin su constante es una serie en la que nadie puede escribir. La prueba del formato de exposición exige que cada sitio esté presente a cero antes de que se haya registrado nada — un valor de etiqueta que solo se materializa cuando deja de ser cero deja vacío en silencio un `rate()` sobre un proceso recién reiniciado, y hace indistinguible "aquí nunca nos hemos bloqueado" de "este sitio no existe" — con los límites de 100ns, 10ms y `+Inf` escritos a mano en vez de derivados del array de límites. Dos de las pruebas construyen un `Metrics` privado en vez de usar el registro global del proceso, porque cada una de las demás pruebas del binario está escribiendo en el global y una afirmación de valor absoluto contra él es una carrera; la prueba de la base de datos no puede (a un `Database` no hay manera de pasarle un registro), así que afirma diferencias contra un fichero en memoria que no deja nada en el equipo.

### Pruebas del resolutor

El resolutor iterativo tiene una batería dedicada construida sobre una **jerarquía de delegaciones simulada** (`tests/mock_hierarchy/mod.rs`) — servidores de nombres reales en proceso cuyas consultas se cuentan, porque los recuentos de consultas (no los registros devueltos) son lo que distingue estos fallos de sus arreglos:

| Fichero de prueba | Qué fija |
| ----------------- | -------- |
| `tests/auto_resolution_test.rs` | La cadena de niveles `auto`: recursión de raíces apuntada a loopback para que falle rápido, nivel seguro vacío, upstreams UDP simulados para los niveles en claro — ejercitando la lógica de respuesta-definitiva/caída como en una red que filtra el `:53` saliente. |
| `tests/recovery_probe_test.rs` | La *recuperación* de nivel, contra la jerarquía firmada: unas raíces validadas se reclaman, mientras que unas raíces alcanzables pero sin firmar, firmadas por un ajeno o caducadas no — más la guarda de que nunca se gasta una consulta de cliente en sondear. Cubre ambas direcciones deliberadamente: una compuerta que nunca se abre pasa todas las pruebas negativas, y una que siempre se abre pasa todas las positivas. |
| `tests/delegation_cache_test.rs` | N nombres en frío deben costar **una** consulta a la raíz, no N. |
| `tests/delegation_flush_test.rs` | `flush_cache()` (llamada desde más de 15 puntos de mutación gRPC) **no** debe borrar las delegaciones; solo `flush_upstream_state()` puede. Añadir un paquete no debe mandar todos los nombres de vuelta a las raíces. |
| `tests/delegation_persist_test.rs` | La persistencia de delegaciones entre reinicios, y la carga de arranque de la caché de respuestas. |
| `tests/record_cache_test.rs` | El glue, las búsquedas de NS sin glue y los saltos CNAME se cachean y no se vuelven a consultar. |
| `tests/negative_ttl_test.rs` | El TTL negativo del RFC 2308 honrado tal como se envía (sin suelo, sin techo); `default_ttl` solo cuando no hay SOA. |
| `tests/resolver_selection_test.rs` | Un servidor lento se degrada, un servidor muerto se degrada, IPv4 siempre se prueba antes que IPv6. |
| `tests/root_balance_test.rs` | La selección por `hits * latencia` reparte la carga entre las raíces en vez de clavar la más rápida. |
| `tests/root_priming_test.rs` | El cebado ocurre al arrancar (nunca en la ruta de consulta) y las pistas son un arranque/reserva. |
| `tests/query_budget_test.rs` | Una búsqueda de cliente cuesta un número acotado de consultas upstream (la zona patológica sin glue que produjo 65 536 consultas en 42 s). |

### Pruebas de firma DNSSEC

`tests/dnssec_signing_test.rs` fija que una firma sea *comprobable*, no meramente que esté presente. Afirmar que aparecieron filas RRSIG pasaría igual de contento con una firma calculada sobre los bytes equivocados, el nombre de propietario equivocado, o con una clave que no es la anunciada — y cada uno de esos falla en un resolutor validador y no en la batería. Así que la prueba central re-deriva la entrada de firma a partir del **RRset DNSKEY publicado** (nunca de las filas de clave privada, ya que un validador solo tiene el DNSKEY) y verifica todos los RRSIG de la zona, en los tres algoritmos y con ambos tipos de clave, sobre una zona que contiene RRset de varios registros, nombres empotrados y prioridades MX/SRV fuera de banda.

El resto cubre: un RRSIG por RRset de varios registros y su fallo al verificar sobre un subconjunto, la separación de papeles KSK/ZSK y la reserva de clave única, el confinamiento de zona por frontera de etiqueta, la refirma reemplazando en vez de acumular firmas (incluso en nombres cuyos registros se borraron), las ventanas de validez y el acuerdo del TTL original, los tipos no firmables saltándose y reportándose, DNSKEY/RRSIG sirviéndose bajo sus propios códigos de tipo, el RDATA servido siendo byte a byte idéntico a lo firmado, las claves generadas llevando el algoritmo que dicen, RSA siendo rechazado, y el registro DS coincidiendo con el DNSKEY publicado.

Las pruebas unitarias de `src/dnssec.rs` cubren la propia forma canónica: paso a minúsculas y cualificación de nombres, recuentos de etiquetas del RFC 4034 §3.1.3, troceado de cadenas de caracteres, codificación de RDATA por tipo, independencia del orden del RRset, ida y vuelta de firma/verificación por algoritmo, detección de manipulación, negativa a cargar material de clave que contradice su etiqueta, y que los nombres de algoritmo almacenados hacen ida y vuelta por `parse`.

### Pruebas de validación DNSSEC

`tests/signed_hierarchy/mod.rs` es una jerarquía simulada **firmada con DNSSEC** — raíz firmada → TLD firmado → zona firmada, sobre sockets UDP reales, cada zona con su propia clave Ed25519, publicando un RRset DNSKEY y entregando un DS por cada hija firmada. Donde `tests/mock_hierarchy` demuestra *recuentos* de consultas, esta demuestra *veredictos*, porque casi todas las formas de hacer mal el DNSSEC siguen devolviendo los registros correctos: un validador que se salta la comprobación de caducidad, o que se cree un NSEC sin firmar, o que acepta cualquier nombre de firmante resuelve internet entera correctamente hasta justo el momento en que alguien lo ataca.

Su enumeración `Tamper` es la clave. Cada variante es un ataque concreto, aplicado cuando la respuesta se **serializa** —después de haber construido la zona correctamente— así que cada prueba es «un despliegue válido, atacado» y no «un despliegue inválido, rechazado», que probaría mucho menos.

- `tests/dnssec_validation_test.rs` — las rutas que deben seguir funcionando: una cadena completamente firmada validando Secure con la dirección correcta, RRSIG sobreviviendo hasta el cliente, una delegación sin firmar demostrada por NSEC resolviendo Insecure, NXDOMAIN y NODATA demostrados, la caché de claves ahorrándole a la raíz una segunda consulta para una zona en caliente, y un resolutor no validador informando Insecure y no Secure.
- `tests/dnssec_hidden_cut_test.rs` — una zona hija firmada servida desde el propio servidor de nombres de su padre, de modo que el corte no lo anuncia nunca una derivación (véase [Cortes de zona que nadie anuncia](#cortes-de-zona-que-nadie-anuncia)). Cubre la respuesta que ahora debe validar contra las claves de la hija, el padre quedando inalterado por el descenso, NXDOMAIN y NODATA demostrados desde dentro de la hija oculta, una hija cuyo DS no casa con ninguna de sus propias claves siendo rechazada, la posición del recorrido no moviéndose con el descenso, y un resolutor no validador resolviendo el nombre sin ninguno. Cubre también la gemela sin firmar — una hija sin firmar en el mismo servidor de nombres, que sigue rechazada y se cuenta bajo `dnssec_unsigned_responses_total`, con su SOA de ápice como evidencia donde la hay y `none` donde no, más el control de que una hija oculta *firmada* nunca aterriza en ese contador.
- `tests/security_dnssec_test.rs` — los ataques, cada uno con el hallazgo enunciado en la documentación del módulo: firmas arrancadas (la degradación que DNSSEC existe para detener), una delegación sin DS ni prueba de su ausencia (la degradación a nivel de delegación), firmas caducadas y prematuras, una firma de una clave que el RRset DNSKEY no publica, un nombre de firmante ajeno, datos mutados tras firmar, un negativo sin demostrar, un ancla de confianza que no casa con ninguna clave raíz, y anclas mal formadas siendo rechazadas al analizarse en vez de volver en silencio a IANA. Fija además las reglas de rechazo de arriba, gobernadas a través de un `DnsServer` real en modo `auto` con un reenviador contador **que funciona** detrás del nivel de raíces, porque «el cliente recibió SERVFAIL» y «al reenviador no se le consultó nunca» son propiedades distintas y solo la segunda es el requisito: una respuesta de raíces rechazada no cae hacia abajo; un recorrido rechazado no deja delegación alguna detrás (con su control, que uno aceptado sí se cachea); una zona raíz no validable da SERVFAIL mientras una *inalcanzable* sigue cayendo hacia abajo; una raíz que sirve firmas malas se omite mientras a sus pares se les sigue consultando; la omisión caduca, escala ante la reincidencia y se detiene en el tope, y solo la limpia una respuesta que valida; la imputación sobrevive a un intercambio correcto mientras un tiempo de espera corriente sí se recupera con uno; imputar a todas las raíces no se convierte en una caída hacia abajo; el modo auto sigue gobernando en ese estado; y la imputación no llega nunca a los servidores de nombres propios de una zona.

Ambas importan por igual y por la misma razón: un validador que lo rechaza todo pasa todas las pruebas de ataque, y uno que lo acepta todo pasa todas las de camino feliz. Solo el par junto dice algo.

La mitad multi-raíz de ese fichero necesita que una raíz simulada cambie su comportamiento *en marcha* — la imputación va sobre la historia de un servidor, y reiniciar un servidor para que deje de mentir le daría una dirección nueva y por tanto un servidor distinto en lo que a la imputación respecta. `signed_hierarchy::serve_switchable` devuelve un `TamperSwitch` para eso, y a una raíz también se la puede dejar enlazada pero callada y arrancarla más tarde, que es como se monta un fallo de transporte seguido de una recuperación.

Las pruebas unitarias de `src/dnssec_validate.rs` cubren las piezas con independencia de red alguna: la combinación de veredictos (gana el peor), base32hex contra los vectores del RFC 4648 §10 y su preservación del orden (que es lo que permite a las comprobaciones de rango NSEC3 comparar cadenas codificadas), el desbordamiento de números de serie del RFC 1982, la cobertura NSEC incluido el último registro que da la vuelta y la exclusividad en ambos extremos, y los casos de rechazo de cada prueba de denegación. `src/key_cache.rs` fija que las búsquedas son por nombre exacto y no por sufijo — una coincidencia por sufijo entregaría las claves de un padre a una subzona delegada.

### Pruebas de rechazo de `arpa.`

`tests/arpa_refusal_test.rs` fija que el subárbol no sale nunca de la máquina, en ambas capas y en todos los modos de resolución. La aserción es sobre **paquetes**, no sobre rcodes: un resolutor que respondiera REFUSED *después* de preguntar a una raíz satisfaría una comprobación de rcode habiendo hecho ya lo que la regla prohíbe, así que lo que se afirma es el recuento de consultas de la raíz simulada, contra una jerarquía que es demostrablemente alcanzable para todo lo demás.

Sus controles son los que le dan sentido. Un resolutor que lo rechazara todo pasaría las pruebas de rechazo, así que `notarpa.`, `arpa.example.test.` y `arpanet.example.` deben resolver *y* validar Secure — la frontera de etiqueta, comprobada a través de ambas capas. Y una regla que simplemente hubiera borrado el espacio de nombres también pasaría, así que un PTR almacenado debe seguir respondiéndose desde datos locales, emparejado con el mismo nombre rechazado cuando no hay nada almacenado para él. Los modos se barren exhaustivamente (`recursive`, `forward`, `auto`) porque cada uno despacha de forma distinta — `forward` no toca el resolutor iterativo en absoluto, así que una regla impuesta solo ahí se escaparía justo en la forma de despliegue que reenvía.

### Pruebas de rechazo de lista de bloqueo

`tests/blocklist_refusal_test.rs` gobierna los códigos de rechazo y la rotación de proveedores sobre **DNS UDP real** — una zona de lista de bloqueo simulada que responde con registros `A` reales, a través de la reserva del reenviador de `RecursiveDnsblResolver`, a través de la clasificación, hasta `DnsServer::handle_query` — porque toda capa intermedia es un sitio donde la distinción listado/rechazo podría perderse, y afirmar solo sobre `classify` pasaría igual de contento con una ruta de consulta que nunca lo llama. La recursión de raíces apunta a una dirección de loopback muerta, así que el nivel de raíces falla al instante y la prueba no toca nunca la red.

Cada prueba va emparejada con un **control**: un listado `127.0.0.2` genuino recorriendo la ruta idéntica debe seguir devolviendo NXDOMAIN. Sin él, un comprobador que simplemente hubiera dejado de bloquear nada pasaría el fichero entero.

Cubre cada código de rechazo documentado fallando al bloquear mientras saca a su proveedor de rotación, la rotación suprimiendo búsquedas posteriores para nombres distintos (el *recuento* de consultas es la única forma de observar «fuera de rotación»), el enfriamiento decayendo por sí solo, `none` restaurando la lectura antigua, una lista explícita reemplazando en vez de extender los valores por defecto, la ida y vuelta por gRPC de códigos/enfriamientos/estado fuera-de-rotación, `InvalidArgument` para un código mal formado y para `none` mezclado con códigos reales, y la ida y vuelta en base de datos del proveedor por ámbito.

Las pruebas unitarias de `src/dnsbl.rs` cubren las piezas: el análisis y enmascarado de prefijos, que toda entrada de `DEFAULT_REFUSAL_CODES` analiza (se resuelven con `filter_map`, así que una errata en la constante descartaría si no un código en silencio) y que ningún código de *listado* de Spamhaus cae dentro de ellos, las reglas vacío/`none`/explícito de `resolve_refusal_codes`, un rechazo ganando a un listado en la misma respuesta, los rechazos no cacheando nada, los listados cacheados sobreviviendo a la rotación, y `flush_cache`/`set_config` devolviendo proveedores a la rotación. `src/config.rs` fija que un proveedor escrito antes de que los campos existieran sigue analizando y aterriza en los códigos integrados.

### Pruebas de lista de bloqueo

`tests/blocklist_nxdomain_test.rs` fija el contrato de la lista de bloqueo de extremo a extremo: **toda coincidencia positiva de lista de bloqueo se responde con NXDOMAIN, y una entrada de la lista de permitidos es lo único que la suprime.** Tres listas pueden producir una coincidencia — un proveedor DNSBL, una entrada local que nombra una IP, y una entrada local que nombra un nombre DNS — a través de dos compuertas (paso 2 para nombres inversos, paso 7 para nombres directos) en dos rutas de código (con ámbito y global). La batería gobierna cada una como lo hace un operador: una mutación por el **plano de control gRPC**, y luego una consulta por un **socket UDP o TCP real**, afirmando lo que el cliente recibe realmente. Esa combinación es lo que una prueba unitaria no puede mostrar — una regresión que moviera una compuerta respecto de la caché de respuestas, o que cableara un transporte directamente al resolutor, deja las pruebas unitarias en verde.

Cada prueba lleva su propio control, porque una compuerta que lo bloquea todo satisface la primera mitad del contrato y una que no bloquea nada satisface la segunda. Los casos negativos son igual de estructurales: un literal IP no debe casar por sufijo (`1.100` no es padre de `192.168.1.100`), un nombre directo debe casar en fronteras de etiqueta, y una lista de bloqueo no debe ensombrecer nunca un registro local — un listado de terceros llevándose por delante un servicio interno es el modo de fallo que hace que los operadores apaguen las listas de bloqueo.

Las pruebas unitarias de `src/dns_server.rs` fijan las propias compuertas (cada lista, cada grafía, las rutas con ámbito y global, y que una dirección en la lista de permitidos no emite consulta de proveedor alguna), y `src/db.rs` cubre la coincidencia exacta-frente-a-sufijo de la lista de permitidos, incluidos los literales IPv6.

### Baterías de regresión de seguridad

Los ficheros `tests/security_*.rs` fijan cada uno el comportamiento que exige un hallazgo de seguridad, enunciado en términos observables y emparejado con un control que debe seguir en verde. Cubren: la validación de respuestas del reenviador Do53 y del resolutor iterativo (`security_forwarder_test`, `security_resolver_test`), la jurisdicción de derivaciones y glue (`security_bailiwick_test`), el confinamiento de la CSR del emisor ACME, su autorización y el manejo de repetición y caducidad (`security_acme_test`), el alcance por zona del portal de inscripción y sus defensas CSRF (`security_portal_test`), la clasificación de orígenes mapeados de IPv4 (`security_scope_test`), la recursión abierta y la amplificación (`security_open_resolver_test`), la validación de nombres de máquina suministrados por DHCP (`security_dhcp_hostname_test`), los límites de conexión de los transportes de flujo (`security_tcp_limits_test`, `security_dot_limits_test`), los permisos del sistema de ficheros y la negativa a arrancar con un enlace gRPC enrutable sin autenticar (`security_local_access_test`), la comparación de secretos en tiempo constante más la limitación de fuerza bruta (`security_auth_hardening_test`), y los ataques de degradación, repetición, vinculación de claves y denegación sin demostrar de DNSSEC (`security_dnssec_test`).

Un fallo en uno de estos es el hallazgo, no una prueba rota — la documentación de módulo al principio de cada fichero enuncia el invariante y por qué está escrito como está. Nunca debilites una aserción para hacer que pase.

### Pruebas unitarias de IPAM

Las pruebas unitarias de IPAM en `src/db.rs` cubren la lógica de asignación de direcciones IP: agotamiento del conjunto (asignar todas las IP de un rango, verificar `None` cuando está lleno), reutilización de IP tras borrar una concesión, aislamiento de ámbitos (los mismos rangos de IP en ámbitos distintos no interfieren), supervivencia de la vinculación MAC pegajosa a la liberación de la concesión, comportamiento del conjunto de una sola IP, y reemplazo de concesión para la misma MAC (siempre reemite la misma IP).

### Pruebas de integración de DHCP

Las pruebas de integración de DHCP en `tests/dhcp_integration_test.rs` cubren flujos DHCP de extremo a extremo: DISCOVER/OFFER/REQUEST/ACK, vinculaciones pegajosas, agotamiento del conjunto, creación de concesión con registro DNS, limpieza al liberar la concesión, barrido de concesiones con eliminación en DNS, entrega de la opción de certificado, múltiples clientes concurrentes, e idas y vueltas completas de paquetes UDP.

### Pruebas de transporte, proxy y TLS

Seis baterías cubren superficies que antes tenían solo una prueba de humo de compilación o una prueba unitaria de análisis de configuración:

- `tests/dot_test.rs` — DoT en dos mitades, que responden a preguntas distintas. En proceso, un cliente `tokio-rustls` real contra `serve_dot`: se negocia el token ALPN `dot`, un cliente que ofrece solo otro protocolo es rechazado, a un cliente que no ofrece ALPN alguno se le sigue sirviendo y respondiendo, un nombre programado vuelve con su dirección mientras uno no programado vuelve NXDOMAIN, y una conexión lleva varias consultas con sus identificadores y preguntas cotejados de vuelta (reutilización del RFC 7766). Fuera de proceso, el binario `rolodex-dns` real contra un fichero de configuración con una sección `dot:`: el escucha desplegado negocia `dot` y responde a un nombre programado por el socket de gestión, y el certificado que presenta se decodifica y se comprueba que lleva la dirección a la que fue enlazado y los `self_signed_sans` configurados, pero no un nombre que nunca se configuró. La segunda mitad es la que caza un `main.rs` que construye un escucha sin pedir el token ALPN o sin nombrar su dirección de enlace — ninguna de las dos cosas las puede ver un arnés en proceso que construye su propio `rustls::ServerConfig`. Enlaza `127.0.0.2` precisamente porque el conjunto de loopback va horneado en todo certificado generado, así que solo una dirección fuera de ese conjunto demuestra la derivación. Un tercer caso rota el certificado bajo un `serve_dot` en marcha y afirma que una conexión abierta *antes* de la rotación queda intacta, que a una conexión abierta *después* se le sirve el certificado nuevo, y que el escucha sigue respondiendo bajo él — la mitad del lado del escucha de la recarga de certificados, cuya mitad del lado del gestor es `tests/tls_reload_test.rs`. Las respuestas vienen de registros de la base de datos local sin reenviadores.

- `tests/doq_test.rs` — un cliente `quinn` real contra `serve_doq`: se negocia el token ALPN `doq` (y un escucha sin él rechaza a un cliente que solo ofrece `doq`), el prefijo de longitud de 2 bytes concuerda con el cuerpo, varios flujos secuenciales y concurrentes en una conexión se responden de forma independiente, un cuerpo truncado no se responde, un mensaje de longitud cero se rechaza sin tirar la conexión, y un mensaje mal formado vuelve como FORMERR con su identificador de transacción devuelto. Las respuestas vienen de registros de la base de datos local sin reenviadores, así que un fallo es sobre el transporte y nunca sobre la resolución.
- `tests/doh_h3_test.rs` — un cliente `h3` real contra el escucha DoH de HTTP/3: el token ALPN `h3` se negocia desde una configuración sembrada con `h2`/`http/1.1` (así que lo que se prueba es la sustitución y no un token que puso el arnés), y un cliente que solo ofrece `h2` sobre QUIC es rechazado; las dos formas de petición de RFC 8484 se responden desde un mismo registro almacenado; el `Cache-Control` lleva el TTL propio de la respuesta, un número poco redondo elegido para que ningún valor por defecto fijo pueda pasar por él; una ruta equivocada, un método equivocado, un parámetro `dns` ausente y otro indescifrable se rechazan cada uno con el stream TERMINADO, porque un rechazo que envía cabeceras y no cierra se lee en el cliente como un resolutor colgado y no como una petición rechazada, y la conexión sobrevive a los cuatro; y cuatro peticiones en vuelo a la vez se responden sin cruzarse, algo que una prueba secuencial no distingue de un servidor que las serializó. El anuncio `Alt-Svc` también se fija aquí, en los dos sentidos: presente con el puerto del escucha cuando HTTP/3 corre, y del todo ausente cuando no.
- `tests/ddr_follow_test.rs` — la cadena DDR de extremo a extremo, recorrida como la recorre un cliente: se pregunta a un resolutor en marcha, por un socket UDP real, por `_dns.resolver.arpa. SVCB`, la respuesta se lee del rdata y no de la cadena que la sembró, y la petición DoH se construye con nada más que lo que dijo el registro —destino, puerto, token ALPN, plantilla de URI—, luego se resuelve allí un nombre y se comprueba su dirección. Cada parte de DDR ya tenía prueba y la cadena aún podía romperse por una plantilla que nadie sirve o un puerto que no nombra ningún escucha. El control pregunta en una ruta que la designación no nombró y exige un 404; sin él, seguir la plantilla no demuestra nada.
- `tests/proxy_test.rs` — proxies simulados de HTTP CONNECT, SOCKS5 (RFC 1928/1929) y DoH que **analizan** lo que el servidor envía en vez de responder con algo enlatado, así que un saludo mal formado o un tipo de dirección incorrecto falla en el proxy. Cada modo afirma tanto la respuesta como lo que se le pidió al proxy (destino del túnel, credenciales Basic, la línea de petición con URI absoluta y el cuerpo sin modificar), que un proxy que rechaza es SERVFAIL y no una respuesta fabricada, que el pool de conexiones DoH reutiliza un socket entre dos consultas, y —el control— que un proxy inalcanzable **no** cae a una conexión directa.
- `tests/tls_reload_test.rs` — `TlsManager` observado a través de saludos TLS reales: un par PEM rotado lo recoge `reload()` y solo `reload()`, un gestor autofirmado acuña un certificado fresco, el ALPN sobrevive a la reconstrucción, un fichero corrupto o ausente hace fallar la recarga dejando el certificado anterior sirviendo (y se recupera una vez reparado), y los observadores suscritos antes y después de una recarga acaban ambos sobre la configuración actual. Luego la mitad del sondeo: un par sin cambios no se recarga, uno rotado se detecta y se sirve, una **renovación cazada a mitad de escritura falla y se reintenta** en vez de registrarse como el estado nuevo, un gestor autofirmado no tiene nada que sondear y no recibe tarea de sondeo, y la propia tarea recoge una rotación por sí misma. Que un *escucha* siga el canal se fija aparte en `tests/dot_test.rs`.

### Pruebas de ZONEMD

`tests/zonemd_test.rs` fija el trazado del RDATA del RFC 8976 campo por campo —serial (u32 BE), esquema, algoritmo de hash, digest en crudo— escrito a mano en vez de tomado del codificador, ya que comparar el codificador consigo mismo ratificaría un fallo. También se cubre: un serial por encima de `i32::MAX`, un digest SHA-512 sin truncar, valores mal formados codificando a `None` (y por tanto siendo saltados-y-reportados por el firmante en vez de firmados sobre una codificación inventada), la ida y vuelta de almacenamiento por gRPC, el servicio bajo el tipo 63 con RDATA byte a byte idéntico a lo firmado, y un RRSIG sobre un RRset ZONEMD verificando contra el DNSKEY publicado.

### Pruebas de administración de ACME

`tests/acme_admin_test.rs` cubre los cinco RPC de administración. Las propiedades, no las banderas de `success`: `EnsureZoneCa` es idempotente (una reacuñación rompería todos los certificados que ya encadenan a la intermedia antigua, y con ellos el registro DANE-TA publicado) y le da a cada zona su propia intermedia bajo una raíz compartida mientras publica la cadena en el DNS; un EAB acuñado se almacena, tiene alcance de zona, está sin usar, y su clave base64url devuelta decodifica al secreto almacenado; la eliminación es honesta sobre si eliminó algo y se confina a la credencial nombrada; y `ListAcmeCertificates` casa por sufijo en fronteras de etiqueta, así que `notexample.com.` no se lista bajo `example.com.`

`tests/acme_tlsa_endpoints_test.rs` cubre `acme.tlsa_endpoints` allí donde un fichero de configuración se encuentra con el binario real, que es el único sitio donde esa severidad se observa. Una entrada malformada —sin protocolo, con un protocolo que no es TCP ni UDP, un puerto fuera de rango, un puerto que no es un número, el puerto cero— tiene que detener el servidor en vez de saltarse, porque una entrada saltada es un registro TLSA que en silencio no aparece nunca, y para un cliente que comprueba DANE un registro ausente y un servidor sin DANE son indistinguibles. Se lanzan cinco formas malformadas, cada una con la afirmación de que termina con código distinto de cero; los controles son un `["853/tcp", "853/udp"]` bien formado y la ausencia de la clave, que deben arrancar y seguir en pie — sin ellos, un servidor que no arrancara por cualquier motivo ajeno satisfaría todos los rechazos.

### Pruebas de integración de la CLI

El binario `rolodex-dns-cli` tiene pruebas de integración que lanzan un servidor gRPC de prueba y ejecutan el binario de la CLI contra él, cubriendo **todas** las subórdenes sobre los transportes TCP y socket Unix: autenticación (éxito, fallo y salto por socket Unix), todos los tipos de registro, filtrado por comodín, pertenencia a red y registros con ámbito, zonas autoritativas, cachés, la lista de bloqueo local, la deriva de TTL y DNS64, conjuntos/concesiones/opciones de certificado de DHCP, generación de claves DNSSEC y firma, generación de TLSA de DANE, y las órdenes de administración de ACME.

La CLI se prueba aparte del servicio gRPC porque es una superficie aparte: un manejador puede estar perfectamente probado y su suborden seguir rota por un `short` mal tecleado, un campo mapeado a la ranura de petición equivocada, o un `default_value` que discrepa del del servidor. Dos consecuencias se fijan explícitamente:

- `test_cli_every_subcommand_help_builds` recorre la lista de subórdenes sacada de la ayuda de nivel superior y ejecuta `--help` en cada una. clap valida las opciones cortas al construir el analizador y entra en **pánico** ante un duplicado, así que una suborden que reutilice una letra tomada por una opción global aborta en toda invocación antes de leer un solo argumento — que es como `generate-dnssec-key` (`-a`/`--algorithm`) y `set-ttl-drift` (`-a`/`--adjustment`) chocaron ambos con el `--address` global y se volvieron imposibles de ejecutar. Ambos son ahora solo de forma larga.

Donde una orden lee un estado que ninguna suborden puede crear —una concesión DHCP, un certificado emitido, una cuenta ACME registrada— la prueba lo siembra por la base de datos del servidor y lo lee de vuelta por la CLI, así que se demuestra que el listado renderiza filas reales y no una tabla vacía.

### Pruebas del cliente Go

El cliente Go tiene dos capas de pruebas:

- **Pruebas unitarias** — usan un servidor gRPC simulado en proceso vía `bufconn` para probar todos los métodos del cliente, la propagación del token de autenticación, los modos de transporte, el manejo de errores y los casos límite (cierre idempotente, marcado perezoso, opciones de marcado propias).
- **Pruebas de integración** — condicionadas a la etiqueta de compilación `integration`. Cada prueba arranca un subproceso real de servidor Rolodex DNS con un directorio temporal único, puertos aleatorios y base de datos aislada. Las pruebas cubren el CRUD de registros, el filtrado por comodín, la configuración de reenviadores, la ida y vuelta de la lista de bloqueo, el vaciado de caché, el transporte por socket Unix, el fallo de autenticación, el comportamiento del TTL por defecto, clientes concurrentes (5 simultáneos), los ámbitos de red, DNS64 y la deriva de TTL.

El objetivo `make test` ejecuta la batería completa: lint, pruebas de integración de Go, pruebas unitarias de Go, pruebas de integración de Rust (cada fichero de prueba explícitamente: `integration_test`, `new_features_test`, `cli_integration_test`, `dhcp_integration_test`, `acme_issuer_test`, `auto_resolution_test`, `metrics_test`, `blocking_metrics_test`, `promql_docs_test`, `prometheus_integration_test`, `blocklist_refusal_test`, `dnssec_signing_test`, `dnssec_validation_test`, `dnssec_hidden_cut_test`, `arpa_refusal_test`, `blocklist_nxdomain_test`, `zonemd_test`, `dot_test`, `doq_test`, `proxy_test`, `tls_reload_test`, `acme_admin_test`, `acme_tlsa_endpoints_test`, y las baterías `security_*`), todas las pruebas de Rust vía `cargo test` (que cubre también la batería del resolutor de arriba), y las pruebas de lint/integración/unitarias de JavaScript. Hay objetivos individuales disponibles: `make go-integration-test`, `make go-test`, `make rust-integration-test`, `make rust-test`, `make js-integration-test`, `make js-test`. Usa `make test-log` para capturar la ejecución entera en un fichero de registro con marca de tiempo. `make translation-check` compara cada documento traducido con el inglés sección por sección y termina con código distinto de cero ante cualquier desviación; es un prerrequisito de `lint`, así que se ejecuta dentro de `make test` y hace fallar la puerta cuando un idioma se queda atrás.

## Dependencias principales

### Rust

- **domain** / **hickory-resolver** / **hickory-proto** — análisis del protocolo DNS, tipos de registro y resolución upstream
- **tonic** / **tonic-prost** / **prost** / **prost-types** — framework gRPC y serialización de protocol buffers
- **rusqlite** (bundled) — base de datos SQLite con modo WAL
- **tokio** / **tokio-stream** / **async-trait** — runtime asíncrono (conjunto completo de características), adaptadores de flujo para el escucha gRPC por socket Unix, y traits asíncronos
- **dashmap** — mapa/conjunto hash concurrente sin cerrojos para caché
- **arc-swap** — intercambio atómico sin cerrojos de punteros `Arc` para la configuración en caliente
- **clap** — análisis de argumentos de la CLI (servidor y cliente)
- **tracing** / **tracing-subscriber** — registro estructurado (configurable con la variable de entorno `RUST_LOG`)
- **hyper-util** / **tower** — transporte HTTP/2 para las conexiones gRPC por socket Unix
- **rustls** / **tokio-rustls** — TLS para los transportes DNS cifrados
- **rcgen** (con la característica `x509-parser`) — generación de certificados y firma de CA (raíz → intermedia por zona → hoja desde CSR)
- **x509-parser** — extracción del SPKI para los registros TLSA y la importación de CA
- **time** — periodos de validez de certificado y marcas de tiempo RFC 3339 en las respuestas ACME
- **axum** / **axum-server** — framework HTTP para DoH
- **quinn** — protocolo QUIC para DoQ
- **ring** / **sha2** — operaciones criptográficas para DNSSEC y DANE
- **subtle** — comparación en tiempo constante del secreto compartido de gRPC (el `verify_slices_are_equal` propio de ring está obsoleto y documentado como de uso interno sin promesas sobre canales laterales)
- **base64** — codificación Base64 para las peticiones GET de DoH
- **hex** — codificación hexadecimal para los registros TLSA/DNSSEC
- **serde** / **serde_yaml_ng** — serialización de la configuración
- **fancy_duration** — análisis de duraciones compuestas para la deriva de TTL
- **rand** — aleatorización de mayúsculas del QNAME, jitter en la selección de servidores de nombres
- **nix** — abstracciones seguras de la interfaz Unix (enumeración de direcciones de interfaz vía `getifaddrs`)
- **socket2** — `SO_REUSEPORT` en los escuchas UDP fragmentados (véase Modelo de concurrencia); la única forma de poner la opción antes de `bind`, y segura — sin ningún bloque `unsafe` nuestro
- **bytes** — búferes de cable sin copias compartidos con los códecs de DNS y gRPC
- **webpki-roots** / **rustls-pemfile** — anclas de confianza para los clientes upstream cifrados (DoH/DoT); carga de PEM
- **dhcproto** — análisis y serialización de mensajes DHCPv4
- **serde_json** — las superficies JSON del portal y de ACME
- **anyhow** / **thiserror** — manejo de errores

### Desarrollo / benchmarks

- **criterion** — framework de micro-benchmarking para pruebas de regresión de rendimiento
- **assert_cmd** / **predicates** — para gobernar el binario `rolodex-dns-cli` en las pruebas de integración de la CLI
- **tempfile** — directorios y bases de datos aislados por prueba (ninguna prueba escribe jamás en el árbol de trabajo ni en el equipo)
- **tokio-test** / **mockall** — ayudantes de prueba asíncronos y simulación
- **rustls-webpki** — aserciones sobre cadenas de certificados en las baterías de TLS/ACME

### Go

- **google.golang.org/grpc** — framework gRPC
- **google.golang.org/protobuf** — runtime de protocol buffers

## Modelo de concurrencia

El servidor corre sobre el runtime asíncrono multihilo de tokio. Cada dirección de escucha UDP está **fragmentada entre sockets `SO_REUSEPORT`** (`dns.udp_shards`, por defecto uno por núcleo): un único socket serializa el escucha —una tarea lo drena con `recv_from` y toda respuesta compite por él— lo que limita el rendimiento muy por debajo de la saturación de CPU por muchos núcleos que estén ociosos. Cada fragmento corre su propio bucle de recepción y responde por su propio socket, así que el núcleo reparte por hash los datagramas que llegan entre los núcleos en ambas direcciones. `SO_REUSEPORT` se pone solo cuando se pide más de un fragmento, así que un escucha de un solo fragmento sigue fallando ruidosamente en un puerto ocupado (de lo que depende el manejo de fallos de enlace de ingreso) en vez de compartirlo en silencio; un enlace al puerto `0` (efímero) se fuerza a un fragmento, ya que el núcleo le daría si no a cada fragmento un puerto distinto. Los fragmentos viven en un `JoinSet` que posee el futuro `serve_udp`, así que abortar la tarea que lo impulsa —como hace `stop_ingress_listener`— desmonta todos los fragmentos con ella. Dentro de un fragmento se lanza una tarea por consulta recibida. Las conexiones DNS por TCP lanzan una tarea nueva por conexión. Las conexiones DoT, DoH y DoQ lanzan cada una una tarea nueva por conexión. Los servidores gRPC (TCP y socket Unix) corren como tareas separadas. La configuración de los reenviadores upstream está protegida por `ArcSwap` para lecturas sin cerrojos. El estado de la lista de bloqueo usa primitivas sin cerrojos: la bandera de activación es un `AtomicBool` y la lista de proveedores usa `ArcSwap` para lecturas sin contención. La caché de la lista de bloqueo y la caché de respuestas DNS usan `DashMap` sin cerrojos. La base de datos SQLite está protegida por un `Mutex` con `prepare_cached` para reutilizar sentencias.

Al arrancar, las cachés en memoria se pueblan desde la base de datos: recuento de ámbitos (`AtomicUsize`), entradas de la lista de bloqueo local (`DashSet`), entradas de la lista de permitidos de DNSBL (`DashSet`), zonas autoritativas (`DashSet`), zonas gestionadas (`DashSet`), propiedad de TLD (`tld_owner_cache`), IP de ingreso por TLD (`tld_ingress_cache`), y la caché de delegaciones persistida. Estas cachés evitan consultas SQL en la ruta caliente y se actualizan de forma incremental conforme se añaden o eliminan registros por gRPC.

La máquina de estados de resolución `auto` es enteramente libre de cerrojos: el nivel activo, la racha de desviación, la marca de tiempo del último sondeo y los parámetros de gracia/sondeo son atómicos. El sondeo de recuperación corre en una única tarea de fondo en vez de en la ruta de consulta, así que no necesita elección por compare-exchange — solo hay siempre un sondeador. La lista de upstreams seguros, la lista de reserva pública, el modo de resolución y la lista de CIDR de superposición usan `ArcSwap`. La supresión de familia en las respuestas es un par de `AtomicBool` escritos por la tarea de sondeo de fondo. Los escuchas de ingreso se rastrean en un `DashMap<IpAddr, Vec<AbortHandle>>`; la caché de delegaciones se persiste mediante un trabajador de escritura SQLite de fondo alimentado por un canal `mpsc`, y las cachés de delegaciones y de registros son `DashMap`.

El registro de Prometheus es libre de cerrojos por los mismos medios: los contadores y medidores son `AtomicU64`, las familias de etiqueta fija son arrays ya reservados indexados directamente (así que un incremento es un índice más un `fetch_add` relajado, sin hashing y sin reservas), los histogramas son atómicos por bucket acumulados en forma acumulativa solo al renderizar, y las familias etiquetadas en tiempo de ejecución son `DashMap`. Nada en la ruta de consulta toma un cerrojo para registrar una métrica. La ruta de raspado tira de sus medidores con una única llamada a `Database::metrics_counts`, así que retiene el mutex de SQLite una vez por raspado en vez de una docena de veces.

El reenvío DNS upstream usa un pool de 8 sockets UDP, lo que permite reenviar de forma concurrente sin contención sobre un único socket. La selección de socket es por turno rotatorio mediante `AtomicUsize`.

La caché DNS en memoria se vacía automáticamente cuando se mutan registros por gRPC (alta, baja o variantes con ámbito) para garantizar la coherencia entre la base de datos y las respuestas cacheadas. Los registros de la base de datos local se cachean con una bandera `local` que impide el decaimiento del TTL y la persistencia en SQLite, ya que son autoritativos.

La configuración de deriva de TTL usa `ArcSwap` para lecturas sin cerrojos, siguiendo el patrón usado para la configuración de reenviadores.

### Optimizaciones de rendimiento

La ruta caliente del DNS usa varias optimizaciones para minimizar las reservas y la contención por cerrojos:

- La **aleatorización de mayúsculas del QNAME** opera directamente sobre los bytes del formato de cable de DNS (conmutando el bit 0x20 en los bytes alfabéticos ASCII) en vez de analizar, clonar, reconstruir y reserializar el mensaje DNS entero. Esto evita unas 6 reservas por consulta reenviada.
- Las **búsquedas en BD por lotes** (`lookup_with_fallbacks`) combinan las búsquedas exacta, comodín, CNAME y ANAME en una única consulta SQL `UNION ALL`, reduciendo las adquisiciones de cerrojo de 4 o más a 1 por consulta.
- La **coincidencia de zonas** usa búsquedas O(etiquetas) por sufijo sobre `DashSet` (`find_managed_zone`, `find_authoritative_zone`) en vez de una iteración lineal O(zonas) con `ends_with()`.
- La **caché DNS** almacena los registros como `Arc<Vec<DnsRecord>>` para eliminar el clonado en la inserción en caché y en los aciertos de caché local. Las claves de caché usan `String::with_capacity` predimensionado sin `to_lowercase()` redundante (los nombres ya están normalizados).
- La **persistencia de caché por lotes** usa un canal `mpsc` acotado (capacidad 1024) con un único trabajador de fondo que drena hasta 64 escrituras de una vez, sustituyendo al `tokio::spawn` por inserción.
- La **reutilización del búfer UDP** reserva el búfer de recepción una vez fuera del bucle y clona solo `len` bytes (con `Vec::with_capacity` + `extend_from_slice`) en vez de copiar siempre el búfer completo de 4096 bytes.
- El **pool de conexiones del proxy DoH** reutiliza conexiones TCP mediante un pool `DashMap` por dirección de proxy (máximo 8 conexiones por dirección) con keep-alive de HTTP/1.1 en vez de `Connection: close`.

### Benchmarks

Los benchmarks de criterion en `benches/dns_perf.rs` cubren las rutas críticas para el rendimiento. Se ejecutan con `make bench`. Operaciones medidas:

- `qname_randomize` / `qname_randomize_long_name` — aleatorización de mayúsculas del QNAME en formato de cable
- `cache_key_with_type` / `cache_key_wildcard` — generación de claves de caché
- `lookup_with_fallbacks_exact_hit` / `_miss` / `_wildcard` — búsquedas en BD por lotes con UNION ALL
- `lookup_original_exact_hit` / `_miss` — búsquedas en BD de consulta única originales (para comparar)
- `find_managed_zone_hit` / `_miss` — coincidencia de zonas O(etiquetas)
- `find_authoritative_zone_hit` / `_miss` — coincidencia de zonas autoritativas O(etiquetas)
- `is_authoritative_zone_hit` / `_miss` — comprobación de zona combinada
- `cache_lookup_local_hit` / `cache_lookup_upstream_hit` / `cache_lookup_miss` — búsquedas en la caché DNS
- `cache_insert_local` — inserción en la caché DNS
- `handle_query_local_hit` / `handle_query_local_nxdomain` — tubería de consulta de extremo a extremo (analizar → resolver → serializar)
- `handle_query_cached_hit` — tubería de consulta con la caché DNS activada (ruta de acierto de caché)
- `handle_query_A` / `_AAAA` / `_TXT` / `_MX` — tubería de consulta a través de los tipos de registro
- `handle_query_scoped_hit` — tubería de consulta con ámbitos de red (horizonte partido)
- `udp_round_trip` / `udp_round_trip_reuse_socket` — ida y vuelta completa por socket UDP (socket de cliente nuevo frente a reutilizado)
- `tcp_round_trip_new_conn` / `tcp_round_trip_reuse_conn` — ida y vuelta completa por TCP con enmarcado de longitud de 2 bytes (conexión nueva frente a reutilizada)
