# El contrato con Town OS

> Idiomas: [English](TOWNOS_CONTRACT.md) | [繁體中文](TOWNOS_CONTRACT.zh-TW.md) | [简体中文](TOWNOS_CONTRACT.zh-CN.md) | **Español (España)** | [Español (México)](TOWNOS_CONTRACT.es-MX.md) | [日本語](TOWNOS_CONTRACT.ja-JP.md)

Esta es la lista autorizada de todo lo que cruza la frontera entre rolodex y Town OS, en ambas direcciones.

**La dirección es la contraria a la de gfeh.** gfeh es un cliente de Town OS; rolodex es algo que Town OS gobierna. El systemcontroller de Town OS es el cliente gRPC de rolodex, la imagen de `../install` escribe el archivo de configuración de arranque de rolodex, y ttyforce escribe la configuración de red que decide qué puede descubrir rolodex. Así que casi todo lo que sigue es **lo que esos tres pueden dar por supuesto sobre rolodex**, y una sección corta de lo que rolodex exige a cambio.

**Aquí no hay nada fijado a una revisión.** `make check-townos-sync` resuelve los checkouts que haya en la máquina en el momento en que se ejecuta. Una revisión anotada que ningún script lee es una afirmación que nadie mantiene, y un pin fallaría ruidosamente en commits de Town OS que no cambiaron nada de lo que rolodex depende — lo peor de ambos.

| Comando | Contra qué comprueba | ¿Se salta? |
|---|---|---|
| `make check-townos-sync` | checkouts locales (`TOWNOS_DIR=`, `INSTALL_DIR=`) | sí, si no están |

Se ejecuta como parte de `make lint`, así que el desarrollo corriente obtiene la comprobación gratis y sigue funcionando en una máquina que solo tiene este repositorio.

### Qué verifica realmente la comprobación

Los nombres por sí solos no bastan — una constante que sigue existiendo pero se movió es exactamente el fallo que aquí queda en verde y se rompe en la máquina. La comprobación compara:

- **Que todo método que declara la interfaz `Client` de Town OS existe en el propio cliente Go de rolodex (`go/client.go`).** Esa, y no el proto, es la superficie a la que Town OS se ata: su propia estructura `client` delega directamente al paquete Go de este repositorio. Algunos de esos métodos son envoltorios de conveniencia y no rpcs distintos (`AddScopeTldWithListener` es `AddScopeTld` con `listen_ip` puesto), así que una comprobación solo contra el proto informa de una deriva que no existe y se pierde un envoltorio eliminado, que sí es deriva.
- **Que los conjuntos de esquemas de reenviador de los dos analizadores son idénticos** — `src/forwarder.rs` aquí y `src/rolodex/forwarder.go` allí. Dos analizadores escritos a mano de la misma gramática, en repositorios que no pueden verse, es lo más nuevo y lo menos defendido de este documento.
- **Que las direcciones fijas coinciden en los tres repositorios**: el backend DoH, el listener de métricas, el loopback que rolodex enlaza y el directorio TLS, como constante Go, como literal en el script de instalación y como valor por defecto aquí.

## Alcance

Tres contrapartes, y no son intercambiables:

1. **Town OS (`../town-os`)** — el systemcontroller. Programa los *ajustes* de rolodex por gRPC y recolecta sus métricas. No escribe ningún archivo de configuración.
2. **La imagen de instalación (`../install`)** — `scripts/rolodex-config.sh` escribe `rolodex.yml` y nadie más lo hace. Lleva solo lo que no se puede fijar en un rolodex en marcha.
3. **ttyforce (`~/src/github.com/erikh/ttyforce`)** — escribe las unidades de networkd. Aparece aquí únicamente porque una de sus decisiones (`UseDNS=no`) determina qué puede encontrar el descubrimiento de reenviadores de Town OS, cosa que no es evidente desde ninguno de los dos lados.

Nada más cruza la frontera. En particular:

- **rolodex nunca llama a Town OS.** No hay cliente HTTP, ni consulta de cuentas, ni llamada de almacenamiento. Todo fluye hacia dentro.
- **rolodex no escribe ningún archivo que Town OS lea.** Su base de datos es suya; el socket gRPC y el endpoint de métricas son toda la superficie hacia fuera.

## `rolodex.yml` es solo de arranque, y los dos repositorios se mueven juntos

`scripts/rolodex-config.sh` en `../install` es el único escritor. Lleva exactamente lo que no se puede fijar en un servidor en marcha:

| Clave | Por qué no se puede programar |
|---|---|
| `dns.bind` | Los listeners tienen que existir antes de que ninguna llamada a la API pueda alcanzarlos |
| `metrics.bind` | rolodex abre ese listener una sola vez al arrancar, por la presencia de la sección |
| `doh` / `dot` / `doq` | Se abren una sola vez al arrancar, por la presencia de cada sección |
| `database_path`, `grpc` | Se leen antes de que el servidor exista |
| `forwarders`, `resolution.mode` | Solo valores **de arranque** — el systemcontroller programa las decisiones reales del operador por gRPC |

**Serde rechaza de plano un campo desconocido o ausente.** Un campo requerido en la revisión de la imagen y ausente del archivo — o presente en el archivo y desconocido para la imagen — es un `failed to parse config file` duro al arrancar, y bajo `Restart=always` eso es un bucle de caídas con el DNS caído para todo lo que hay en la máquina. Ya ha pasado una vez, con el renombrado de `rbl` a `dnsbl`.

La regla que se sigue: **el `rolodex-config.sh` del repositorio de instalación y la imagen publicada de rolodex se mueven juntos.** Una clave de configuración renombrada aquí sin el cambio correspondiente allí es una máquina rota, no un test fallido. `TestRolodexDohBackendMatchesTheInstallScript` en Town OS atrapa exactamente una dirección de esto, y solo donde `../install` está clonado.

## Los ajustes viven solo en memoria

rolodex **no** persiste nada de lo fijado por gRPC. Toma su semilla de `rolodex.yml` al arrancar y mantiene el resto en memoria, así que una caída bajo `Restart=always`, un cambio de concesión DHCP que rebota la unidad, o un operador reiniciándolo a mano devuelven todos los ajustes que Town OS empujó a los valores de arranque.

La obligación de Town OS, por tanto: **volver a empujar tras cada reinicio.** `ProgramRolodex` corre en un tick de 15 segundos y advierte un reinicio a través de `Manager.Generation` — la identidad del socket gRPC que rolodex enlaza al arrancar (dispositivo, inodo, mtime). Nada en rolodex anuncia un reinicio; la identidad del socket es la señal.

Dos consecuencias que conviene decir con claridad:

- **Un reempuje idéntico tiene que ser gratis.** `SetForwarders` y los setters de la lista de bloqueo son almacenamientos simples — sin vaciado de caché, sin reconexión aguas arriba — precisamente para que el tick pueda empujar incondicionalmente en lugar de comparar. `SetResolutionMode` *no* es gratis (entrar en `auto` reinicia el descubrimiento de escalones), y por eso Town OS compara ese contra `GetResolutionMode` y empuja solo cuando cambia.
- **La salud por reenviador tiene que sobrevivir al tick.** Un cortacircuitos propiedad de la lista empujada se reiniciaría cada 15 segundos — más deprisa de lo que tres fallos pueden dispararlo — así que `forwarder::carry_health` traslada la salud a la lista de reemplazo por etiqueta. Es una obligación del lado de rolodex creada enteramente por la cadencia de empuje de Town OS, y es la razón de que la etiqueta de un reenviador sea estable y no cosmética.

## La gramática de las especificaciones de reenviador

**Dos analizadores escritos a mano, una gramática y ningún código generado entre ellos.** `src/forwarder.rs` aquí y `src/rolodex/forwarder.go` en Town OS aceptan las mismas cadenas; los repositorios no pueden verse y nada en tiempo de compilación los ata. `make check-townos-sync` compara los conjuntos de esquemas, y los tests unitarios de cada lado fijan deliberadamente los mismos casos. Trátalo como la única guarda que hay.

`SetForwarders` sigue tomando `repeated string`, sin cambios, así que la gramática viaja sobre el tipo de cable que ya existía:

| Especificación | Transporte |
|---|---|
| `8.8.8.8:53` | UDP en claro (Do53) |
| `tcp://8.8.8.8:53` | TCP en claro (RFC 7766) |
| `tls://cloudflare-dns.com@1.1.1.1:853` | DoT (RFC 7858) |
| `https://cloudflare-dns.com@1.1.1.1/dns-query` | DoH (RFC 8484) |
| `quic://dns.adguard.com@94.140.14.14:853` | DoQ (RFC 9250) |

Propiedades de las que el lado de Town OS depende exactamente:

- **Un `ip:port` pelado es UDP en claro.** Todo llamante escrito antes de que los transportes fueran nombrables sigue funcionando, y el esquema es lo que un llamante añade para pedir otra cosa. Tanto `udp://` como la forma pelada se analizan hacia el mismo reenviador y llevan la misma etiqueta de métricas.
- **La dirección es siempre un literal, nunca un nombre de host.** `name@ip` lleva la dirección a la que marcar y el nombre contra el que validar el certificado, en una sola cadena. Esta es la propiedad de arranque: un upstream cifrado que hubiera que resolver primero no podría ser lo que arregla una máquina sin DNS que funcione.
- **En qué escalón cae un reenviador lo decide rolodex, no Town OS.** Se deriva del reenviador — cifrado, luego en claro privado, luego en claro público — así que Town OS no debe ordenar la lista para expresar preferencia, ni suponer que el orden que envió es el orden que se prueba.
- **La validación es todo o nada.** `SetForwarders` reemplaza la lista, así que rolodex analiza cada entrada antes de aplicar ninguna, y Town OS valida antes de empujar. Una lista aceptada con una entrada descartada deja al resolutor sosteniendo algo que nadie pidió.

**Los upstreams cifrados solo son programables a través de esta lista.** `resolution.secure_upstreams` en `rolodex.yml` no tiene setter gRPC y se lee una sola vez al arrancar. Antes de que la lista fuera tipada, eso significaba que el único escalón que funciona en una red que filtra el `:53` saliente era también el único que nada podía reconfigurar sin reiniciar el único resolutor de la máquina — mientras que el escalón que *sí* era programable solo podía llevar las direcciones en claro que semejante red descarta.

## Direcciones fijas

Cada una de estas está escrita en más de un repositorio, y cada par ha estado mal al menos una vez:

| Valor | rolodex | Town OS | `../install` |
|---|---|---|---|
| `127.0.0.2` | primera entrada de `dns.bind` | `rolodex.DNSLoopback` | `add_bind 127.0.0.2` |
| `127.0.0.2:9153` | `metrics.bind` | `rolodex.DefaultMetricsPort` | literal `metrics.bind` |
| `127.0.0.2:4443` | `doh.bind` | `systemcontroller.RolodexDohBackend` | literal `doh.bind` |
| `/data/tls/dot` | `cert_path` de `dot`/`doq` | `systemcontroller.RolodexTLSSubdir` | `ENC_CERT` / `ENC_KEY` |
| `/data/rolodex.sock` | `grpc.unix_socket` | `Config.UnixSocketPath` | literal `unix_socket` |

Que sea `4443` y no `443` es determinante: el ingress se publica en `0.0.0.0:443` y rolodex corre con `--net host`, así que un `:443` comodín y un `127.0.0.2:443` específico en un mismo namespace es `EADDRINUSE` para el que enlace segundo — cae el DNS o cae el ingress, según el orden de arranque.

Que sea `127.0.0.2` y no `127.0.0.1` evita el stub de systemd-resolved en `127.0.0.53` y cualquier otra cosa en `127.0.0.1`; es además la dirección a la que `bootstrap-dns.sh` apunta resolved, así que es el único enlace sin el cual la resolución de la propia máquina no puede funcionar.

## Métricas

rolodex sirve la exposición de texto de Prometheus en `127.0.0.2:9153`, abierta una sola vez al arrancar por la presencia de la sección `metrics`. Town OS configura el objetivo de recolección desde `rolodex.Manager.MetricsAddr()` en lugar de recomponerlo desde un valor por defecto, así que el objetivo y el enlace no pueden separarse.

Dos propiedades de las que depende la monitorización de Town OS:

- **Toda dimensión de etiqueta está acotada.** Un enum fijo, o acotada por configuración. Cualquier cosa que un cliente controle se pliega en un cajón de sastre (`OTHER` para tipos de consulta, `other` para TLD). **Los nombres de consulta nunca son etiquetas.** `upstream_queries_total{server}` y `upstream_skipped_total{server}` están acotadas por la lista de reenviadores configurada.
- **Los valores de etiqueta nuevos se añaden, nunca se insertan.** Las constantes del estilo `BLOCK_*` son posiciones en un array preasignado; una inserción reetiqueta en silencio todos los contadores existentes.

Añadir o renombrar una métrica implica actualizar el recuento de familias y las consultas afectadas en `README.md` y `DESIGN.md` — `tests/promql_docs_test.rs` fija el recuento documentado contra lo que el registro emite.

## Exigido de Town OS: no reordenar, y no dar por supuesto Do53

Dos cosas que Town OS *no* debe hacer, y ambas solían ser seguras:

- **No ordenar ni reordenar la lista de reenviadores para expresar preferencia.** El orden dentro de un escalón se respeta — es la secuencia que rolodex prueba — pero el escalón mismo se deriva. Una lista ordenada por Town OS con "los cifrados primero" es redundante en el mejor caso y, si esa ordenación discrepa de la derivación de rolodex, engañosa en los registros.
- **No suponer que un reenviador es `ip:port`.** `Manager.Forwarders` puede devolver una especificación con esquema. Cualquier cosa que parta un reenviador por `:` para recuperar host y puerto está mal para `tls://name@ip:853` y catastróficamente mal para un literal IPv6.

## Exigido de Town OS: el resolutor de DHCP no es descubrible desde resolv.conf

Este es el único punto donde una decisión de Town OS/ttyforce desactiva en silencio una funcionalidad del lado de rolodex, y se anota aquí porque ninguno de los dos lados se equivoca por sí solo.

- ttyforce escribe `[DHCPv4] UseDNS=no` (y el equivalente v6) en sus unidades de networkd, así que los resolutores ofrecidos por DHCP nunca llegan a ser un resolutor por enlace que superase a rolodex.
- `bootstrap-dns.sh` en `../install` apunta systemd-resolved a `127.0.0.2` siempre que rolodex está en marcha.
- `/etc/resolv.conf` es el propio stub `127.0.0.53` de resolved.

Los tres son loopback o inexistentes, y los tres se descartan correctamente como bucles de consulta. Así que `HostResolversFrom` de Town OS no encuentra **nada** en una máquina en marcha, y su descubrimiento de reenviadores locales tiene que leer la **pasarela por defecto** de `/proc/net/route` para encontrar algo siquiera. La pasarela sobrevive porque viene de la opción *router* de la concesión DHCP y no de su opción DNS.

Cualquier cosa que cambie una de esas tres decisiones cambia qué puede encontrar el descubrimiento. Cámbialas juntas o no las cambies.

## Divergencias conocidas

Anotadas para que nadie las descubra depurando:

- **La superficie gRPC de rolodex es mucho mayor que lo que Town OS usa.** El proto declara la API de gestión completa; la interfaz `Client` de Town OS es un subconjunto. La comprobación verifica que todo lo que Town OS declara existe aquí, no al revés — un rpc que ningún cliente de Town OS llama no es una deriva.
- **`shared_secret` está vacío y la autenticación son los permisos del sistema de archivos.** El script de instalación escribe `grpc.tcp_bind: ""` y un socket Unix, así que el modo de ese socket es todo el control de acceso. Un bind TCP necesitaría el secreto, y nada en Town OS fija uno.
- **`GetForwarders` no existe.** Town OS empuja incondicionalmente y no puede leer de vuelta lo que rolodex sostiene. Por eso `GET /dns/status` informa de lo que Town OS *programaría* en lugar de lo que rolodex tiene.
- **Los reenviadores de scope/TLD son otra lista.** `SetScopeTldForwarders` es reenvío entre pares por scope y no es la lista global de reenviadores; es `ip:port` a secas y no admite la gramática de transportes de arriba.

## Mantenerse en sincronía

Town OS se distribuye como imágenes de contenedor por arquitectura sin versión semántica, así que una revisión de commit es la única unidad precisa de sincronización — y deliberadamente **no hay pin**.

**En todo cambio que toque la superficie gRPC, la gramática de reenviadores o cualquier dirección fija:**

1. Ejecuta `make check-townos-sync` con `TOWNOS_DIR` e `INSTALL_DIR` apuntando a los checkouts.
2. Reconcilia cualquier fallo actualizando el otro lado **y** este documento a la vez — nunca uno sin el otro.
3. Si el cambio renombra o elimina una clave de `rolodex.yml`, el script de instalación y la imagen publicada tienen que salir juntos. No hay ningún apretón de manos de versiones que lo atrape.
