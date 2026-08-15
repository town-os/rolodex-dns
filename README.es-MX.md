# Rolodex DNS

> Idiomas: [English](README.md) | [繁體中文](README.zh-TW.md) | [简体中文](README.zh-CN.md) | [Español (España)](README.es-ES.md) | **Español (México)** | [日本語](README.ja-JP.md)

Un servidor DNS de horizonte partido y resolvedor recursivo/reenviador con la privacidad por delante, con transportes cifrados, DNSSEC y administración por gRPC, escrito en Rust.

Rolodex DNS ofrece DNS sobre UDP, TCP, TLS (DoT), HTTPS (DoH) y QUIC (DoQ) con una base de datos local de registros que tiene prioridad sobre la resolución externa. Los registros se administran en remoto por gRPC (autenticación por secreto compartido sobre TCP, o sin autenticar por socket Unix). Admite resolución a nivel de TLD con superposición de dominios, de modo que las representaciones internas del DNS siempre se prefieren. Un caché de respuestas DNS integrado evita la fuga de consultas a los resolvedores upstream una vez que un registro se ha visto.

Los nombres que no son locales se resuelven **iterativamente desde los servidores raíz** por omisión, cayendo por upstreams cifrados (DoH/DoT) y en claro, de modo que la resolución sobrevive a redes que filtran el puerto 53 saliente. Véase [Resolución upstream](#resolución-upstream).

Las respuestas resueltas desde las raíces se **validan con DNSSEC** contra las anclas de confianza de IANA por omisión; los datos bogus no se sirven ni se cachean nunca. Véase [DNSSEC](#dnssec).

Rolodex DNS admite además listas de bloqueo de dominios (DNSBL) para filtrar spam y malware, firma DNSSEC de zonas, asociación de certificados DANE TLSA, una autoridad de certificación ACME integrada, síntesis AAAA de DNS64, particionado del DNS por red, y un servidor DHCPv4 integrado.

¿Nuevo por aquí? Empieza por la **[Guía de configuración](CONFIGURATION.es-ES.md)** — un recorrido orientado a tareas desde una configuración mínima que funciona hasta cada subsistema, con un ejemplo resuelto por forma de despliegue.

## Funcionalidades

- **Caché DNS con la privacidad por delante**: el cacheado local de respuestas DNS evita la fuga de consultas al upstream. Una vez cacheadas, las consultas se responden localmente sin contactar con ningún reenviador. Pon `forwarders: []` para un servidor puramente autoritativo.
- **Transportes cifrados**: DNS-over-TLS (DoT, puerto 853), DNS-over-HTTPS (DoH, puerto 443 con GET/POST), DNS-over-QUIC (DoQ, puerto 8853)
- **DNS de horizonte partido**: los registros de la base de datos local siempre tienen prioridad sobre los resultados resueltos externamente
- **DNS sobre UDP y TCP**: soporte completo del protocolo para ambas capas de transporte
- **Resolvedor recursivo con reserva resiliente**: resolución iterativa desde los servidores raíz por omisión, luego DoH/DoT a resolvedores públicos, luego los reenviadores configurados, luego resolvedores públicos en claro — de modo que la resolución sigue funcionando en redes que filtran `:53` (y con DPI que bloquea el `:853` de DoT). Un nivel pegajoso evita pagar tiempos de espera en un camino muerto, y todo cambio de nivel vacía el caché
- **Cacheado del resolvedor que honra los TTL**: un caché persistente de delegaciones zona→servidor de nombres (caliente entre reinicios), un caché en memoria para glue, búsquedas de NS sin glue y saltos CNAME, y cacheado negativo del RFC 2308 — todo servido con su vida restante
- **Conciencia de la familia de direcciones**: una sonda de fondo prueba la alcanzabilidad real de internet por IPv4/IPv6 y suprime las respuestas A o AAAA de una familia que el equipo no puede enrutar, así los clientes recurren a la otra en vez de atascarse en una pila muerta
- **Resolvedor reenviador**: reenviadores DNS upstream configurables, usables en exclusiva con `resolution.mode: forward`
- **Superposición de TLD/dominios**: agrega registros en cualquier nivel (incluidos TLD) para sustituir el DNS público
- **Firma DNSSEC**: generación de llaves Ed25519 (preferido) y ECDSA P-256/P-384, firma de zonas y cálculo de registros DS. RSA/SHA-256 es verificable pero no se puede generar (`ring` no genera llaves RSA), y la denegación autenticada (NSEC/NSEC3) no se produce
- **Validación DNSSEC**: las respuestas resueltas iterativamente se validan contra las anclas de confianza de la raíz de IANA, activo por omisión (`dnssec.validate`). La cadena se construye de arriba abajo junto al recorrido de delegaciones, así que un DS no cuesta ninguna consulta extra; una delegación sin firmar debe *demostrar* que lo está (NSEC/NSEC3 firmado), de modo que arrancar firmas no es una degradación. Los datos bogus son SERVFAIL y no se cachean nunca, y AD se pone solo para respuestas genuinamente Secure
- **DANE TLSA + emisor ACME**: generación de registros TLSA a partir de certificados, una autoridad de certificación ACME integrada (CA intermedias por zona), generación de CA raíz autofirmada, manejo del desafío DNS-01 de ACME (sirve registros TXT `_acme-challenge` de forma nativa)
- **Distribución de la CA por DNS**: la cadena de CA raíz e intermedia por zona se publica como registros `CERT` (RFC 4398) con una reserva `TXT` troceada, así cualquier cliente que pueda resolver la zona puede obtener y confiar en la CA — sin necesidad de acceso al portal (véase [Distribuir y confiar en la CA](#distribuir-y-confiar-en-la-ca))
- **22 tipos de registro**: A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR, URI, SSHFP, DNAME, ANAME, ZONEMD, TLSA, CERT, DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM. Los 22 se pueden almacenar y listar; NSEC, NSEC3 y NSEC3PARAM no se generan ni se sirven nunca (véase [DNSSEC](#dnssec))
- **Comodines DNS**: coincidencia de comodines conforme al RFC 4592 (`*.example.com.` casa sustituciones de una sola etiqueta; la coincidencia exacta tiene prioridad)
- **DNS autoritativo**: imposición del bit AA para las zonas locales y para las zonas declaradas autoritativas explícitamente
- **EDNS (RFC 6891)**: soporte del registro OPT, negociación del tamaño de payload, bit DO para DNSSEC, BADVERS para versión > 0
- **DNS64 (RFC 6147)**: síntesis AAAA a partir de registros A con prefijo configurable (por omisión `64:ff9b::/96`)
- **Deriva de TTL**: modo fijo (sumar/restar una duración, admite formatos compuestos como `"1h30m"`) y modo logarítmico experimental (basado en la latencia)
- **Aleatorización de mayúsculas del QNAME**: la codificación 0x20 aleatoriza las mayúsculas del QNAME en las consultas reenviadas como defensa contra el envenenamiento de caché
- **Administración por gRPC**: administración remota de registros por gRPC con autenticación por secreto compartido o por socket Unix
- **Listas de bloqueo**: revisión de proveedores DNSBL con cacheado en memoria, más una base de datos local de bloqueo para entradas propias
- **Soporte de DNSBL**: listas de bloqueo de dominios (Spamhaus DBL, SURBL, URIBL) revisadas antes de cualquier resolución externa, así que un nombre listado se rechaza incluso si antes se había cacheado una respuesta reenviada
- **Manejo de rechazos de lista de bloqueo**: una DNSxL responde «listado» y «deja de consultarnos» con la misma clase de registro `A`, así que los códigos de rechazo (`127.255.255.254`, `127.0.0.1`, …) se reconocen como *no* siendo un listado y el proveedor se saca de la rotación de consultas durante un enfriamiento — en vez de dar NXDOMAIN a todos los nombres revisados contra él
- **Lista de permitidos de la lista de bloqueo**: una única salida de emergencia que cubre todas las listas y ambas compuertas — una entrada exime a un nombre y a sus subdominios de la revisión DNSBL/local, y a una dirección (por nombre inverso o literal IP) de la revisión de búsqueda inversa
- **Control de acceso a la recursión**: `security.recursion_cidrs` decide quién puede dirigir la resolución *upstream*, y por omisión trae los rangos no enrutables desde internet, así que una ligadura por omisión a `0.0.0.0:53` no es un resolvedor recursivo abierto. Los desconocidos siguen recibiendo las respuestas autoritativas de este servidor
- **Ámbitos de red**: vistas DNS de horizonte partido con registros por ámbito y control de acceso basado en IP. La imposición de ámbito se confina a los CIDR de superposición (WireGuard) configurados; loopback, LAN y los orígenes de contenedores son de confianza y no se rechazan nunca
- **TLD propios por red**: TLD globalmente únicos que posee un ámbito, separados entre pares de superposición y nunca reenviados upstream, con **escuchas DNS de ingreso** opcionales por TLD que responden en la dirección propia de una red y reescriben los nombres programados hacia su controlador de ingreso
- **Servidor DHCPv4 integrado**: conjuntos de direcciones por ámbito con vinculaciones MAC pegajosas, registro automático de A/PTR, entrega de certificados mediante opciones específicas del lugar, y un barrido de concesiones en segundo plano
- **Registros PTR inversos automáticos**: mantenimiento opcional (`dns.auto_ptr`) de los PTR `in-addr.arpa`/`ip6.arpa` correspondientes a los registros A/AAAA agregados por gRPC
- **Soporte de proxy**: reenvía las consultas DNS a través de un proxy HTTP CONNECT, SOCKS5 o DoH
- **Métricas de Prometheus**: un endpoint `/metrics` opcional y apagado por omisión que expone 82 familias de métricas con cardinalidad de etiquetas acotada — incluidas la atribución de respuestas por etapa y el aislamiento por TLD, de modo que la tubería de horizonte partido es legible desde fuera. Los nombres de consulta nunca son etiquetas
- **Persistencia en SQLite**: los registros DNS persisten entre reinicios
- **Recarga en caliente de TLS**: los archivos de certificado se sondean cada 30 segundos y un par renovado lo sirven DoT, DoH, DoQ, ACME y el portal de inscripción dentro de esa ventana, sin reinicio y sin conexiones caídas. Una reconstrucción que falla —un archivo truncado, o un sondeo que cayó entre las dos escrituras de un cliente ACME— mantiene sirviendo el certificado anterior y reintenta en el siguiente sondeo
- **Rendimiento**: runtime tokio multihilo, estado de listas de bloqueo y del resolvedor sin cerrojos (`AtomicBool` + `ArcSwap` + atómicos), cachés de arranque en memoria para ámbitos/zonas/TLD/entradas de bloqueo, pool de sockets UDP para el reenvío upstream, y cacheado concurrente con DashMap/DashSet por todas partes

## Compilación

```
make build
```

## Pruebas

```
make test
```

Ejecuta el lint (la revisión de deriva de las traducciones, `cargo fmt --check` + `clippy --all-targets -D warnings`), las pruebas de integración y unitarias de Go, las pruebas de integración y unitarias de Rust, las pruebas de lint/integración/unitarias de JavaScript, y la revisión de ejecución del PromQL documentado. La capa de integración de Rust incluye baterías con sockets reales para la firma y la validación DNSSEC (contra una jerarquía simulada firmada cuyas respuestas se manipulan en el momento de serializar, así que cada prueba es «un despliegue válido, atacado»), el contrato NXDOMAIN de las listas de bloqueo, los códigos de rechazo de las listas de bloqueo, DoQ, el proxying, la recarga de TLS, ZONEMD, la administración de ACME, y una batería `security_*` por hallazgo de seguridad. Usa `make test-log` para la misma ejecución duplicada a un archivo de registro con marca de tiempo bajo `/tmp/rolodex-dns/log` (sustituible con `LOG_DIR`), impresa al final incluso si falla. Capas individuales: `make lint`, `make rust-test`, `make rust-integration-test`, `make go-test`, `make go-integration-test`, `make js-test`, `make js-integration-test`.

`make test` ejecuta además `make prometheus-test`, que pasa todas las consultas PromQL documentadas en este archivo por un contenedor de Prometheus real que raspa un servidor vivo — cachando una consulta mal formada *como PromQL* y no meramente una que nombre una serie inexistente. Necesita podman; sin él la revisión **salta ruidosamente** en vez de fallar, así que una máquina sin runtime de contenedores sigue obteniendo una ejecución en verde sin fingir jamás que las consultas se verificaron. Pon `ROLODEX_PROMETHEUS_REQUIRED=1` para convertir ese salto en un fallo duro, y `ROLODEX_PROMETHEUS_IMAGE` para apuntar a un espejo de la imagen.

## Desarrollo

Arranca un servidor de desarrollo local para pruebas y desarrollo:

```
make dev
```

Esto:
1. Compila el proyecto en modo depuración (`cargo build`)
2. Arranca el servidor usando `dev.yml` con los siguientes ajustes:
   - Escuchas DNS en `127.0.0.1:5300` y en la IP saliente principal en el puerto `5300` (UDP y TCP)
   - Socket Unix de gRPC en `/tmp/rolodex-dns.sock` (sin escucha TCP de gRPC)
   - Base de datos SQLite en `/tmp/rolodex-dns-dev.db`
   - Sin autenticación
   - Revisión de listas de bloqueo desactivada
   - Reenviadores upstream por omisión (`8.8.8.8:53`, `8.8.4.4:53`), usados como el nivel `local` de la cadena de resolución `auto` por omisión

`make help` enumera todos los objetivos con una descripción, agrupados por sección (es además el objetivo por omisión, así que un `make` pelado lo imprime).

Para un servidor de desarrollo optimizado como release:
```
make dev-release
```

Para instalar los binarios en tu directorio bin de Cargo:
```
make install
```

Una vez el servidor de desarrollo está en marcha, lo puedes administrar con el binario `rolodex-dns-cli` o con la biblioteca cliente de Go conectada a `/tmp/rolodex-dns.sock`. Pulsa Ctrl+C para detener el servidor.

## Imágenes de contenedor

Rolodex DNS compila de forma cruzada sus binarios en el equipo de compilación con `cargo-zigbuild`, y luego ensambla una imagen de ejecución ligera (`debian:bookworm-slim`) que contiene solo los binarios despojados y un bundle de CA. El `Containerfile` deliberadamente **no contiene pasos `RUN`**, que es lo que permite a cualquier equipo construir una imagen para cualquier arquitectura sin emulación y sin VM constructora.

Las imágenes se publican en `quay.io/town/rolodex` como listas de manifiestos multiarquitectura que cubren `linux/amd64` y `linux/arm64`.

### Compilaciones multiarquitectura

Las compilaciones son **nativas**: cada arquitectura se compila en un equipo de esa arquitectura. Toda imagen se etiqueta con un sufijo de arquitectura usando el nombre de host de `uname -m` (`-x86_64` o `-aarch64`, *no* los nombres OCI `amd64`/`arm64`), así que un equipo de despliegue puede bajar `` <etiqueta>-`uname -m` `` sin ningún mapeo. Un paso de manifiesto aparte ensambla las imágenes por arquitectura en una única etiqueta multiarquitectura.

#### Elegir la arquitectura: `TARGET`

`TARGET` selecciona la arquitectura para todos los objetivos de contenedor (`image`, `push-arch`, `push-rc`, `push-release`). Por omisión es la arquitectura del equipo, y coincide con el modelo `TARGET=` que usa el repo `install` de town-os, de modo que el mismo valor se puede pasar a cualquiera de los dos:

| `TARGET` | Compila |
| -------- | ------- |
| *(sin poner)* | la arquitectura del equipo |
| `x86_64`, `x86`, `amd64` | imagen amd64, etiquetada `-x86_64` |
| `aarch64`, `arm64` | imagen arm64, etiquetada `-aarch64` |
| `rpi` | imagen arm64, etiquetada `-aarch64` |
| `rg35xxpro`, `rg35xx-pro`, `rg35xx`, `anbernic` | imagen arm64, etiquetada `-aarch64` |

Cualquier otro valor es un error que enumera los aceptados. Los sabores de placa no cambian la imagen —rolodex-dns distribuye una imagen de contenedor por arquitectura, no por placa— se aceptan para que un `TARGET=rg35xxpro` que significa algo concreto en `install` siga resolviendo con sentido aquí.

**Cualquier equipo construye cualquier arquitectura.** Un `TARGET` ajeno se compila de forma cruzada en vez de emularse, así que no hay combinaciones rechazadas ni VM constructora — véase Compilación cruzada más abajo.

Los pasos RUN de `podman build` comparten la red del equipo (`--network=host`) para poder usar un resolvedor DNS en el loopback del equipo (por ejemplo rolodex mismo); sustitúyelo con `BUILD_NETWORK=` para desactivarlo.

El flujo de extremo a extremo para publicar una imagen multiarquitectura — un equipo por arquitectura:

1. En un equipo amd64: `make push-release` → sube `…:latest-x86_64` (y la etiqueta de fecha).
2. En un equipo arm64: `make push-release` → sube `…:latest-aarch64` (y la etiqueta de fecha).
3. En cualquiera de los dos (una vez subidos ambos): `make manifest-release` → crea y sube la lista de manifiestos multiarquitectura `…:latest`.

Un consumidor que baje `quay.io/town/rolodex:latest` recibe entonces de forma transparente la imagen que corresponde a su arquitectura.

#### Compilación cruzada

Ambas arquitecturas se compilan de forma cruzada en el equipo que ejecute `make`, usando `cargo-zigbuild` con zig como compilador cruzado de C y enlazador. `make deps` aprovisiona la cadena de herramientas entera **sin root**, y revisa `python3` (que `make translation-check` necesita y que no puede instalar sin root):

```bash
make deps        # objetivos de rustup + cargo-zigbuild + zig, las dependencias de desarrollo de JS y una revisión de python3
make cross-deps  # solo la cadena cruzada de Rust
```

Un `rustup target add` a secas no bastaría: `rusqlite` compila las fuentes C empaquetadas de SQLite y `ring` compila C y ensamblador, así que tiene que haber una cadena cruzada de **C** de verdad o la compilación falla en el paso `cc`. zig aporta una sin paquetes específicos de la distribución, y liga contra una glibc fijada (`GLIBC_VERSION`, por omisión `2.36` para coincidir con `debian:bookworm`), de modo que el binario corre sobre la imagen de ejecución sea cual sea la que lleve el equipo de compilación.

Versiones fijadas, todas sustituibles: `ZIG_VERSION`, `ZIGBUILD_VERSION`, `GLIBC_VERSION`.

```bash
make image TARGET=x86_64         # compilación cruzada + ensamblar una imagen amd64
make push-release TARGET=aarch64 # compilación cruzada + subir una imagen arm64
make push-release-all            # ambas arquitecturas + el manifiesto, desde un solo equipo
```

`make image-amd64`, `push-rc-amd64` y `push-release-amd64` siguen existiendo como alias de las formas `TARGET=x86_64`.

### Construir imágenes

Construye la imagen de release para la arquitectura del **equipo** (etiquetada como `quay.io/town/rolodex:latest-<arch>`):

```
make image
```

Construye para una arquitectura concreta:

```
make image TARGET=x86_64
make image TARGET=aarch64
```

Construye con una etiqueta concreta:

```
make IMAGE_TAG=v1.2.3 image
```

Los cachés del registro de Cargo y de git se persisten en `.cache/` para acelerar las recompilaciones.

### Subir

Inicia sesión en Quay.io (lee `QUAY_USERNAME` y `QUAY_PASSWORD` del entorno o de `.env`):

```
make quay-login
```

Construye y sube la imagen candidata a release para `TARGET` (autoetiqueta `rc.YYYYMMDD-<arch>` y `rc.latest-<arch>`, por ejemplo `rc.latest-x86_64` / `rc.latest-aarch64`):

```
make push-rc
make push-rc TARGET=x86_64    # arquitectura explícita
```

Construye y sube la imagen de release para `TARGET` (autoetiqueta `release.YYYYMMDD-<arch>` y `latest-<arch>`):

```
make push-release
make push-release TARGET=aarch64
```

#### Ensamblar el manifiesto multiarquitectura

Después de que se hayan subido las imágenes por arquitectura de **todas** las arquitecturas (ejecuta `push-rc`/`push-release` en cada equipo nativo), ensambla y sube la lista de manifiestos multiarquitectura desde cualquier equipo:

```
make manifest-rc       # combina rc.latest-x86_64 + rc.latest-aarch64 → rc.latest (y la etiqueta de fecha rc.YYYYMMDD)
make manifest-release  # combina latest-x86_64 + latest-aarch64 → latest (y la etiqueta de fecha release.YYYYMMDD)
```

El manifiesto se ensambla a partir de las imágenes que ya están en el registro (`podman manifest add docker://…`), así que no requiere que las imágenes por arquitectura estén presentes localmente.

#### Subir una etiqueta concreta

Usa `IMAGE_TAG` para construir y subir una etiqueta exacta en vez de las etiquetas autogeneradas basadas en la fecha. El sufijo de arquitectura se sigue aplicando a las imágenes por arquitectura:

```
make IMAGE_TAG=v1.2.3 push-release    # sube quay.io/town/rolodex:v1.2.3-<arch>
make IMAGE_TAG=v1.2.3 manifest-release # combina v1.2.3-x86_64 + v1.2.3-aarch64 → v1.2.3
```

Lo mismo funciona con `push-rc` / `manifest-rc`:

```
make IMAGE_TAG=v1.2.3-rc1 push-rc
make IMAGE_TAG=v1.2.3-rc1 manifest-rc
```

Para subir una imagen ya construida bajo otra etiqueta sin reconstruirla:

```
sudo podman tag quay.io/town/rolodex:latest quay.io/town/rolodex:v1.2.3
sudo podman push quay.io/town/rolodex:v1.2.3
```

Para subir a un registro completamente distinto:

```
sudo podman tag quay.io/town/rolodex:latest registry.example.com/myorg/rolodex:v1.2.3
sudo podman push registry.example.com/myorg/rolodex:v1.2.3
```

### Limpieza

Elimina las imágenes de contenedor locales:

```
make clean-containers
```

## Configuración

Rolodex DNS lee la configuración de un archivo YAML (por omisión: `rolodex-dns.yml`, sustituible con `-c`/`--config`). Toda sección es opcional — si falta el archivo, el servidor arranca con los valores por omisión.

Para un recorrido que construye una configuración subsistema a subsistema, con un ejemplo resuelto por forma de despliegue, consulta la **[Guía de configuración](CONFIGURATION.es-ES.md)**. La referencia de abajo es la lista completa de campos.

### Sintaxis de las direcciones de ligadura

Las cadenas de dirección de ligadura (usadas por `dns.bind`, `dot.bind`, `doh.bind`, `doq.bind`, `grpc.tcp_bind`, `dhcp.bind`) aceptan cuatro formas:

| Forma | Ejemplo | Descripción |
| ----- | ------- | ----------- |
| `ip:puerto` | `192.168.1.1:53` | Ligar a una dirección IPv4 y puerto concretos |
| `[ipv6]:puerto` | `[::1]:53` | Ligar a una dirección IPv6 y puerto concretos (los corchetes son obligatorios) |
| `primary:puerto` | `primary:53` | Detectar la IP saliente de la ruta por omisión del SO y ligar a ella |
| `interfaz:puerto` | `eth0:53` | Ligar a todas las IP de la interfaz de red nombrada |

La palabra clave `primary` detecta qué dirección IP usaría el SO para alcanzar la internet pública (mediante un connect UDP que no envía datos a `8.8.8.8:53`) y liga un único escucha en esa dirección. La palabra clave es insensible a mayúsculas.

La ligadura por interfaz resuelve todas las direcciones IPv4 e IPv6 asignadas a la interfaz y crea un escucha aparte para cada una. Por ejemplo, si `eth0` tiene `192.168.1.5` y `fe80::1`, entonces `eth0:53` crea escuchas tanto en `192.168.1.5:53` como en `[fe80::1]:53`.

`dot.bind` y `doq.bind` aceptan **o una sola cadena de enlace, o una lista de ellas**:

```yaml
dot:
  bind:
    - "0.0.0.0:853"
    - "[2001:db8::1]:853"
```

Una lista es como una sola escucha cubre ambas familias de direcciones. `0.0.0.0` es
solo IPv4, y `[::]` no es un sustituto portable de las dos: con `net.ipv6.bindv6only=0`
(el valor por omisión de Linux) un socket `[::]` acepta también tráfico v4 mapeado, así
que choca con un socket `0.0.0.0` en el mismo puerto y el segundo en ligar falla con
`EADDRINUSE`. Nombra en su lugar las direcciones v6. Cada entrada pasa por las cuatro
formas de arriba de manera independiente, los duplicados se descartan en vez de
enlazarse dos veces, y una cadena suelta se sigue aceptando — toda configuración escrita
antes de que existiera la forma de lista sigue analizándose.

El campo `dns.bind` es una lista de pares protocolo/dirección. Cada entrada es un mapa de una sola llave con `udp` o `tcp` como llave y una dirección de ligadura como valor:

```yaml
dns:
  bind:
    - udp: "eth0:53"
    - udp: "lo:53"
    - tcp: "eth0:53"
```

### Ejemplo de configuración

```yaml
# Ruta del archivo de base de datos
database_path: rolodex-dns.db

# Reenviadores DNS upstream (formato dirección:puerto). Se usan como el nivel
# "local" de la cadena auto, o como único upstream cuando resolution.mode es "forward".
# Ponlo a lista vacía (con resolution.mode: forward) para un servidor puramente autoritativo
forwarders:
  - "8.8.8.8:53"
  - "8.8.4.4:53"

# Estrategia de resolución upstream (todos los campos opcionales; se muestran los valores por omisión)
resolution:
  mode: auto              # "auto" (cadena de niveles), "recursive" (solo raíces), "forward"
  root_hints: []          # sustituye las direcciones raíz de IANA integradas
  secure_upstreams:       # nivel cifrado, probado cuando la recursión desde las raíces falla
    - transport: https    # "https" (DoH :443, preferido) o "tls" (DoT :853)
      addr: "1.1.1.1:443" # se marca por IP, así que no necesita DNS previo
      hostname: cloudflare-dns.com  # SNI / nombre de certificado validado
      path: /dns-query
    - transport: https
      addr: "8.8.8.8:443"
      hostname: dns.google
      path: /dns-query
  public_fallback:        # Do53 en claro, probado el último
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  switch_grace_failures: 3      # consultas desviadas antes de confirmar una degradación de nivel
  recovery_probe_secs: 60       # cada cuánto una cadena degradada reintenta desde arriba
  delegation_persist_min_ttl: 300  # persistir delegaciones con un TTL superior a este
  default_ttl: 300              # reserva solo donde nada aporta un TTL

# Validación DNSSEC de las respuestas resueltas desde las raíces (solo ruta iterativa)
dnssec:
  validate: true          # los datos bogus se convierten en SERVFAIL y no se cachean nunca
  trust_anchors: []       # vacío = las llaves raíz de IANA; una sustitución las REEMPLAZA

# Cada entrada empareja un protocolo (udp/tcp) con una dirección de ligadura.
# Las direcciones aceptan ip:puerto, [ipv6]:puerto, primary:puerto o interfaz:puerto.
dns:
  bind:
    - udp: "0.0.0.0:53"     # o "eth0:53" para ligar a una interfaz concreta
    - tcp: "0.0.0.0:53"
  auto_ptr: false           # mantener PTR inversos para los A/AAAA agregados por gRPC
  ingress_listen_port: 53   # puerto de los escuchas de ingreso por TLD (la IP es por TLD)

# DNS-over-TLS (RFC 7858)
dot:
  bind: "0.0.0.0:853"
  tls:
    cert_path: /etc/rolodex-dns/cert.pem
    key_path: /etc/rolodex-dns/key.pem
    auto_self_signed: false
    # Solo se usa cuando se genera un certificado. Los nombres de loopback y las
    # direcciones de ligadura del propio escucha se cubren automáticamente; lista aquí
    # los demás nombres por los que los clientes llaman a esta máquina.
    self_signed_sans: []

# DNS-over-HTTPS (RFC 8484)
doh:
  bind: "0.0.0.0:443"
  tls:
    cert_path: /etc/rolodex-dns/cert.pem
    key_path: /etc/rolodex-dns/key.pem
    auto_self_signed: false
  enable_h3: false

# DNS-over-QUIC (RFC 9250)
doq:
  bind: "0.0.0.0:8853"
  tls:
    cert_path: /etc/rolodex-dns/cert.pem
    key_path: /etc/rolodex-dns/key.pem
    auto_self_signed: false

grpc:
  # Escucha TCP de gRPC (cadena vacía para desactivar)
  tcp_bind: "127.0.0.1:50051"
  # Ruta del socket Unix (cadena vacía para desactivar)
  unix_socket: /var/run/rolodex-dns.sock
  # Secreto compartido para la autenticación gRPC por TCP (no hace falta para el socket Unix)
  shared_secret: your-secret-here

# Listas de bloqueo de dominios (revisadas por nombre, antes de cualquier resolución externa)
dnsbl:
  # Activa/desactiva globalmente la revisión de listas de bloqueo (por omisión: false)
  enabled: false
  # Segundos que un proveedor que rechaza nuestras consultas permanece fuera de rotación
  refusal_cooldown_secs: 3600
  providers:
    - zone: dbl.spamhaus.org
      enabled: true
      # Códigos que significan "consulta rechazada", no "listado". Omítelo para el
      # conjunto integrado; "none" a secas desactiva la detección en este proveedor.
      refusal_codes: []
      # Sustitución por proveedor de la duración fuera de rotación (omítelo para heredarla)
      refusal_cooldown_secs: 3600
    - zone: multi.surbl.org
      enabled: true

# Servidor DHCPv4 integrado (omite la sección para desactivarlo)
dhcp:
  bind: "0.0.0.0:67"
  tld: example.com          # obligatorio: los nombres se registran como <host>.lan.<tld>.
  default_lease_duration: 3600
  reclaim_timeout: 86400
  sweep_interval: 60

# Emisor ACME / autoridad de certificación (omite la sección para desactivarlo)
acme:
  bind: "0.0.0.0:8555"                    # escucha HTTPS de ACME de cara al cliente
  portal_bind: "127.0.0.1:8500"           # portal de inscripción de red de confianza
  directory_url: "https://dns.example.com:8555/acme"  # anunciada a los clientes
  root_ca_cn: "Rolodex Root CA"
  leaf_validity_days: 90
  tlsa_port: 443
  tlsa_proto: tcp
  require_eab: true
  issuance_scope: managed_zones           # o "any"

# Proxy HTTP para las consultas DNS reenviadas
proxy:
  url: "http://proxy:8080"
  auth: "user:pass"
  mode: "connect"  # "connect" (túnel HTTP CONNECT), "socks5" (proxy SOCKS5) o "doh" (consultas DoH por proxy)

# Ajuste por deriva de TTL
ttl_drift:
  mode: "fixed"          # "fixed" o "logarithmic" (experimental)
  fixed_adjustment: "5m" # p. ej. "5m", "-30s", "1h30m", "2d12h" (solo en modo fixed)
  log_multiplier: 1.0    # multiplicador (solo en modo logarithmic, experimental)

# Síntesis AAAA de DNS64
dns64:
  enabled: false
  prefix: "64:ff9b::"    # prefijo bien conocido por omisión (64:ff9b::/96)

# Preferencia de familia de direcciones en las respuestas
address_family:
  mode: auto              # "auto" (sondear y suprimir), "off", "force4", "force6"
  probe_interval_secs: 30
  fail_threshold: 2       # ciclos fallidos antes de marcar una familia como caída
  probe_timeout_secs: 2
  targets_v4: ["1.1.1.1:443", "8.8.8.8:443"]
  targets_v6: ["[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"]

# Ajustes de seguridad
security:
  qname_case_randomization: true  # codificación 0x20 para las consultas reenviadas
  overlay_cidrs: ["10.64.0.0/10"] # rangos de origen sujetos a la imposición de ámbito de red
  # Quién puede dirigir la resolución UPSTREAM. Los orígenes fuera de esta lista
  # reciben igual las respuestas de las que este servidor es autoritativo, pero son
  # REFUSED para lo que salga de la máquina. Lista vacía = autoritativo para todos.
  recursion_cidrs:
    - "127.0.0.0/8"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "169.254.0.0/16"
    - "100.64.0.0/10"
    - "::1/128"
    - "fe80::/10"
    - "fc00::/7"

# Endpoint de raspado de Prometheus (omite la sección para no arrancar escucha alguna)
metrics:
  bind: "127.0.0.1:9153"
  # TLD a los que se da su propia etiqueta `tld` en las métricas de consultas por TLD.
  # Los TLD propios se rastrean automáticamente; todo lo no rastreado se pliega en `other`.
  tracked_tlds:
    - common
```

### Opciones de configuración

| Opción | Por omisión | Descripción |
|--------|---------|-------------|
| `database_path` | `"rolodex-dns.db"` | Ruta al archivo de base de datos SQLite |
| `forwarders` | `["8.8.8.8:53", "8.8.4.4:53"]` | Direcciones de los resolvedores DNS upstream (el nivel `local` en modo `auto`; el único upstream en modo `forward`) |
| `resolution.mode` | `"auto"` | Estrategia upstream: `"auto"` (cadena de niveles), `"recursive"` (solo raíces), `"forward"` (solo reenviadores). **Solo semilla de arranque** — `SetResolutionMode` cambia el modo en un servidor en marcha sin reiniciarlo, y `GetResolutionMode` informa de lo que está de verdad en vigor |
| `resolution.root_hints` | `[]` (raíces de IANA integradas) | Sustituye las pistas de servidores raíz usadas en modo `recursive`/`auto` |
| `resolution.secure_upstreams` | Cloudflare + Google por DoH | Upstreams cifrados para el nivel `secure`: `{transport, addr, hostname, path}` |
| `resolution.public_fallback` | `["1.1.1.1:53", "8.8.8.8:53"]` | Resolvedores públicos en claro, probados los últimos en modo `auto` |
| `resolution.switch_grace_failures` | `3` | Consultas divergentes consecutivas antes de que se confirme una degradación de nivel en `auto` |
| `resolution.recovery_probe_secs` | `60` | Cada cuánto una cadena `auto` degradada reintenta desde el nivel superior |
| `resolution.delegation_persist_min_ttl` | `300` | TTL mínimo para que una delegación aprendida se persista en SQLite |
| `resolution.default_ttl` | `300` | TTL de reserva cuando un registro o respuesta no trae el suyo |
| `dnssec.validate` | `true` | Valida DNSSEC en las respuestas resueltas iterativamente (modo `recursive` y el nivel de las raíces de `auto`). Los datos bogus e indeterminados pasan a ser SERVFAIL y no se cachean nunca |
| `dnssec.trust_anchors` | `[]` (llaves raíz de IANA) | Anclas en forma de presentación DNSKEY, `"<flags> <protocolo> <algoritmo> <clave en base64>"` — los campos RDATA tal como los imprime `dig DNSKEY .`. Cada campo se valida al arrancar y uno incorrecto es un fallo duro. Una sustitución **reemplaza** las llaves de IANA en vez de agregarse a ellas |
| `dns.bind` | `[{udp: "0.0.0.0:53"}, {tcp: "0.0.0.0:53"}]` | Escuchas DNS; lista de entradas `{udp: dirección}` / `{tcp: dirección}` |
| `dns.auto_ptr` | `false` | Mantiene registros PTR inversos para los A/AAAA agregados por gRPC |
| `dns.ingress_listen_port` | `53` | Puerto UDP/TCP para las escuchas de ingreso por TLD (la IP de ligadura es por TLD) |
| `dns.udp_shards` | `0` (uno por núcleo) | Sockets `SO_REUSEPORT` ligados por cada dirección UDP de escucha. Un socket único serializa la escucha —un bucle de recepción, un socket para cada respuesta— y limita el rendimiento muy por debajo de la saturación de CPU. El fragmentado deja que el núcleo reparta los datagramas entre CPU. Pon `1` para el comportamiento antiguo de socket único |
| `dot.bind` | `""` (desactivado) | Escucha DoT; admite interfaz:puerto (típicamente el puerto 853). Acepta **una sola dirección o una lista** — una lista es como una escucha cubre ambas familias de direcciones |
| `dot.tls.cert_path` | `""` | Ruta al certificado TLS para DoT |
| `dot.tls.key_path` | `""` | Ruta a la llave privada TLS para DoT |
| `dot.tls.auto_self_signed` | `true` | Genera automáticamente un certificado autofirmado para DoT |
| `dot.tls.self_signed_sans` | `[]` | Nombres alternativos del sujeto adicionales para un certificado DoT generado. El conjunto de loopback y las direcciones de ligadura de la escucha se agregan automáticamente; una ligadura comodín (`0.0.0.0`) no aporta nada, así que nombra aquí la máquina |
| `doh.bind` | `""` (desactivado) | Escucha DoH; admite interfaz:puerto (típicamente el puerto 443) |
| `doh.tls.cert_path` | `""` | Ruta al certificado TLS para DoH |
| `doh.tls.key_path` | `""` | Ruta a la llave privada TLS para DoH |
| `doh.tls.auto_self_signed` | `true` | Genera automáticamente un certificado autofirmado para DoH |
| `doh.tls.self_signed_sans` | `[]` | Como `dot.tls.self_signed_sans`, para DoH |
| `doh.enable_h3` | `false` | Activa el transporte HTTP/3 (QUIC) para DoH |
| `doq.bind` | `""` (desactivado) | Escucha DoQ; admite interfaz:puerto (típicamente el puerto 8853). Acepta **una sola dirección o una lista**, igual que `dot.bind` |
| `doq.tls.cert_path` | `""` | Ruta al certificado TLS para DoQ |
| `doq.tls.key_path` | `""` | Ruta a la llave privada TLS para DoQ |
| `doq.tls.auto_self_signed` | `true` | Genera automáticamente un certificado autofirmado para DoQ |
| `doq.tls.self_signed_sans` | `[]` | Como `dot.tls.self_signed_sans`, para DoQ |
| `grpc.tcp_bind` | `"127.0.0.1:50051"` | Escucha gRPC por TCP; admite interfaz:puerto (vacío para desactivar) |
| `grpc.unix_socket` | `"/var/run/rolodex-dns.sock"` | Ruta del socket Unix (vacío para desactivar) |
| `grpc.shared_secret` | `""` | Secreto compartido para la autenticación gRPC por TCP (vacío = sin autenticación) |
| `dnsbl.enabled` | `false` | Activa globalmente la revisión de listas de bloqueo de dominios (DNSBL) |
| `dnsbl.providers[].zone` | -- | Zona DNSBL a consultar (el nombre consultado se antepone) |
| `dnsbl.providers[].enabled` | `true` | Activa/desactiva un proveedor DNSBL concreto |
| `dnsbl.providers[].refusal_codes` | `[]` (conjunto integrado) | Respuestas que significan «consulta rechazada» en vez de «listado». Cada entrada es una dirección IPv4 o `dirección/prefijo`. Vacío significa el conjunto integrado; la entrada única `none` desactiva la detección para ese proveedor. Una lista explícita reemplaza los valores por omisión en vez de ampliarlos, y un código no interpretable se rechaza al arrancar (véase [Códigos de rechazo](#códigos-de-rechazo-y-rotación-de-proveedores)) |
| `dnsbl.providers[].refusal_cooldown_secs` | (por omisión de la lista) | Duración de la salida de rotación por proveedor después de un rechazo |
| `dnsbl.refusal_cooldown_secs` | `3600` | Segundos que un proveedor que rechaza permanece fuera de rotación, para los proveedores que no fijan ninguno. `0` significa «usa el valor por omisión», no «sin enfriamiento» |
| `dhcp.bind` | `"0.0.0.0:67"` | Escucha DHCP (sección ausente = DHCP desactivado) |
| `dhcp.tld` | -- | Obligatorio cuando DHCP está activo: los nombres de host se registran como `<host>.lan.<tld>.` |
| `dhcp.default_lease_duration` | `3600` | Duración de concesión por omisión en segundos |
| `dhcp.reclaim_timeout` | `86400` | Segundos después de la expiración antes de reclamar una IP |
| `dhcp.sweep_interval` | `60` | Intervalo del barrido de concesiones en segundo plano, en segundos |
| `acme.bind` | `"0.0.0.0:8555"` | Escucha ACME HTTPS de cara al cliente (sección ausente = ACME desactivado) |
| `acme.portal_bind` | `"127.0.0.1:8500"` | Escucha del portal de inscripción para la red de confianza |
| `acme.directory_url` | `"https://localhost:8555/acme"` | URL externa del directorio ACME anunciada a los clientes (configúrala) |
| `acme.root_ca_cn` | `"Rolodex Root CA"` | Nombre común de la CA raíz creada al arrancar |
| `acme.leaf_validity_days` | `90` | Validez de los certificados de hoja emitidos |
| `acme.tlsa_port` / `acme.tlsa_proto` | `443` / `"tcp"` | Dónde se publica el registro TLSA DANE-TA para cada nombre |
| `acme.tlsa_endpoints` | `[]` | Endpoints `"<puerto>/<protocolo>"` adicionales en los que publicar el registro TLSA DANE-TA, más allá de `tlsa_port`/`tlsa_proto`. Un registro TLSA nombra un endpoint de servicio, así que un certificado que sirve DoT (`853/tcp`) y DoQ (`853/udp`) necesita un registro para cada uno; una entrada malformada se rechaza al arrancar en vez de saltarse |
| `acme.require_eab` | `true` | Exige External Account Binding para registrar una cuenta |
| `acme.issuance_scope` | `"managed_zones"` | `"managed_zones"` (la zona debe tener una CA) o `"any"` |
| `proxy.url` | `""` (desactivado) | URL del proxy HTTP para las consultas DNS reenviadas |
| `proxy.auth` | `""` | Autenticación del proxy (`"usuario:contraseña"`) |
| `proxy.mode` | `"connect"` | Modo del proxy: `"connect"` (HTTP CONNECT), `"socks5"` (SOCKS5) o `"doh"` |
| `ttl_drift.mode` | `"disabled"` | Modo de deriva de TTL: `"disabled"`, `"fixed"` o `"logarithmic"` |
| `ttl_drift.fixed_adjustment` | `""` | Ajuste fijo del TTL. Admite duraciones simples (`"5m"`, `"-30s"`, `"1h"`, `"2d"`) y compuestas (`"1h30m"`, `"2d12h"`) |
| `ttl_drift.log_multiplier` | `0.1` | Multiplicador del modo logarítmico (ajusta el TTL según la latencia upstream) |
| `dns64.enabled` | `false` | Activa la síntesis AAAA de DNS64 |
| `dns64.prefix` | `"64:ff9b::"` | Prefijo IPv6 para la síntesis DNS64 |
| `security.qname_case_randomization` | `true` | Activa la aleatorización 0x20 de las mayúsculas del QNAME |
| `security.overlay_cidrs` | `["10.64.0.0/10"]` | Rangos de origen tratados como pares de superposición no fiables y sometidos a la imposición de ámbito; cualquier otro origen es de confianza |
| `security.recursion_cidrs` | loopback, RFC 1918, enlace-local, ULA, CGNAT | Rangos de origen a los que se permite dirigir la resolución **upstream**. A los demás se les sirven los datos locales/autoritativos y se les da REFUSED para todo lo que saldría de la máquina; una lista vacía cierra la recursión a todo el mundo (véase [Control de acceso a la recursión](#control-de-acceso-a-la-recursión)) |
| `address_family.mode` | `"auto"` | `"auto"` (sondea y suprime una familia no enrutable), `"off"`, `"force4"`, `"force6"` |
| `address_family.probe_interval_secs` | `30` | Segundos entre sondeos de enrutabilidad en modo `auto` |
| `address_family.fail_threshold` | `2` | Ciclos de sondeo fallidos consecutivos antes de marcar una familia como caída (la recuperación es inmediata) |
| `address_family.probe_timeout_secs` | `2` | Tiempo de espera de conexión TCP por destino en cada sondeo |
| `address_family.targets_v4` / `targets_v6` | Cloudflare/Google en `:443` | Destinos de sondeo por familia (IP literales) |
| `metrics.bind` | `127.0.0.1:9153` | Escucha HTTP `/metrics` de Prometheus; admite interfaz:puerto. La sección es opcional y se omite por omisión, en cuyo caso no se arranca escucha alguna (véase [Métricas de Prometheus](#métricas-de-prometheus)) |
| `metrics.tracked_tlds` | `[]` | TLD a los que se da su propio valor de etiqueta `tld` en las métricas de consultas por TLD. Los TLD propios se rastrean automáticamente; `common` se expande al conjunto integrado de TLD comunes; todo lo no rastreado se pliega en `other` |

## Uso

### Servidor

```
rolodex-dns [OPCIONES]

Opciones:
  -c, --config <CONFIG>  Ruta al archivo de configuración [por omisión: rolodex-dns.yml]
  -h, --help             Muestra la ayuda
```

### Cliente CLI

`rolodex-dns-cli` es un cliente de línea de órdenes para administrar un servidor Rolodex DNS en marcha a través de su interfaz de administración gRPC. Admite tanto el transporte TCP como el de socket Unix.

```
rolodex-dns-cli [OPCIONES] <ORDEN>
```

#### Opciones globales

| Opción | Por omisión | Descripción |
|--------|---------|-------------|
| `-a, --address <ADDRESS>` | `127.0.0.1:50051` | Dirección del servidor gRPC para conexiones TCP (host:puerto). Se ignora cuando se pone `--unix-socket`. |
| `-u, --unix-socket <PATH>` | -- | Ruta al socket de dominio Unix. Tiene prioridad sobre `--address`. Las conexiones por socket Unix se saltan la autenticación. |
| `-t, --auth-token <TOKEN>` | `""` | Testigo de autenticación para las conexiones TCP. Obligatorio cuando el servidor tiene configurado un secreto compartido. Se ignora en las conexiones por socket Unix. |
| `-h, --help` | -- | Muestra la ayuda |
| `-V, --version` | -- | Muestra la versión |

#### Órdenes

| Orden | Descripción |
|---------|-------------|
| **Registros** | |
| `add-record` | Agrega un registro DNS a la base de datos local |
| `remove-record` | Elimina uno o más registros DNS de la base de datos local |
| `list-records` | Lista los registros DNS con filtros opcionales |
| **Reenviadores y resolución** | |
| `set-forwarders` | Fija los reenviadores DNS upstream en tiempo de ejecución |
| `set-resolution-mode` | Cambia el modo de resolución upstream (`auto`, `recursive`, `forward`) en tiempo de ejecución |
| `get-resolution-mode` | Muestra el modo de resolución actualmente en vigor |
| **Listas de bloqueo** | |
| `set-dnsbl-config` | Configura los ajustes de listas de bloqueo de dominios (DNSBL) en tiempo de ejecución |
| `get-dnsbl-config` | Obtiene la configuración DNSBL actual |
| `flush-cache` | Vacía el caché de resultados de las listas de bloqueo |
| `add-local-blocklist` | Agrega una entrada a la lista de bloqueo local |
| `remove-local-blocklist` | Elimina una entrada de la lista de bloqueo local |
| `list-local-blocklist` | Lista todas las entradas de la lista de bloqueo local |
| `add-dnsbl-allow` | Exime a un nombre (y a sus subdominios) de la revisión de listas de bloqueo |
| `remove-dnsbl-allow` | Elimina una entrada de la lista de permitidos de DNSBL |
| `list-dnsbl-allow` | Lista todas las entradas de la lista de permitidos de DNSBL |
| **Ámbitos de red** | |
| `create-scope` | Crea un nuevo ámbito de red |
| `delete-scope` | Elimina un ámbito de red y todos sus datos |
| `list-scopes` | Lista todos los ámbitos de red configurados |
| `join-network` | Asocia una IP con un ámbito |
| `leave-network` | Elimina la asociación de ámbito de una IP |
| `list-associations` | Lista las asociaciones IP-ámbito |
| `add-scoped-record` | Agrega un registro DNS dentro de un ámbito |
| `remove-scoped-record` | Elimina registros DNS de un ámbito |
| `list-scoped-records` | Lista los registros DNS dentro de un ámbito |
| `get-search-domains` | Obtiene los dominios de búsqueda de una IP |
| **TLD propios / Ingreso** | |
| `add-scope-tld` | Registra un TLD propio globalmente único para un ámbito (el `--listen-ip` opcional arranca una escucha de ingreso) |
| `remove-scope-tld` | Elimina un TLD propio de un ámbito |
| `list-scope-tlds` | Lista los TLD que posee un ámbito |
| `set-scope-tld-forwarders` | Fija los reenviadores pares para el TLD de un ámbito |
| `list-scope-tld-forwarders` | Lista los reenviadores pares para el TLD de un ámbito |
| `list-scope-tld-listeners` | Lista las escuchas DNS de ingreso ligadas a los TLD de un ámbito |
| **Zonas autoritativas** | |
| `add-auth-zone` | Declara una zona como autoritativa |
| `remove-auth-zone` | Elimina una zona de la lista de autoritativas |
| `list-auth-zones` | Lista todas las zonas autoritativas |
| **Caché** | |
| `cache-stats` | Muestra las estadísticas de aciertos/fallos del caché DNS |
| `flush-dns-cache` | Vacía el caché de respuestas DNS |
| **DHCP** | |
| `add-dhcp-pool` / `remove-dhcp-pool` / `list-dhcp-pools` | Administra los conjuntos de direcciones DHCP por ámbito |
| `list-dhcp-leases` / `delete-dhcp-lease` | Inspecciona y elimina concesiones DHCP |
| `set-dhcp-cert` / `remove-dhcp-cert` / `list-dhcp-certs` | Administra la entrega de certificados mediante opciones DHCP |
| **DNSSEC** | |
| `generate-dnssec-key` | Genera un par de llaves DNSSEC (KSK o ZSK) |
| `list-dnssec-keys` | Lista las llaves DNSSEC de una zona |
| `sign-zone` | Firma una zona con sus llaves DNSSEC |
| **DANE / ACME** | |
| `generate-tlsa` | Genera un registro TLSA a partir de un certificado |
| `request-acme-cert` | Solicita un certificado por ACME DNS-01 |
| `acme-status` | Revisa el estado de un certificado ACME |
| `ensure-zone-ca` | Se asegura de que existe la CA intermedia de la zona; imprime el PEM de la raíz y la intermedia y publica la cadena de CA en el DNS |
| `create-eab` / `remove-eab` | Acuña o elimina una credencial EAB con ámbito de zona |
| `list-acme-accounts` | Lista las cuentas ACME registradas |
| `list-acme-certs` | Lista los certificados emitidos |
| **Deriva de TTL** | |
| `set-ttl-drift` / `get-ttl-drift` | Configura/obtiene los ajustes de deriva de TTL |
| **DNS64** | |
| `set-dns64` / `get-dns64` | Configura/obtiene los ajustes de DNS64 |
| **Observabilidad** | |
| `latency-stats` | Muestra la latencia de consulta upstream por servidor |
| `set-tracked-tlds` / `list-tracked-tlds` | Administra qué TLD reciben su propia etiqueta `tld` en las métricas de consultas por TLD |

Los transportes (DoT/DoH/DoQ), el proxy y unas pocas operaciones DNSSEC/DANE están disponibles por gRPC pero no tienen subórden en la CLI — véase [Métodos gRPC adicionales](#métodos-grpc-adicionales). Para el conjunto completo de banderas de cada orden, ejecuta `rolodex-dns-cli <ORDEN> --help`.

##### `add-record`

Agrega un registro DNS a la base de datos local.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/AddRecord`

```
rolodex-dns-cli add-record -n <NAME> -v <VALUE> [OPTIONS]
```

| Opción | Por omisión | Descripción |
|--------|---------|-------------|
| `-n, --name <NAME>` | -- | Nombre de dominio completamente cualificado (p. ej. `"example.com."` — se recomienda el punto final) |
| `-r, --record-type <TYPE>` | `a` | Tipo de registro DNS (véase la tabla de tipos de registro) |
| `-v, --value <VALUE>` | -- | Datos del registro. El formato depende del tipo de registro (véase la sección Tipos de registro) |
| `--ttl <TTL>` | `300` | Tiempo de vida en segundos. Si se pone a 0, el servidor usa 300 por omisión |
| `-p, --priority <PRIORITY>` | `0` | Prioridad para los registros MX y SRV. Valores más bajos = mayor prioridad. Se ignora en los demás tipos |

Ejemplos:
```bash
# Agrega un registro A por TCP
rolodex-dns-cli -a 127.0.0.1:50051 -t my-secret add-record \
  -n example.com. -r a -v 10.0.0.1 --ttl 600

# Agrega un registro MX por socket Unix
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-record \
  -n example.com. -r mx -v mail.example.com. -p 10

# Agrega un registro CNAME
rolodex-dns-cli add-record -n www.example.com. -r cname -v example.com.

# Agrega un registro SRV
rolodex-dns-cli add-record -n _sip._tcp.example.com. -r srv \
  -v "5 5060 sip.example.com." -p 10

# Agrega un registro URI
rolodex-dns-cli add-record -n example.com. -r uri \
  -v "10 1 \"https://example.com/\"" -p 10

# Agrega un registro SSHFP
rolodex-dns-cli add-record -n host.example.com. -r sshfp \
  -v "2 1 123456789abcdef..."

# Agrega un registro comodín
rolodex-dns-cli add-record -n "*.example.com." -r a -v 10.0.0.99
```

##### `remove-record`

Elimina uno o más registros DNS de la base de datos local. Elimina por nombre, con filtros opcionales de tipo y valor.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/RemoveRecord`

```
rolodex-dns-cli remove-record -n <NAME> [OPTIONS]
```

| Opción | Por omisión | Descripción |
|--------|---------|-------------|
| `-n, --name <NAME>` | -- | Nombre de dominio completamente cualificado de los registros a eliminar |
| `-r, --record-type <TYPE>` | -- | Si se indica, solo elimina los registros de este tipo. Si se omite, elimina todos los tipos para ese nombre |
| `-v, --value <VALUE>` | -- | Si se indica, solo elimina el registro con este valor exacto |

Ejemplos:
```bash
# Elimina todos los registros de un nombre
rolodex-dns-cli remove-record -n old.example.com.

# Elimina solo los registros A de un nombre
rolodex-dns-cli remove-record -n example.com. -r a

# Elimina un registro concreto por su valor
rolodex-dns-cli remove-record -n example.com. -r a -v 10.0.0.1
```

##### `list-records`

Lista los registros DNS de la base de datos local con filtros opcionales.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/ListRecords`

```
rolodex-dns-cli list-records [OPTIONS]
```

| Opción | Por omisión | Descripción |
|--------|---------|-------------|
| `-n, --name <NAME>` | -- | Filtra por nombre de dominio. Admite el prefijo comodín `"*."` para casar todos los subdominios (p. ej. `"*.example.com."`) |
| `-r, --record-type <TYPE>` | -- | Filtra por tipo de registro. Si se omite, devuelve todos los tipos |

Ejemplos:
```bash
# Lista todos los registros
rolodex-dns-cli list-records

# Lista los registros de un nombre concreto
rolodex-dns-cli list-records -n example.com.

# Lista todos los subdominios
rolodex-dns-cli list-records -n "*.example.com."

# Lista solo los registros AAAA
rolodex-dns-cli list-records -r aaaa
```

##### `set-forwarders`

Fija los reenviadores DNS upstream en tiempo de ejecución. Reemplaza la lista de reenviadores completa.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/SetForwarders`

```
rolodex-dns-cli set-forwarders -f <ADDR>...
```

| Opción | Por omisión | Descripción |
|--------|---------|-------------|
| `-f, --forwarders <ADDR>...` | -- | Direcciones de los servidores DNS upstream en formato `"host:puerto"`. Varias direcciones separadas por espacios |

Ejemplos:
```bash
# Fija el DNS de Google y de Cloudflare
rolodex-dns-cli set-forwarders -f 8.8.8.8:53 1.1.1.1:53

# Fija un único reenviador
rolodex-dns-cli set-forwarders -f 9.9.9.9:53

# Elimina todos los reenviadores (modo puramente autoritativo)
rolodex-dns-cli set-forwarders -f ""
```

##### `set-resolution-mode`

Cambia cómo se resuelven los nombres para los que este servidor no es autoritativo,
sin reiniciar. El `resolution.mode` del archivo de configuración es solo la semilla
de arranque — esto es lo que cambia el modo que de verdad está resolviendo consultas.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/SetResolutionMode`

```
rolodex-dns-cli set-resolution-mode -m <MODO>
```

| Opción | Por omisión | Descripción |
|--------|-------------|-------------|
| `-m, --mode <MODO>` | -- | `auto`, `recursive` o `forward`. No distingue mayúsculas |

Un modo no reconocido se rechaza con `InvalidArgument` en lugar de caer en silencio a
`auto` como hace el archivo de configuración: a quien llama y escribe mal un modo no
se le puede decir que la máquina está en uno mientras resuelve en otro.

Ejemplos:
```bash
# Cadena de reserva con las raíces primero (el valor por omisión)
rolodex-dns-cli set-resolution-mode -m auto

# Iterar solo desde las raíces, sin ninguna reserva
rolodex-dns-cli set-resolution-mode -m recursive

# Solo los reenviadores configurados
rolodex-dns-cli set-resolution-mode -m forward
```

Cambiar *hacia* `auto` vuelve a lanzar el precalentamiento de niveles, de modo que las
primeras consultas después del cambio no pagan el coste del nivel frío.

##### `get-resolution-mode`

Muestra el modo actualmente en vigor. Es el modo que de verdad está resolviendo
consultas, que no tiene por qué ser el que nombra el archivo de configuración — los
dos difieren después de un `set-resolution-mode`.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/GetResolutionMode`

```
rolodex-dns-cli get-resolution-mode
```

Ejemplo:
```bash
$ rolodex-dns-cli get-resolution-mode
Resolution mode: auto
```

##### `flush-cache`

Vacía el caché de resultados de las listas de bloqueo. Fuerza búsquedas frescas para las consultas siguientes.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/FlushCache`

```
rolodex-dns-cli flush-cache
```

##### `create-scope`

Crea un nuevo ámbito de red con un dominio `.home` reservado.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/CreateNetworkScope`

```
rolodex-dns-cli create-scope -n <NAME> [OPTIONS]
```

| Opción | Por omisión | Descripción |
|--------|---------|-------------|
| `-n, --name <NAME>` | -- | Nombre único del ámbito de red (p. ej. `"office"`, `"lab"`) |
| `-d, --home-domain <DOMAIN>` | `"<name>.home."` | Dominio `.home` reservado para este ámbito. Si se omite, por omisión es `"<name>.home."` |

Ejemplos:
```bash
# Crea un ámbito con el dominio home por omisión
rolodex-dns-cli create-scope -n office
# Crea el ámbito "office" con el dominio home "office.home."

# Crea un ámbito con un dominio home a medida
rolodex-dns-cli create-scope -n lab -d lab.internal.
```

##### `delete-scope`

Elimina un ámbito de red y todos sus registros y asociaciones.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/DeleteNetworkScope`

```
rolodex-dns-cli delete-scope -n <NAME>
```

| Opción | Por omisión | Descripción |
|--------|---------|-------------|
| `-n, --name <NAME>` | -- | Nombre del ámbito a eliminar |

##### `list-scopes`

Lista todos los ámbitos de red configurados.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/ListNetworkScopes`

```
rolodex-dns-cli list-scopes
```

##### `join-network`

Asocia una dirección IP con un ámbito de red. La asociación tiene un TTL y debe refrescarse con regularidad.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/JoinNetwork`

```
rolodex-dns-cli join-network -i <IP> -s <SCOPE> [OPTIONS]
```

| Opción | Por omisión | Descripción |
|--------|---------|-------------|
| `-i, --ip <IP>` | -- | Dirección IP del cliente a asociar (p. ej. `"192.168.1.100"`) |
| `-s, --scope <SCOPE>` | -- | Nombre del ámbito de red al que unirse |
| `--ttl <TTL>` | `300` | TTL en segundos de la asociación. Debe refrescarse antes de que expire. Si es 0, por omisión son 300 |

Ejemplos:
```bash
# Se une con el TTL por omisión
rolodex-dns-cli join-network -i 192.168.1.100 -s office

# Se une con un TTL a medida
rolodex-dns-cli join-network -i 10.0.0.5 -s lab --ttl 600
```

##### `leave-network`

Elimina la asociación de una dirección IP con su ámbito de red.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/LeaveNetwork`

```
rolodex-dns-cli leave-network -i <IP>
```

| Opción | Por omisión | Descripción |
|--------|---------|-------------|
| `-i, --ip <IP>` | -- | Dirección IP del cliente a desasociar |

##### `list-associations`

Lista las asociaciones IP-ámbito, opcionalmente filtradas por ámbito.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/GetNetworkAssociations`

```
rolodex-dns-cli list-associations [OPTIONS]
```

| Opción | Por omisión | Descripción |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | -- | Filtra por nombre de ámbito. Si se omite, lista todas las asociaciones |

##### `add-scoped-record`

Agrega un registro DNS dentro de un ámbito de red concreto. Los registros con ámbito solo son visibles para las IP asociadas a ese ámbito.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/AddScopedRecord`

```
rolodex-dns-cli add-scoped-record -s <SCOPE> -n <NAME> -v <VALUE> [OPTIONS]
```

| Opción | Por omisión | Descripción |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | -- | Ámbito de red al que agregar el registro |
| `-n, --name <NAME>` | -- | Nombre de dominio completamente cualificado |
| `-r, --record-type <TYPE>` | `a` | Tipo de registro DNS |
| `-v, --value <VALUE>` | -- | Datos del registro |
| `--ttl <TTL>` | `300` | Tiempo de vida en segundos |
| `-p, --priority <PRIORITY>` | `0` | Prioridad para los registros MX y SRV |

Ejemplos:
```bash
# Agrega un registro A con ámbito
rolodex-dns-cli add-scoped-record -s office -n printer.office.home. -v 192.168.1.50

# Agrega un CNAME con ámbito
rolodex-dns-cli add-scoped-record -s lab -n app.lab.home. -r cname -v server.lab.home.
```

##### `remove-scoped-record`

Elimina registros DNS de un ámbito de red concreto.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/RemoveScopedRecord`

```
rolodex-dns-cli remove-scoped-record -s <SCOPE> -n <NAME> [OPTIONS]
```

| Opción | Por omisión | Descripción |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | -- | Ámbito de red del que eliminar registros |
| `-n, --name <NAME>` | -- | Nombre de dominio completamente cualificado |
| `-r, --record-type <TYPE>` | -- | Filtra por tipo de registro |
| `-v, --value <VALUE>` | -- | Filtra por valor exacto |

##### `list-scoped-records`

Lista los registros DNS dentro de un ámbito de red.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/ListScopedRecords`

```
rolodex-dns-cli list-scoped-records -s <SCOPE> [OPTIONS]
```

| Opción | Por omisión | Descripción |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | -- | Ámbito de red a consultar |
| `-n, --name <NAME>` | -- | Filtra por nombre de dominio (admite el prefijo comodín `"*."`) |
| `-r, --record-type <TYPE>` | -- | Filtra por tipo de registro |

##### `get-search-domains`

Obtiene los dominios de búsqueda de una dirección IP de cliente.
**Ruta gRPC:** `/rolodex_dns.RolodexDnsService/GetSearchDomains`

```
rolodex-dns-cli get-search-domains -i <IP>
```

| Opción | Por omisión | Descripción |
|--------|---------|-------------|
| `-i, --ip <IP>` | -- | Dirección IP del cliente a buscar |

## API gRPC

La API de administración está definida en `proto/rolodex_dns.proto`. Todos los métodos aceptan un campo `auth_token` para la autenticación por secreto compartido al conectar por TCP. Las conexiones por socket Unix se saltan la autenticación.

Consulta el archivo proto para la referencia completa de la API. El servicio define 74 métodos RPC que cubren la administración de registros, los ámbitos de red, los TLD propios y el ingreso, las listas de bloqueo, DHCP, los transportes cifrados, DNSSEC, DANE/ACME, el cacheado, DNS64, las métricas y la observabilidad.

### Servicio: `rolodex_dns.RolodexDnsService`

#### `AddRecord`

**Ruta:** `/rolodex_dns.RolodexDnsService/AddRecord`

Agrega un registro DNS a la base de datos local.

**Parámetros:**
- `record` (DnsRecord, obligatorio): el registro DNS a agregar
  - `name` (string): nombre de dominio completamente cualificado (p. ej. `"example.com."`)
  - `record_type` (RecordType): tipo de registro DNS (véase Tipos de registro más abajo)
  - `value` (string): datos del registro (p. ej. dirección IP, nombre de host)
  - `ttl` (uint32): tiempo de vida en segundos. Por omisión: 300 si se pone a 0
  - `priority` (uint32): prioridad para los registros MX/SRV (se ignora en los demás tipos). Por omisión: 0
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `success` (bool): si la operación tuvo éxito
- `message` (string): mensaje de error si `success` es falso

#### `RemoveRecord`

**Ruta:** `/rolodex_dns.RolodexDnsService/RemoveRecord`

Elimina uno o más registros DNS de la base de datos local.

**Parámetros:**
- `name` (string, obligatorio): nombre de dominio completamente cualificado
- `record_type` (RecordType): si se pone, solo elimina los registros de este tipo. Si no se pone (A/0), elimina todos los registros de ese nombre
- `value` (string): si no está vacío, solo elimina el registro con este valor exacto
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `success` (bool): si la operación tuvo éxito
- `removed_count` (uint32): número de registros eliminados
- `message` (string): mensaje de error si `success` es falso

#### `ListRecords`

**Ruta:** `/rolodex_dns.RolodexDnsService/ListRecords`

Consulta la base de datos DNS local con filtros opcionales.

**Parámetros:**
- `name_filter` (string): filtra por nombre de dominio. Admite el prefijo comodín `"*."` para casar todos los subdominios (p. ej. `"*.example.com."`)
- `record_type_filter` (RecordType): filtra por tipo de registro (solo se aplica cuando `filter_by_type` es verdadero)
- `filter_by_type` (bool): si se aplica el `record_type_filter`. Por omisión: falso
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `records` (repeated DnsRecord): registros DNS coincidentes

#### `SetForwarders`

**Ruta:** `/rolodex_dns.RolodexDnsService/SetForwarders`

Configura los reenviadores DNS upstream en tiempo de ejecución.

**Parámetros:**
- `forwarders` (repeated string): lista de direcciones de servidores DNS upstream en formato `"host:puerto"` (p. ej. `"8.8.8.8:53"`)
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `success` (bool): si la operación tuvo éxito
- `message` (string): mensaje de error si `success` es falso

#### `SetResolutionMode`

**Ruta:** `/rolodex_dns.RolodexDnsService/SetResolutionMode`

Cambia el modo de resolución upstream en tiempo de ejecución.

Por lo demás, `resolution.mode` es un ajuste que solo se lee al arrancar, lo que lo
convertía en la única pieza del comportamiento upstream que un orquestador no podía
cambiar sin reescribir ese archivo y reiniciar el proceso — y reiniciar el único
resolvedor de una máquina es una caída de DNS para todo lo que hay en ella.

**Parámetros:**
- `mode` (string): `"auto"` (cadena de reserva con las raíces primero), `"recursive"` (iterativo solo desde las raíces) o `"forward"` (solo los reenviadores configurados). No distingue mayúsculas
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `success` (bool): si la operación tuvo éxito
- `message` (string): mensaje de error si `success` es falso

Un modo no reconocido devuelve `InvalidArgument` en lugar de caer a `auto` como hace
el camino del archivo de configuración. Un archivo lo lee una vez al arrancar alguien
que puede ver el aviso; una RPC tiene a quien llama esperando una respuesta, y decirle
"éxito" mientras se resuelve en un modo que no pidió es como una máquina acaba en
`recursive` en una red que filtra el `:53` sin nada en los registros que explique por
qué falla cada nombre.

Cambiar **hacia** `auto` lanza el mismo precalentamiento de niveles que hace el camino
de arranque, así que las primeras consultas después del cambio no pagan el coste del nivel
frío. El sondeo de recuperación de niveles se ejecuta incondicionalmente, de modo que
un modo cambiado a `auto` en caliente todavía puede recuperar un nivel restablecido.

#### `GetResolutionMode`

**Ruta:** `/rolodex_dns.RolodexDnsService/GetResolutionMode`

Devuelve el modo de resolución actualmente en vigor — el que de verdad está
resolviendo consultas, no el que nombra el archivo de configuración. Los dos difieren
después de una llamada a `SetResolutionMode`.

**Parámetros:**
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `mode` (string): `"auto"`, `"recursive"` o `"forward"`

#### `FlushCache`

**Ruta:** `/rolodex_dns.RolodexDnsService/FlushCache`

Vacía el caché de búsquedas de las listas de bloqueo.

**Parámetros:**
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `success` (bool): si la operación tuvo éxito
- `message` (string): mensaje de error si `success` es falso

#### `CreateNetworkScope`

**Ruta:** `/rolodex_dns.RolodexDnsService/CreateNetworkScope`

Crea un nuevo ámbito de red con un dominio `.home` reservado.

**Parámetros:**
- `scope` (NetworkScope, obligatorio): el ámbito a crear
  - `name` (string): nombre único del ámbito (p. ej. `"office"`, `"lab"`)
  - `home_domain` (string): dominio `.home` reservado. Por omisión: `"<name>.home."` si está vacío
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `success` (bool): si la operación tuvo éxito
- `message` (string): mensaje de error si `success` es falso

#### `DeleteNetworkScope`

**Ruta:** `/rolodex_dns.RolodexDnsService/DeleteNetworkScope`

Elimina un ámbito de red y todos sus registros y asociaciones.

**Parámetros:**
- `name` (string, obligatorio): nombre del ámbito a eliminar
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `success` (bool): si la operación tuvo éxito
- `message` (string): mensaje de error si `success` es falso

#### `ListNetworkScopes`

**Ruta:** `/rolodex_dns.RolodexDnsService/ListNetworkScopes`

Obtiene todos los ámbitos de red configurados.

**Parámetros:**
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `scopes` (repeated NetworkScope): todos los ámbitos configurados

#### `JoinNetwork`

**Ruta:** `/rolodex_dns.RolodexDnsService/JoinNetwork`

Asocia una dirección IP de cliente con un ámbito de red. La asociación tiene un TTL que debe refrescarse con regularidad para mantener la resolución DNS.

**Parámetros:**
- `ip_address` (string, obligatorio): IP del cliente a asociar (p. ej. `"192.168.1.100"`)
- `scope_name` (string, obligatorio): nombre del ámbito de red al que unirse
- `ttl_seconds` (uint64): TTL en segundos. Por omisión: 300 si se pone a 0. Debe refrescarse antes de que expire.
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `success` (bool): si la operación tuvo éxito
- `message` (string): mensaje de error si `success` es falso

#### `LeaveNetwork`

**Ruta:** `/rolodex_dns.RolodexDnsService/LeaveNetwork`

Elimina la asociación de una dirección IP con su ámbito de red.

**Parámetros:**
- `ip_address` (string, obligatorio): IP del cliente a desasociar
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `success` (bool): si la operación tuvo éxito
- `message` (string): mensaje de error si `success` es falso

#### `GetNetworkAssociations`

**Ruta:** `/rolodex_dns.RolodexDnsService/GetNetworkAssociations`

Obtiene las asociaciones IP-ámbito.

**Parámetros:**
- `scope_name` (string): filtra por nombre de ámbito. Vacío devuelve todas las asociaciones.
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `associations` (repeated NetworkAssociation): asociaciones coincidentes
  - `ip_address` (string): la IP asociada
  - `scope_name` (string): el nombre del ámbito
  - `ttl_seconds` (uint64): TTL de la asociación

#### `AddScopedRecord`

**Ruta:** `/rolodex_dns.RolodexDnsService/AddScopedRecord`

Agrega un registro DNS dentro de un ámbito de red concreto. Los registros con ámbito solo son visibles para las IP asociadas a ese ámbito.

**Parámetros:**
- `scope_name` (string, obligatorio): el ámbito al que agregar el registro
- `record` (DnsRecord, obligatorio): el registro DNS a agregar
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `success` (bool): si la operación tuvo éxito
- `message` (string): mensaje de error si `success` es falso

#### `RemoveScopedRecord`

**Ruta:** `/rolodex_dns.RolodexDnsService/RemoveScopedRecord`

Elimina registros DNS de un ámbito de red concreto.

**Parámetros:**
- `scope_name` (string, obligatorio): el ámbito del que eliminar registros
- `name` (string, obligatorio): FQDN cuyos registros se eliminan
- `record_type` (RecordType): filtro de tipo opcional
- `value` (string): filtro de valor exacto opcional
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `success` (bool): si la operación tuvo éxito
- `removed_count` (uint32): número de registros eliminados
- `message` (string): mensaje de error si `success` es falso

#### `ListScopedRecords`

**Ruta:** `/rolodex_dns.RolodexDnsService/ListScopedRecords`

Consulta los registros DNS dentro de un ámbito de red.

**Parámetros:**
- `scope_name` (string, obligatorio): el ámbito a consultar
- `name_filter` (string): filtra por nombre de dominio (admite el prefijo comodín `"*."`)
- `record_type_filter` (RecordType): filtra por tipo de registro (solo se aplica cuando `filter_by_type` es verdadero)
- `filter_by_type` (bool): si se aplica el `record_type_filter`. Por omisión: falso
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `records` (repeated DnsRecord): registros con ámbito coincidentes

#### `GetSearchDomains`

**Ruta:** `/rolodex_dns.RolodexDnsService/GetSearchDomains`

Obtiene los dominios de búsqueda de una dirección IP de cliente. Devuelve el dominio `.home` del ámbito con el que la IP está asociada.

**Parámetros:**
- `ip_address` (string, obligatorio): IP del cliente a buscar
- `auth_token` (string): secreto compartido para la autenticación

**Respuesta:**
- `search_domains` (repeated string): dominios de búsqueda de la IP (típicamente el dominio `.home` del ámbito)

#### Métodos gRPC adicionales

También están disponibles los métodos siguientes. Véase `proto/rolodex_dns.proto` para las definiciones completas de petición/respuesta.

| Método | Descripción |
|--------|-------------|
| `AddAuthoritativeZone` | Declara una zona como autoritativa (bit AA, sin reenvío upstream) |
| `RemoveAuthoritativeZone` | Elimina una zona de la lista de autoritativas |
| `ListAuthoritativeZones` | Lista todas las zonas autoritativas |
| `GetCacheStats` | Obtiene las estadísticas del caché DNS (entradas, aciertos, fallos) |
| `FlushDnsCache` | Vacía el caché de respuestas DNS |
| `SetTtlDriftConfig` | Configura el ajuste por deriva de TTL (modo fijo o logarítmico) |
| `GetTtlDriftConfig` | Obtiene la configuración de deriva de TTL |
| `GetQueryLatencyStats` | Obtiene las estadísticas de latencia de consulta upstream por servidor |
| `SetResolutionMode` / `GetResolutionMode` | Cambia el modo de resolución upstream en caliente, y lee el modo actualmente en vigor |
| `SetTrackedTlds` / `ListTrackedTlds` | Reemplaza la lista de TLD rastreados, y lee los conjuntos almacenado, propio y efectivo |
| `AddLocalBlocklistEntry` | Agrega una entrada a la lista de bloqueo local |
| `RemoveLocalBlocklistEntry` | Elimina una entrada de la lista de bloqueo local |
| `ListLocalBlocklistEntries` | Lista todas las entradas de la lista de bloqueo local |
| `SetDnsblConfig` / `GetDnsblConfig` | Configura/obtiene los ajustes de listas de bloqueo de dominios (DNSBL) |
| `AddDnsblAllowlistEntry` | Exime a un nombre (y a sus subdominios) de la revisión de listas de bloqueo |
| `RemoveDnsblAllowlistEntry` | Elimina una entrada de la lista de permitidos de DNSBL |
| `ListDnsblAllowlistEntries` | Lista todas las entradas de la lista de permitidos de DNSBL |
| `AddScopeTld` | Registra un TLD propio globalmente único para un ámbito; un `listen_ip` opcional arranca además una escucha DNS de ingreso |
| `RemoveScopeTld` | Elimina un TLD propio (y su escucha de ingreso, una vez sin uso) |
| `ListScopeTlds` | Lista los TLD que posee un ámbito |
| `SetScopeTldForwarders` / `ListScopeTldForwarders` | Administra los reenviadores pares de un TLD |
| `ListScopeTldListeners` | Lista las escuchas DNS de ingreso ligadas a los TLD de un ámbito |
| `AddDhcpPool` / `RemoveDhcpPool` / `ListDhcpPools` | Administra los conjuntos de direcciones DHCP por ámbito |
| `ListDhcpLeases` / `DeleteDhcpLease` | Inspecciona y elimina concesiones DHCP |
| `SetDhcpCertOption` / `RemoveDhcpCertOption` / `ListDhcpCertOptions` | Administra la entrega de certificados mediante opciones DHCP |
| `EnsureZoneCa` | Crea la CA intermedia de la zona si no existe; devuelve el PEM de la raíz y la intermedia |
| `CreateEabCredential` / `RemoveEabCredential` | Acuña o elimina una credencial EAB con ámbito de zona |
| `ListAcmeAccounts` / `ListAcmeCertificates` | Lista las cuentas ACME y los certificados emitidos |
| `SetDotConfig` / `GetDotConfig` | Configura/obtiene los ajustes de DNS-over-TLS |
| `SetDohConfig` / `GetDohConfig` | Configura/obtiene los ajustes de DNS-over-HTTPS |
| `SetDoqConfig` / `GetDoqConfig` | Configura/obtiene los ajustes de DNS-over-QUIC |
| `SetProxyConfig` / `GetProxyConfig` | Configura/obtiene los ajustes del proxy HTTP |
| `GenerateDnssecKey` | Genera un par de llaves DNSSEC para una zona |
| `ListDnssecKeys` | Lista las llaves DNSSEC de una zona |
| `DeleteDnssecKey` | Elimina una llave DNSSEC |
| `GetDsRecords` | Obtiene los registros DS para la delegación desde la zona padre |
| `SignZone` | Firma (o vuelve a firmar) una zona con sus llaves DNSSEC |
| `GenerateTlsaRecord` | Genera un registro TLSA a partir de un certificado PEM |
| `ListTlsaRecords` | Lista los registros TLSA de un dominio |
| `GenerateDaneRootCa` | Genera una CA raíz DANE autofirmada |
| `RequestAcmeCert` | Solicita un certificado mediante el desafío ACME DNS-01 |
| `GetAcmeStatus` | Obtiene el estado del certificado ACME de un dominio |
| `SetDns64Config` / `GetDns64Config` | Configura/obtiene los ajustes de síntesis DNS64 |

### Tipos de registro

| Valor del enum | Nombre | Descripción |
|-----------|------|-------------|
| 0 | `A` | Correspondencia con dirección IPv4. Valor: dirección IPv4 (p. ej. `"192.168.1.1"`) |
| 1 | `AAAA` | Correspondencia con dirección IPv6. Valor: dirección IPv6 (p. ej. `"::1"`) |
| 2 | `CNAME` | Alias de nombre canónico. Valor: FQDN de destino (p. ej. `"target.example.com."`) |
| 3 | `MX` | Intercambiador de correo. Valor: FQDN del servidor de correo. Usa el campo `priority` |
| 4 | `TXT` | Registro de texto. Valor: contenido textual |
| 5 | `NS` | Servidor de nombres. Valor: FQDN del servidor de nombres |
| 6 | `SOA` | Inicio de autoridad. Valor: `"mname rname serial refresh retry expire minimum"` (separados por espacios) |
| 7 | `SRV` | Localizador de servicio. Valor: `"weight port target"` (separados por espacios). Usa el campo `priority` |
| 8 | `PTR` | Puntero para DNS inverso. Valor: FQDN de destino |
| 9 | `URI` | Registro de recurso URI (RFC 7553). Valor: `"priority weight \"uri\""` |
| 10 | `SSHFP` | Huella SSH (RFC 4255). Valor: `"algorithm fp_type fingerprint"` |
| 11 | `DNAME` | Nombre de delegación (RFC 6672). Valor: FQDN de destino (reescribe el subárbol entero) |
| 12 | `ANAME` | Nombre alias (borrador). Valor: FQDN de destino (resuelto en el momento de la consulta, funciona en el ápice de la zona) |
| 13 | `ZONEMD` | Resumen del mensaje de zona (RFC 9156). Valor: `"serial scheme hash_algorithm digest"` |
| 14 | `TLSA` | Asociación de certificado TLS (RFC 6698). Valor: `"usage selector matching_type cert_data"` |
| 15 | `DNSKEY` | Llave pública DNSSEC. Administrada automáticamente por la generación de llaves DNSSEC |
| 16 | `DS` | Firmante de delegación. Administrado automáticamente por DNSSEC |
| 17 | `RRSIG` | Firma de registro de recurso DNSSEC. Administrada automáticamente por la firma de zonas |
| 18 | `NSEC` | Registro «siguiente seguro» (DNSSEC). Administrado automáticamente por la firma de zonas |
| 19 | `NSEC3` | Registro «siguiente seguro» v3 (DNSSEC). Administrado automáticamente por la firma de zonas |
| 20 | `NSEC3PARAM` | Parámetros de NSEC3 (DNSSEC). Administrados automáticamente por la firma de zonas |
| 21 | `CERT` | Almacenamiento de certificados en el DNS (RFC 4398). Valor: `"cert_type key_tag algorithm base64_cert_data"`. Se usa para distribuir la cadena de CA |
| 22 | `SVCB` | Vinculación de servicio (RFC 9460). El valor es una línea de formato de presentación: `"<prioridad> <destino> [llave=valor ...]"` — p. ej. `"1 dns.home. alpn=dot port=853"`. Es el tipo con el que se publica una designación DDR en `_dns.resolver.arpa.` (RFC 9462) |
| 23 | `HTTPS` | La forma SVCB específica de HTTPS (RFC 9460 §9). Mismo formato de valor que `SVCB` |

## Cacheado con la privacidad por delante

Rolodex DNS cachea las respuestas DNS localmente, de modo que las consultas repetidas para el mismo nombre se responden sin contactar con ningún reenviador upstream. Esto evita la fuga de consultas DNS: una vez cacheado un registro, ningún observador externo puede ver que la consulta se volvió a hacer.

El caché distingue dos clases de entradas:

- **Registros locales** (de la base de datos SQLite): cacheados en memoria con TTL estables (sin decaimiento). Estas entradas no se persisten al almacén de respaldo del caché, ya que viven en la base de datos. El caché DNS en memoria se invalida automáticamente cada vez que se agregan, eliminan o modifican registros por gRPC, así que los cambios surten efecto de inmediato.
- **Respuestas reenviadas** (de los resolvedores upstream): cacheadas con TTL decrecientes y persistidas en una tabla de caché respaldada por SQLite. Al reiniciar, las entradas persistidas se recargan, así que el caché está caliente de inmediato.

Las respuestas negativas (NXDOMAIN/NODATA autoritativos) se cachean aparte, durante el TTL negativo del RFC 2308 (`min(SOA MINIMUM, SOA TTL)`) tal como lo publicó la zona. Agregar un registro local para un nombre descarta cualquier negativo cacheado para él, así que un nombre recién agregado resuelve de inmediato en vez de esperar a que expire el TTL negativo.

Las estadísticas del caché están disponibles por `GetCacheStats` y el caché se puede vaciar con `FlushDnsCache`.

Para privacidad máxima, pon `resolution.mode: forward` con `forwarders: []` para ejecutar Rolodex DNS como un servidor puramente autoritativo sin resolución externa alguna. Todas las respuestas saldrán de la base de datos local.

## Resolución upstream

Los nombres que no se satisfacen localmente se resuelven según `resolution.mode`:

| Modo | Comportamiento |
| ---- | -------- |
| `auto` (por omisión) | La cadena de reserva por niveles de más abajo |
| `recursive` | Iterativo solo desde los servidores raíz; no se contacta nunca con un resolvedor upstream |
| `forward` | Reenvía solo a los `forwarders` configurados |

**El archivo de configuración es solo la semilla de arranque.** `resolution.mode` se
lee una vez al arrancar; de ahí en adelante el modo es el que
[`SetResolutionMode`](#setresolutionmode) fijó por última vez, y
[`GetResolutionMode`](#getresolutionmode) informa del que de verdad está resolviendo
consultas. Los dos difieren después de un cambio — nunca se reinicia un servidor en marcha
para cambiar de modo, porque reiniciar el único resolvedor de una máquina es una caída
de DNS para todo lo que hay en ella. `rolodex-dns-cli set-resolution-mode` /
`get-resolution-mode` son esas dos mismas llamadas desde la consola.

**`arpa.` no se resuelve nunca fuera de esta máquina.** En todos los modos, `arpa.` y todo lo que hay bajo él se responde desde datos locales —un PTR almacenado, un registro con ámbito, una zona inversa administrada o autoritativa— o se da **REFUSED**. Nada del subárbol se envía a un servidor raíz, a un reenviador ni a un upstream cifrado. REFUSED y no NXDOMAIN porque el servidor se está negando a responder por un espacio de nombres, no afirmando que el nombre no exista.

La regla casa en el límite de etiqueta, así que `notarpa.` y `arpa.example.com` son nombres corrientes y resuelven con normalidad. Dos consecuencias que conviene saber antes de activar esto en una máquina que usa gente: una búsqueda inversa de una dirección de la que no se tienen datos se rechaza en vez de responderse desde internet (`dig -x 8.8.8.8`), y `ipv4only.arpa` se rechaza, lo que un cliente que descubre NAT64 lee como «aquí no hay NAT64».

### La cadena de reserva `auto`

Los niveles se prueban empezando por el más preferido (el más fiable):

| Nivel | Camino | Por qué |
| ---- | ---- | --- |
| 0 | Iterativo desde los servidores raíz | Ningún tercero ve tus consultas |
| 1 | DoH (`:443`) o DoT (`:853`) a `resolution.secure_upstreams` | Cifrado, y usa puertos que sobreviven al filtrado de `:53` |
| 2 | Do53 en claro a `forwarders` | El resolvedor local o provisto por DHCP |
| 3 | Do53 en claro a `resolution.public_fallback` | Último recurso |

Se prefiere DoH a DoT porque el `:443` parece HTTPS corriente y sobrevive a la inspección profunda de paquetes que deja abrir una conexión DoT pero tira su sesión TLS. Los upstreams seguros se marcan **por IP**, con el certificado validado contra el `hostname` configurado, así que el nivel no necesita DNS previo para arrancar.

Un nivel solo «gana» cuando el transporte tuvo éxito y el rcode es NoError o NXDOMAIN; SERVFAIL, REFUSED y las respuestas no interpretables caen al siguiente. El nivel ganador es **pegajoso**, así que las consultas no pagan un tiempo de espera en un camino muerto cada vez. Recuperar un nivel más preferido ocurre de inmediato; degradar a uno menor solo se confirma después de `resolution.switch_grace_failures` consultas divergentes consecutivas, así que una consulta inestable no puede hacer oscilar el resolvedor. **Las consultas de cliente nunca sondean**: el nivel de partida es siempre el nivel confirmado. Una tarea de fondo vuelve a probar los niveles por encima cada `resolution.recovery_probe_secs` con su propio canario desechable, y reclamar el nivel 0 exige una respuesta validada con DNSSEC para el propio `DNSKEY` de la zona raíz — la mera alcanzabilidad dejaría que cualquier caja intermedia que secuestre el `:53` se instalase como el nivel más fiable. Todo cambio de nivel confirmado vacía el caché DNS, así que las respuestas de un nivel no pueden quedarse después de un cambio a otro.

### Resolvedor iterativo

El resolvedor recorre la cadena de delegaciones desde las raíces —raíz → TLD → autoritativo— con el bit de recursión deseada apagado, validando las respuestas por identificador de transacción y nombre de la pregunta contra la suplantación fuera de camino, sobre UDP con reserva automática a TCP al truncarse.

- **Pistas de raíz y cebado.** Las 13 direcciones raíz de IANA (solo IPv4, así que un equipo solo-v4 no se atasca nunca en una raíz v6) son un arranque: al iniciar, Rolodex pregunta a las raíces quiénes son las raíces y cachea el conjunto NS de `.` vivo con su TTL real. El cebado no se ejecuta nunca en el camino de la consulta, y las pistas siguen siendo la reserva si falla. Sustitúyelas con `resolution.root_hints`.
- **Reparto de carga entre servidores.** Los servidores de nombres se eligen por el menor `aciertos × latencia media`, lo que reparte las consultas como `aciertos ∝ 1/latencia`: los servidores rápidos llevan más, pero todo servidor sano lleva algo. Esto evita deliberadamente fijar cada consulta fría a una sola raíz (sea «la primera» o «la más rápida»), lo que se gana un límite de tasa y convierte cada búsqueda en un tiempo de espera y una conmutación.
- **Retroceso ante fallos.** Un servidor que falla queda fuera 2 s, duplicando por cada fallo consecutivo hasta 300 s, y se limpia con su primer éxito. Los servidores en retroceso se ordenan los últimos pero no se descartan nunca, así que la resolución sigue avanzando cuando todo está fallando.
- **Trabajo acotado.** 1,5 s de tiempo de espera por servidor de nombres, 30 remisiones, 16 saltos CNAME, profundidad 16, 4 servidores de nombres por delegación sin glue, y un techo duro de 64 consultas upstream por búsqueda de cliente — los límites de cada eje se multiplican, así que el total queda acotado de plano.

### Cachés del resolvedor

Bajo el caché de respuestas hay dos cachés que honran los TTL y guardan lo que una recursión aprende en el camino de bajada:

- **Caché de delegaciones** — zona → direcciones de servidores de nombres, aprendida de cada remisión. Una búsqueda de `.com` caliente se salta el salto a la raíz por completo. Las delegaciones cuyo TTL supera `resolution.delegation_persist_min_ttl` (300 s por omisión) se persisten en SQLite y se recargan al arrancar, así que un reinicio vuelve caliente; los conjuntos NS de la raíz y de los TLD traen TTL de varios días, así que sobreviven exactamente las entradas que merece la pena guardar.
- **Caché de registros** — glue, búsquedas de nombres NS sin glue y saltos CNAME, indexados por `(nombre, tipo)` y servidos con su vida *restante*.

Ambas sobreviven a las mutaciones de registros (agregar un registro no debe mandar a las raíces todos los nombres del mundo) y solo se vacían al conmutar de nivel en modo `auto`.

Los TTL se honran exactamente tal como se publican — incluido el TTL negativo del SOA de una zona, que no se recorta nunca. `resolution.default_ttl` se aplica solo donde nada trae un TTL usable.

## Filtrado por familia de direcciones

Las redes anuncian rutinariamente una ruta por omisión IPv6 y luego tiran silenciosamente todo el tráfico v6 (y el caso espejo ocurre en el NAT solo-v4). Un cliente al que se le entrega una dirección de una familia que su equipo no puede enrutar se atasca en la familia muerta en vez de recurrir a la otra — el fallo que atasca las descargas de imágenes de contenedor en un enlace con v6 roto.

Con `address_family.mode: auto` (el valor por omisión), un sondeo de fondo hace conexiones TCP a resolvedores públicos anycast en `:443` —el puerto que usa el tráfico real, y uno que sobrevive al filtrado de `:53`/`:853` que imponen algunas redes— para probar la alcanzabilidad *real* por familia. Los registros A/AAAA de una familia inalcanzable se descartan entonces de las respuestas (convirtiéndolas en NODATA) para que los clientes recurran a la pila que funciona.

El primer sondeo se ejecuta síncronamente al arrancar y es decisivo, así que arrancar en un enlace con una familia muerta suprime esa familia desde la primera consulta. Después, una familia que venía funcionando solo se marca como caída después de `address_family.fail_threshold` ciclos fallidos consecutivos, mientras que la recuperación surte efecto al primer éxito. Pon `mode: off` para responder siempre en ambas familias, o `force4`/`force6` para fijar una sin sondear.

## Transportes cifrados

Rolodex DNS admite tres protocolos de transporte DNS cifrado para evitar la escucha de las consultas DNS:

**DNS-over-TLS (DoT)** — RFC 7858, puerto 853 por omisión, testigo ALPN `dot`. DNS estándar envuelto en TLS sobre TCP, con el mismo encuadre de prefijo de longitud de 2 bytes. El testigo ALPN se anuncia, no se exige: un cliente que ofrece `dot` lo negocia, un cliente que solo ofrece algún otro protocolo se rechaza, y a un cliente que no manda extensión ALPN alguna se le sirve igualmente. Se configura con la sección `dot` en YAML o con `SetDotConfig` por gRPC.

**DNS-over-HTTPS (DoH)** — RFC 8484, puerto 443 por omisión. Consultas DNS sobre HTTPS con soporte de los métodos GET (`/dns-query?dns=<base64>`) y POST (`application/dns-message`). Opcionalmente admite HTTP/3 por QUIC (`enable_h3: true`). Se configura con la sección `doh` en YAML o con `SetDohConfig` por gRPC.

**DNS-over-QUIC (DoQ)** — RFC 9250, puerto 8853 por omisión. Consultas DNS sobre transporte QUIC para resolución cifrada de baja latencia. Se configura con la sección `doq` en YAML o con `SetDoqConfig` por gRPC.

Los tres protocolos requieren certificados TLS. Puedes aportar tu propio certificado y llave, o poner `auto_self_signed: true` para que Rolodex DNS genere un certificado autofirmado automáticamente. Un certificado generado cubre `localhost`, `127.0.0.1`, `::1` y las propias direcciones de ligadura de la escucha; agrega cualquier otro nombre por el que los clientes marquen la máquina —su nombre de host, su nombre `.local`, un alias de la LAN— a `self_signed_sans`, ya que un cliente configurado con un nombre de autenticación lo revisa y una ligadura comodín no aporta ningún nombre propio.

**Se puede nombrar un certificado que todavía no existe.** Que `cert_path`/`key_path` apunten a un archivo que no está ahí nada más es una falla dura cuando `auto_self_signed` está apagado. Con él prendido, la escucha arranca con material generado y el sondeo de certificados adopta el par real en cuanto aparece — sin reinicio y sin nada que coordinar. Eso es lo que permite configurar una escucha para un certificado que otra cosa todavía no ha emitido, que es el caso corriente en una máquina cuya CA se crea después de que arranque el resolvedor. Con `auto_self_signed: false` un archivo ausente sigue siendo fatal: eso es quien opera diciendo «sirve este certificado o ninguno».

**Los tres se reconfiguran con el servidor en marcha.** `SetDotConfig`, `SetDohConfig` y `SetDoqConfig` abren, mueven, recambian la llave o apagan su escucha sin reiniciar, y `Get*Config` informa de las direcciones realmente ligadas — que difieren de las pedidas siempre que la petición nombrara el puerto 0. El camino de arranque usa el mismo código, así que una configuración que funciona desde el YAML se comporta igual llegando por gRPC.

El orden merece conocerse, porque una escucha no puede arrancar antes de que la anterior suelte su puerto. Primero se revisa todo lo revisable **sin** el puerto — que la lista de ligaduras resuelva, que el material TLS cargue o se genere — de modo que una dirección mala o un certificado ilegible se rechazan con la escucha anterior todavía sirviendo. Nada más después se paran las escuchas viejas y se esperan. Si aun así la ligadura falla, se restaura la configuración anterior y la llamada informa de que el transporte está caído en vez de afirmar que tuvo éxito. Una lista de ligaduras vacía es un apagado, no un error.

Nada de esto toca el `:53` en ningún momento. Los transportes cifrados son escuchas independientes, así que reconfigurar una no cuesta nada fuera de sí misma.

## DNSSEC

Rolodex DNS tiene dos mitades DNSSEC independientes: **firma** sus propias zonas y **valida** las respuestas que resuelve del upstream. No comparten código — el firmante trabaja sobre filas de base de datos que escribimos nosotros y controla cada byte, un validador trabaja sobre lo que llegue de una parte cuya honradez es justo lo que está en cuestión, y los dos deben poder discrepar.

### Firma de zonas

La firma admite los algoritmos siguientes:

- **Ed25519** (preferido) — llaves y firmas compactas, firma rápida
- **ECDSA P-256/SHA-256** y **ECDSA P-384/SHA-384**

**RSA/SHA-256 (algoritmo 8) no se puede generar** y `generate-dnssec-key` lo rechaza: `ring` no genera llaves RSA. Sigue *interpretándose* —una fila de llave existente archivada bajo él se puede seguir listando— y las firmas RSA de zonas upstream son verificables, pero nada de aquí firmará con él. Un algoritmo que no se puede honrar de extremo a extremo se rechaza en la generación de llaves en vez de sustituirse en silencio, porque un DNSKEY que anuncia un algoritmo sobre el material de llave de otro produce un DS, un DNSKEY y un conjunto de RRSIG que discrepan todos entre sí, y ese fallo aflora en un resolvedor validador y no localmente.

Ed448 no está soportado por una limitación del crate de criptografía ring.

#### Flujo de trabajo de la firma

1. Genera una llave de firma de llaves (KSK) y una llave de firma de zona (ZSK) para tu zona:
   ```bash
   rolodex-dns-cli generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type KSK
   rolodex-dns-cli generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type ZSK
   ```

2. Firma la zona:
   ```bash
   rolodex-dns-cli sign-zone --zone example.com.
   ```

3. Obtén los registros DS para tu registrador. No hay subórden de CLI para esto — llama al método gRPC `GetDsRecords` (p. ej. mediante el `GetDsRecords(ctx, zone)` del cliente Go), o consulta los registros DS de la zona con cualquier cliente DNS.

La firma vuelve a publicar el RRset DNSKEY del ápice y produce un RRSIG por RRset. Vuelve a ejecutar `sign-zone` después de agregar o modificar registros; los RRSIG existentes se reemplazan en vez de acumularse.

**La denegación autenticada no se genera.** NSEC, NSEC3 y NSEC3PARAM son tipos de registro almacenables y listables, pero `sign-zone` ni los genera ni los sirve, así que una zona firmada aquí demuestra lo que existe y no lo que no.

DNSKEY, DS y RRSIG se sirven bajo sus propios códigos de tipo, con RDATA producido por el mismo codificador canónico que el firmante trocea — lo que va por el cable es byte a byte lo que se firmó.

### Validación del upstream

Las respuestas resueltas **iterativamente** se validan contra las anclas de confianza de la raíz de IANA. Esto está activo por omisión:

```yaml
dnssec:
  validate: true        # el valor por omisión
  trust_anchors: []     # vacío = las llaves raíz de IANA
```

Se aplica solo al camino iterativo — el modo `recursive` y el nivel de las raíces de `auto`. Una respuesta reenviada es el resumen recursivo de otro, y validarla significaría volver a resolver la cadena nosotros mismos, que es justo lo que ya es el nivel de las raíces. Una cadena `auto` que se ha degradado más allá del nivel 0 queda por tanto sin validar, y lo dice dejando AD apagado.

Los cuatro veredictos del RFC 4033 §5 se mantienen distintos:

| Veredicto | Significado | ¿Se sirve? |
| ------- | ------- | ------- |
| `Secure` | Las firmas encadenan hasta el ancla de confianza | Sí, con AD puesto para un cliente que lo pidió |
| `Insecure` | La cadena para de forma **demostrable** — una delegación del camino no tiene DS, y esa ausencia está firmada | Sí, AD apagado |
| `Bogus` | Los datos afirman estar firmados y la afirmación no se sostiene | **Nunca.** SERVFAIL |
| `Indeterminate` | No pudimos obtener lo necesario para decidir | **Nunca.** SERVFAIL |

La distinción que carga con la seguridad es Insecure contra Bogus. «No hay firma» *no* es Insecure — un atacante en el camino quita las firmas de cualquier respuesta. Es Insecure solo cuando un NSEC/NSEC3 firmado demuestra el DS ausente en la delegación de arriba, algo que un atacante no puede falsificar sin la llave del padre. Esa demostración es la razón de existir de la maquinaria NSEC/NSEC3; sin ella, un validador es uno que un atacante degrada hasta dejarlo en nada.

Cómo se comporta en la práctica:

- **La cadena se construye de arriba abajo**, junto al recorrido de delegaciones que el resolvedor ya hace, así que el DS viaja gratis en la remisión. Los conjuntos de llaves validados (y las delegaciones demostradamente inseguras) se cachean por zona, así que una zona caliente no cuesta ninguna rederivación.
- **Las respuestas bogus no se cachean nunca**, ni en positivo ni en negativo — un negativo bogus cacheado suprimiría el nombre real durante todo su TTL. En modo `auto` una validación fallida es una respuesta *definitiva* y no un fallo de nivel, así que una firma rota no se puede blanquear a través de un upstream que no valida.
- **AD se pone solo para `Secure`**, y solo para un cliente que puso DO o AD. Las respuestas construidas desde datos locales no ponen AD nunca.
- **RRSIG/NSEC/NSEC3 se quitan para un cliente que no puso DO** (RFC 4035 §3.2.1), salvo que pidiera ese tipo por su nombre — un registro A firmado casi triplica de tamaño, y una respuesta grande a una pregunta pequeña es la forma de amplificación que `security.recursion_cidrs` existe para cerrar.
- **Los algoritmos no soportados son Insecure, no Bogus** (RFC 6840 §5.11): que nos falte un algoritmo no es la caída de la zona. RSA/SHA-1/256/512, ambas curvas ECDSA y Ed25519 verifican todos. Los recuentos de iteración de NSEC3 por encima de 100 se tratan como inseguros en vez de calcularse (RFC 9276).
- **La validación cuesta aproximadamente una consulta extra por zona del camino**, así que el presupuesto de consultas por búsqueda gana 32 sobre las 64 de base cuando la validación está activa.
- **Una respuesta rechazada se rechaza, no se vuelve a pedir.** En el nivel de las raíces un veredicto que retiene es un SERVFAIL *definitivo*: la consulta no cae al upstream cifrado ni a un reenviador, no se cachea nada, y una remisión que no verificó no deja atrás delegación ni glue.
- **Una zona raíz que no valida se rechaza también.** No lograr anclar el propio DNSKEY de la raíz solía aflorar como un error, que la cadena de reserva leía como «las raíces son inalcanzables» y respondía desde un upstream que no valida — así que romper la obtención del DNSKEY de la raíz sacaba la validación del camino sin producir ni un solo veredicto bogus. Ahora es un veredicto. Una raíz que no podemos *alcanzar* sigue cayendo al siguiente nivel, deliberadamente: inalcanzable no es inválido. El compromiso es real y merece decirse — un ancla de confianza que esta compilación no conoce se convierte en una caída del DNS en vez de una degradación silenciosa, y `dnssec.validate: false` es la salida de emergencia.
- **Un servidor raíz que sirve DNSSEC inválido se saca del conjunto raíz** durante 15 minutos, duplicando por cada ofensa hasta un tope de 24 horas, por la única afirmación que podemos revisar sin preguntar a nadie más: su DNSKEY de la raíz contra el ancla local. La penalización sobrevive a que el servidor responda pronto, solo se limpia con una respuesta que *valide* (nunca esperando), y no se aplica nunca a la última raíz que queda — que todas las raíces fallen a la vez significa la zona o el ancla, no trece servidores rebeldes. Se aplica solo a los servidores raíz; por debajo de la raíz, un fallo de validación suele ser el error de firma de la propia zona, y esos ya fallan en cerrado. La imputación está en memoria y no sobrevive a un reinicio. Monitorea `rolodex_dns_dnssec_blamed_roots`.

Poner `dnssec.validate: false` resuelve exactamente como antes: sin bit DO saliente, sin cadena de confianza, sin SERVFAIL para los datos bogus.

**Anclas de confianza.** `dnssec.trust_anchors` toma la forma de presentación DNSKEY — `"<flags> <protocolo> <algoritmo> <clave en base64>"`, los cuatro campos RDATA tal como los imprime `dig DNSKEY .`. Una sustitución **reemplaza** las llaves de IANA en vez de agregarse a ellas, así que una raíz privada queda anclada a su propia llave y a nada más. Cada campo se valida al arrancar y un ancla malformada es un fallo duro, no una reserva silenciosa — un ancla que no puede casar con un DNSKEY real hace que toda zona firmada falle sin que nada apunte al ancla como causa.

Los veredictos son visibles por Prometheus como `rolodex_dns_dnssec_verdicts_total{verdict}`, junto a `dnssec_servfail_total`, `dnssec_blamed_roots` y `key_cache_entries`.

## Distribuir y confiar en la CA

Rolodex DNS es él mismo una autoridad de certificación ACME: una **CA raíz** autofirmada firma una **CA intermedia por zona**, y cada intermedia firma los certificados de hoja emitidos a través del endpoint ACME. Para que los clientes confíen en esos certificados, tienen que confiar en la CA raíz. Rolodex distribuye la cadena de CA de tres maneras.

### CA por DNS (registros CERT con reserva TXT)

Cada vez que se crea una CA intermedia por zona, Rolodex publica los certificados raíz e intermedio **en el propio DNS**, así que cualquier cliente que pueda resolver la zona puede obtener la CA y confiar en ella sin tocar jamás el portal de inscripción:

- **Registros `CERT` (RFC 4398)** en `_ca.<zona>.` — un registro por certificado, con RDATA `"1 0 0 <DER en base64>"` (tipo 1 = PKIX/X.509, etiqueta de llave y algoritmo 0). La raíz se identifica como el certificado autofirmado. Vale cualquier cliente DNS:
  ```bash
  dig CERT _ca.example.com
  ```
- **Registros `TXT`** en `_rolodex-ca.<zona>.` — el mismo DER en base64 partido en trozos de ≤255 bytes encuadrados como `rolodex-ca:v1:<root|intermediate>:<i>/<n>:<trozo>`. El prefijo único `rolodex-ca:` distingue los trozos de datos TXT ajenos, y los números de secuencia explícitos dejan a los clientes reensamblarlos sea cual sea el orden de la respuesta. Esta es la reserva para las pilas de resolución que no pueden consultar `CERT`.

La publicación es idempotente (los registros se reemplazan, no se duplican) y ocurre en cada punto en que se asegura la CA de una zona: inscripción por el portal, los RPC `EnsureZoneCa`/`CreateEabCredential` y la creación de cuenta/finalización de ACME. Los consumidores deberían preferir `CERT` y recurrir a `TXT`.

### Extensión de navegador

La extensión de navegador que hay bajo [`extension/`](extension/) tiene un panel **CA por DNS** independiente del portal: dale una URL DoH (p. ej. `https://dns.example.com/dns-query`) y una zona, y obtiene la cadena por DNS-over-HTTPS (prefiriendo `CERT`, recurriendo a `TXT`), identifica la raíz frente a la intermedia, opcionalmente verifica la intermedia contra el registro `TLSA` DANE-TA publicado, y ofrece descargas del PEM de la raíz, de la intermedia o de la cadena. La lógica DNS vive en `extension/ca_dns.js`, un módulo de navegador sin dependencias reutilizado por la batería de pruebas de JavaScript.

### Portal y CLI

En la red de confianza, el portal de inscripción (`acme.portal_bind`, por omisión `https://<host>:8500`) sirve la CA raíz en `GET /api/ca`, y la CLI de administración imprime la cadena completa:

```bash
# Imprime el PEM de la raíz y la intermedia de una zona
rolodex-dns-cli ensure-zone-ca --zone example.com

# O descarga la CA raíz desde el portal
curl -k https://<host>:8500/api/ca -o rolodex-root-ca.pem
```

Una vez que tengas el PEM de la CA raíz, añádelo al almacén de confianza de cada dispositivo (p. ej. `update-ca-trust` en Fedora/RHEL, `update-ca-certificates` en Debian/Ubuntu, Acceso a Llaveros en macOS, o el propio administrador de certificados del navegador para Firefox). Los servidores emitidos a través del endpoint ACME presentan una cadena `hoja + intermedia` que valida contra esta raíz; los clientes que entienden DANE pueden además fijar la intermedia mediante los registros `TLSA` que Rolodex publica automáticamente al emitir.

## DNS64

DNS64 (RFC 6147) sintetiza registros AAAA a partir de registros A para clientes solo-IPv6 que necesitan llegar a máquinas solo-IPv4. Cuando un cliente consulta un registro AAAA y no existe ninguno, pero sí existe un registro A, Rolodex DNS construye un AAAA sintético incrustando la dirección IPv4 en el prefijo IPv6 configurado.

El prefijo por omisión es `64:ff9b::/96` (el prefijo NAT64 bien conocido). Por ejemplo, un registro A de `192.0.2.1` se sintetizaría como `64:ff9b::192.0.2.1` (`64:ff9b::c000:201`).

Configúralo por YAML:
```yaml
dns64:
  enabled: true
  prefix: "64:ff9b::"
```

O en tiempo de ejecución por gRPC: `SetDns64Config` / `GetDns64Config`.

## Métricas de Prometheus

Una sección `metrics` opcional arranca un endpoint de raspado por HTTP en claro en `/metrics`. La sección está **ausente por omisión**, así que no se arranca escucha alguna y una actualización no abre ningún puerto nuevo.

```yaml
metrics:
  bind: "127.0.0.1:9153"
  # TLD que reciben su propia etiqueta `tld`. Los TLD propios se rastrean automáticamente.
  tracked_tlds:
    - common          # se expande al conjunto integrado de TLD comunes
    - lab.internal    # cualquier otro que quieras aislado, por nombre
```

El endpoint no está autenticado y solo lleva recuentos agregados — sin nombres de consulta, sin valores de registro, sin material de certificados. Lígalo a una dirección privada; por omisión es loopback. TLS no se ofrece aquí deliberadamente, ya que significaría enviar un certificado autofirmado a cada raspador para un endpoint que, de entrada, no debería ser alcanzable públicamente.

Se exponen 82 familias de métricas, todas con el prefijo `rolodex_dns_`, que cubren las consultas, el caché de respuestas, las listas de bloqueo (incluidos los rechazos y los proveedores sacados de rotación), los niveles upstream, el resolvedor iterativo, los veredictos DNSSEC, el estado del horizonte partido, DHCP, ACME, gRPC y el propio trabajo bloqueante del runtime.

La que conviene conocer es `rolodex_dns_answers_total{source}`, que informa de qué etapa del orden de resolución produjo cada respuesta — `cache`, `local`, `scoped`, `scope_fallback`, `tld_peer`, `blocklist`, `reverse_blocklist`, `dns64`, `upstream`, `authoritative_nxdomain`, `refused`, `error`. Su total es igual al total de consultas, que es lo que hace legible la tubería de horizonte partido desde fuera:

```
curl -s http://127.0.0.1:9153/metrics | grep answers_total
```

### Cardinalidad

La cardinalidad acotada es una restricción de diseño, porque un endpoint de métricas que un desconocido puede hacer crecer sin límite es un fallo de agotamiento de memoria disfrazado de monitorización. Cada etiqueta es o bien un enum fijo o bien está acotada por la configuración. Las dos dimensiones que un *cliente* podría inflar se pliegan ambas en un cajón de sastre:

| Dimensión | Cota | Cajón de sastre |
|-----------|-------|-----------|
| `qtype` | 23 tipos de registro conocidos | `OTHER` — una avalancha de consultas `TYPE4242` no acuña nada |
| `tld` | TLD propios, más `metrics.tracked_tlds` | `other` — un escáner barriendo TLD basura no acuña nada |

**Los nombres de consulta nunca son etiquetas.** Solo el sufijo de TLD, y solo cuando el operador ya ha optado por ese sufijo.

### Aislamiento por TLD

`rolodex_dns_queries_by_tld_total{tld}` desglosa el flujo de consultas por TLD, que es lo que hace separables entre sí, y del internet público, las redes de un despliegue de horizonte partido. Tres cosas alimentan el conjunto rastreado:

1. **Los TLD propios, automáticamente.** Todo TLD que posee un ámbito de red —incluido el dominio `.home` implícito de cada ámbito— se rastrea sin pedirlo. El espacio de nombres propio de una red es lo que más merece aislarse, y exigir nombrarlo dos veces (una para poseerlo, otra para rastrearlo) es una trampa que aparece como una serie ausente en silencio.
2. **La lista de configuración.** `metrics.tracked_tlds` en el YAML. La entrada `common` se expande al conjunto integrado de TLD comunes (`com.`, `net.`, `org.`, `io.`, `dev.`, …) para que los TLD públicos habituales sean una línea en vez de veinte. Las entradas de configuración están fijadas: sobreviven a los reinicios y no se pueden eliminar por la API.
3. **La lista almacenada.** Administrada en tiempo de ejecución, sin reinicio:

```bash
# Rastrea el conjunto común más un TLD excepcional
rolodex-dns-cli set-tracked-tlds --tld common --tld lab.internal

# Muestra los conjuntos almacenado, propio y efectivo
rolodex-dns-cli list-tracked-tlds

# Vacía la lista almacenada (los TLD propios y los fijados por configuración no se ven afectados)
rolodex-dns-cli set-tracked-tlds
```

El conjunto **efectivo** es la unión de los tres, y es el que realmente produce series — por eso ambas órdenes lo imprimen. La lista almacenada por sí sola no te dice qué series van a aparecer.

### DNS y DHCP se seleccionan por separado

DNS y DHCP son servicios distintos que da la casualidad de que comparten proceso, y sus series se mantienen aparte a propósito:

- Las familias de DHCP etiquetan sus dimensiones como **`message_type`** y **`lease_state`**, no como los genéricos `type` y `state`. Un nombre de etiqueta genérico es lo que hace que una agregación que abarque ambos subsistemas —un `sum by (type) (...)` en una regla de registro, digamos— mezcle en silencio un recuento de ACK de DHCP con uno de DNS.
- Los agregados de DNS (`queries_total`, `traffic_bytes_total`, `records_served_total`, `queries_by_tld_total`) cuentan **solo DNS**. Los paquetes DHCP en `:67` no se cuentan nunca como tráfico DNS, y un nombre registrado por DHCP contribuye a las métricas de DNS solo cuando alguien lo resuelve de verdad.

> **Nota de actualización:** `rolodex_dns_dhcp_messages_total{type}` pasó a ser `{message_type}` y `rolodex_dns_dhcp_leases{state}` pasó a ser `{lease_state}`. Los cuadros de mando y las alertas que seleccionan por los nombres de etiqueta antiguos hay que actualizarlos.

### Consultas comunes

```promql
# Tasa de consultas por transporte
sum by (proto) (rate(rolodex_dns_queries_total[5m]))

# Qué etapa del orden de resolución está respondiendo
sum by (source) (rate(rolodex_dns_answers_total[5m]))

# Proporción de NXDOMAIN sobre todas las respuestas
sum(rate(rolodex_dns_queries_total{rcode="NXDOMAIN"}[5m]))
  / sum(rate(rolodex_dns_queries_total[5m]))

# Ratio de aciertos del caché de respuestas
sum(rate(rolodex_dns_cache_hits_total[5m]))
  / (sum(rate(rolodex_dns_cache_hits_total[5m])) + sum(rate(rolodex_dns_cache_misses_total[5m])))

# Latencia de consulta p99 por transporte
histogram_quantile(0.99, sum by (le, proto) (rate(rolodex_dns_query_duration_seconds_bucket[5m])))
```

El volumen de tráfico, y cuánto de él son registros de verdad en vez de respuestas negativas:

```promql
# Bytes de cable entrantes y salientes
sum by (direction) (rate(rolodex_dns_traffic_bytes_total[5m]))

# Factor de amplificación: bytes emitidos por byte recibido. Un valor que sube en
# una escucha alcanzable públicamente es la forma de un ataque de reflexión.
sum(rate(rolodex_dns_traffic_bytes_total{direction="tx"}[5m]))
  / sum(rate(rolodex_dns_traffic_bytes_total{direction="rx"}[5m]))

# Registros devueltos por consulta — un millón de NXDOMAIN y un millón de
# respuestas pobladas son el mismo recuento de consultas y muy distinto trabajo.
sum(rate(rolodex_dns_records_served_total[5m]))
  / sum(rate(rolodex_dns_queries_total[5m]))
```

Listas de bloqueo — el par que importa es bloqueos contra rechazos, porque una lista que ha dejado de responder se ve idéntica a una limpia si solo se monitorea el contador de bloqueos:

```promql
# Bloqueos según qué lista casó
sum by (kind) (rate(rolodex_dns_blocklist_blocks_total[5m]))

# Proporción bloqueada de todo el tráfico
sum(rate(rolodex_dns_blocklist_blocks_total[5m]))
  / sum(rate(rolodex_dns_queries_total[5m]))

# Actividad de la lista de permitidos por camino de coincidencia. Que suba aquí
# significa que un operador está tapando sin parar una lista que se desmadra.
sum by (kind) (rate(rolodex_dns_blocklist_allowlisted_total[5m]))

# Un proveedor ha empezado a rechazarnos en vez de informar de reputación
sum by (kind) (rate(rolodex_dns_blocklist_refusals_total[5m])) > 0

# Proveedores actualmente fuera de rotación
rolodex_dns_blocklist_rotated_out > 0
```

Por TLD, salud del upstream y DNSSEC:

```promql
# Tasa de consultas por TLD rastreado, ignorando el cajón de sastre de los no rastreados
sum by (tld) (rate(rolodex_dns_queries_by_tld_total{tld!="other"}[5m]))

# Qué fracción del tráfico es para nombres que no rastreas
sum(rate(rolodex_dns_queries_by_tld_total{tld="other"}[5m]))
  / sum(rate(rolodex_dns_queries_by_tld_total[5m]))

# Degradado fuera del nivel iterativo (0=raíces, 1=seguro, 2=local, 3=público)
rolodex_dns_upstream_active_tier > 0

# Vaivén de niveles
sum by (direction) (rate(rolodex_dns_upstream_tier_switches_total[5m]))

# Datos firmados que no validaron: un ataque, o una zona que rompió su propia
# firma. Distinto de `indeterminate`, que es un fallo de red.
sum(rate(rolodex_dns_dnssec_verdicts_total{verdict="bogus"}[5m])) > 0

# Servidores raíz actualmente descartados por servir DNSSEC que no valida.
# Un valor no nulo y estable es una instancia raíz secuestrada o rota; todas ellas
# a la vez es el ancla de confianza o la zona raíz, no los servidores.
rolodex_dns_dnssec_blamed_roots > 0

# Remisiones descartadas por delegar fuera de la zona que responde
rate(rolodex_dns_resolver_out_of_bailiwick_total[5m]) > 0

# Búsquedas abortadas por el presupuesto de consultas por búsqueda
rate(rolodex_dns_resolver_budget_exhausted_total[5m]) > 0
```

DHCP, usando los nombres de etiqueta aislados:

```promql
# Concesiones por estado
rolodex_dns_dhcp_leases{lease_state="active"}

# Tasa de mensajes DHCP por tipo
sum by (message_type) (rate(rolodex_dns_dhcp_messages_total[5m]))

# Agotamiento del conjunto
rate(rolodex_dns_dhcp_allocation_failures_total[5m]) > 0
```

Plano de control y alcanzabilidad del equipo:

```promql
# Alguien está adivinando el secreto compartido de gRPC
rate(rolodex_dns_grpc_auth_failures_total[5m]) > 0

# Una familia de direcciones que el equipo no puede enrutar, así que sus registros se suprimen
rolodex_dns_address_family_reachable{family="ipv6"} == 0
```

Bloqueo del runtime — dónde hay trabajo síncrono ocupando hilos que deberían estar sirviendo consultas. `db_lock_wait` y `db_locked` son las dos mitades de la única conexión SQLite: el tiempo de espera es lo que te cuestan otros llamadores, el tiempo de tenencia es lo que tú les cuestas a ellos.

```promql
# Cuánto de cada segundo pasan bloqueados todos los workers en conjunto, por site.
# La única conexión SQLite es la respuesta habitual; `db_lock_wait` subiendo
# mientras `db_locked` sigue plano es contención, al revés son sentencias lentas.
sum by (site) (rate(rolodex_dns_blocking_duration_seconds_sum[5m]))

# Percentil 99 del tiempo en cola detrás de la única conexión a la base de datos
histogram_quantile(0.99, sum by (le) (rate(rolodex_dns_blocking_duration_seconds_bucket{site="db_lock_wait"}[5m])))

# Regiones de bloqueo que retuvieron un hilo 10ms o más. En un site de worker
# (db_locked, db_lock_wait, dnssec_verify, metrics_collect) estas son consultas
# que no se estaban sondeando.
sum by (site) (rate(rolodex_dns_blocking_stalls_total[5m]))

# Costo del scrape como fracción de su intervalo: /metrics compitiendo con la
# ruta de consulta por la misma conexión. Por encima de un pequeño porcentaje, amplía el intervalo.
rate(rolodex_dns_blocking_duration_seconds_sum{site="metrics_collect"}[5m])
  / rate(rolodex_dns_metrics_scrapes_total[5m])

# Tiempo medio de verificar las firmas de un RRset, sobre todo el juego de llaves candidatas
rate(rolodex_dns_blocking_duration_seconds_sum{site="dnssec_verify"}[5m])
  / rate(rolodex_dns_blocking_duration_seconds_count{site="dnssec_verify"}[5m])
```

Cada consulta de arriba está cubierta por una prueba que resuelve sus nombres de métrica y sus casadores de etiqueta contra la salida de exposición viva, así que una consulta documentada no puede referirse a una serie que no existe.

## Listas de bloqueo

Rolodex DNS bloquea nombres de dos maneras, y ambas responden a una consulta bloqueada con `NXDOMAIN`:

- **Proveedores DNSBL** — zonas de terceros consultadas por nombre, cubiertas en [DNSBL (Listas de bloqueo de dominios)](#dnsbl-listas-de-bloqueo-de-dominios) más abajo.
- **La lista local** — una tabla respaldada por la base de datos con nombres y direcciones que un operador bloqueó a mano.

Ambas están desactivadas/vacías por omisión: no se consulta nada externo y no se entrega ningún nombre a un operador de listas de bloqueo hasta que se agregan proveedores.

### Base de datos de bloqueo local

Las entradas locales son la lista propia del operador, revisada antes de consultar a proveedor alguno, y administrada con `AddLocalBlocklistEntry`, `RemoveLocalBlocklistEntry` y `ListLocalBlocklistEntries`.

Una entrada puede nombrar un **dominio**, casado en la compuerta del nombre directo, o una **dirección**, casada en una búsqueda inversa. Una dirección se puede escribir de cualquiera de las dos formas —como el literal, o como el nombre `in-addr.arpa`/`ip6.arpa` que imprime `dig -x`— y ambas grafías bloquean. Las direcciones solo las bloquea esta lista: a un proveedor se le pregunta por el nombre que se está resolviendo, y en una búsqueda inversa ese es un nombre del que nadie publica reputación.

```bash
# Bloquea una IP concreta con un motivo
rolodex-dns-cli add-local-blocklist --name 10.0.0.5 --reason "known spam source"

# Lista las entradas locales
rolodex-dns-cli list-local-blocklist

# Elimina una entrada
rolodex-dns-cli remove-local-blocklist --name 10.0.0.5
```

### Cacheado

- Los resultados positivos (el nombre está listado) se cachean durante el TTL que devolvió el proveedor
- Los resultados negativos (no listado) se cachean 5 minutos
- Los errores de búsqueda no se cachean y se tratan como «no listado», para evitar falsos positivos
- Los rechazos tampoco se cachean, y sacan al proveedor de la rotación — véase más abajo
- El caché se puede vaciar con el método gRPC `FlushCache`, que además devuelve a la rotación a todos los proveedores sacados de ella

### Códigos de rechazo y rotación de proveedores

Una DNSxL responde un listado y una queja sobre *ti* de la misma manera: un registro `A` bajo `127.0.0.0/8`. `zen.spamhaus.org` dice «listado» con `127.0.0.2` y «estás consultando a través de un resolvedor público» con `127.255.255.254`, y **solo la dirección los distingue**. Leer cualquier registro `A` como un listado convierte el momento en que una lista de bloqueo decide dejar de responderte en NXDOMAIN para *todos* los nombres revisados contra ese proveedor — y empieza cuando tu volumen de consultas cruza el umbral del proveedor, horas o semanas después de un despliegue que pintaba bien. Spamhaus lo dice directamente: esos códigos «NO deberían interpretarse como ninguna clase de reputación».

Así que cada proveedor lleva un conjunto de códigos de rechazo. Una respuesta que case es **`Refused`**: no es un listado, no es un negativo, no se cachea nada — no se aprendió nada sobre el nombre consultado. Un rechazo en cualquier parte de una respuesta gana sobre un listado en la misma respuesta, porque un proveedor que se está quejando no está informando de reputación al mismo tiempo, y equivocarse en esta dirección falla en *abierto* donde el orden contrario falla en cerrado para todos los nombres.

El conjunto integrado, usado cuando un proveedor no configura ninguno:

| Código | Significado |
| ---- | ------- |
| `127.255.255.0/24` | Rango de error de Spamhaus: `.252` errata en el nombre de zona, `.254` consulta a través de un resolvedor público/abierto, `.255` consultas excesivas. Un rango entero en vez de los tres códigos, porque Spamhaus lo reserva y va agregando |
| `127.0.1.255` | DBL de Spamhaus respondiendo a una consulta de IP — «consultas de IP no soportadas» |
| `127.0.2.255` | ZRD de Spamhaus respondiendo a una consulta de IP — lo mismo |
| `127.0.0.1` | «consulta bloqueada» de URIBL/SURBL. El RFC 5782 §5 además prohíbe que una DNSxL liste `127.0.0.1`, así que nunca es un listado legítimo |
| `127.0.0.255` | «consulta bloqueada» de URIBL (por encima de cuota) |

Cada entrada es una dirección IPv4 o `dirección/prefijo`. **Vacío significa el conjunto integrado** — no puede significar «sin códigos», porque vacío es lo que tiene toda configuración escrita antes de que existiera esta funcionalidad. La entrada única `none` desactiva la detección para una lista de bloqueo privada cuyos listados reales colisionen con alguno de los de arriba. Una lista explícita es exactamente esa lista; los valores por omisión no se fusionan, así que un operador que la deletrea también puede estrecharla. Un código no interpretable se rechaza —al arrancar, o con `InvalidArgument` desde el RPC— en vez de saltarse, ya que un código que en silencio no se aplica es un rechazo que se lee como un listado.

**Rotación.** Un rechazo saca al proveedor de la rotación de búsquedas durante `refusal_cooldown_secs` (3600 s por omisión, con sustitución por proveedor disponible), así que una lista de bloqueo que acaba de decirte que pares recibe un retroceso en vez de consultarse en cada petición. La rotación:

- se salta **solo las búsquedas nuevas** — los veredictos ya cacheados siguen contando, ya que «este proveedor no va a responder preguntas nuevas» no es «las respuestas que ya dio estaban mal»;
- **caduca sola**, así que un periodo transitorio por encima de cuota se cura sin acción del operador;
- se **limpia** con `flush-cache` y con cualquier `set-dnsbl-config` — una reconfiguración es a menudo el arreglo del rechazo (una errata en el nombre de zona es a la vez causa de un `127.255.255.252` y lo que se está corrigiendo);
- se **informa** con `get-dnsbl-config` y con `rolodex_dns_blocklist_refusals_total{kind}` / `rolodex_dns_blocklist_rotated_out`.

Poner un enfriamiento a `0` significa «usa el valor por omisión», no «sin enfriamiento» — un enfriamiento cero vuelve a preguntar al proveedor que acaba de decirte que pares, que es el comportamiento que la rotación existe para evitar.

## DNSBL (Listas de bloqueo de dominios)

Los proveedores DNSBL bloquean por **nombre de dominio**: las etiquetas del nombre consultado se anteponen a la zona del proveedor, así que `googleadservices.com` contra `dbl.spamhaus.org` se consulta como `googleadservices.com.dbl.spamhaus.org`. Así operan Spamhaus DBL, SURBL y URIBL.

DNSBL da a las listas de bloqueo **prioridad sobre el DNS externo**. La revisión se ejecuta después de los registros locales y de las zonas administradas/autoritativas —así que los datos internos siempre ganan— pero **antes** del caché de respuestas upstream y de cualquier resolución externa. Un nombre listado devuelve por tanto NXDOMAIN aunque antes se hubiera cacheado una respuesta reenviada para él.

DNSBL está desactivado por omisión con una lista de proveedores vacía, y los proveedores individuales se pueden activar o desactivar de forma independiente. Un DNSBL activado pero vacío no hace nada. Las zonas estándar que un operador suele agregar son `dbl.spamhaus.org`, `multi.surbl.org` y `multi.uribl.com`. Los resultados se cachean como arriba (los positivos durante el TTL del proveedor, los negativos 5 minutos).

```bash
rolodex-dns-cli set-dnsbl-config --enabled --providers dbl.spamhaus.org:true
rolodex-dns-cli get-dnsbl-config
```

### Poner una máquina en la lista de permitidos

La lista de permitidos es la salida de emergencia del operador ante un falso positivo, y cubre **todas las listas y ambas compuertas**: la revisión del nombre directo (proveedores DNSBL y lista de bloqueo local) *y* la revisión de DNS inverso/IP (entradas locales que nombran una dirección). Una IP listada por error rompe `dig -x` para una máquina que funciona bien, así que una salida de emergencia que solo llegara a los nombres no lo sería.

- **Los nombres se casan por sufijo.** Una entrada cubre el nombre y todos los que hay bajo él, así que permitir `example.com` exime también a `www.example.com`; la coincidencia es en límites de etiqueta, así que `notexample.com` no queda exento.
- **Una dirección se puede nombrar de cualquiera de las dos formas.** Una consulta inversa queda exenta con una entrada que nombre el nombre `in-addr.arpa`/`ip6.arpa` *o* el literal IP que codifica, así que nadie tiene que invertir octetos a mano. El **nombre** inverso se casa por sufijo como cualquier nombre DNS (permitir `1.168.192.in-addr.arpa` levanta el bloqueo de todo ese /24); el **literal** IP se casa de forma **exacta**, porque una dirección va con el octeto más significativo delante — `1.100` no es padre de `192.168.1.100`, y tratarlo como tal eximiría direcciones que nadie nombró.
- **Cortocircuita la revisión por completo.** Un nombre o dirección exento no se revisa contra ningún proveedor y no emite búsqueda alguna a las listas de bloqueo.
- Las entradas se normalizan (minúsculas, punto final), así que cualquier grafía agrega o elimina la misma entrada; persisten entre reinicios y surten efecto en la siguiente consulta sin necesidad de vaciar el caché.

```bash
# Exime a una máquina sobre la que un proveedor da un falso positivo
rolodex-dns-cli add-dnsbl-allow --name vendor.example.com --reason "blocklist false positive"

# Exime a una dirección — vale cualquiera de las dos grafías
rolodex-dns-cli add-dnsbl-allow --name 192.168.1.100 --reason "our own mail relay"
rolodex-dns-cli add-dnsbl-allow --name 1.168.192.in-addr.arpa --reason "whole /24"

# Lista la lista de permitidos
rolodex-dns-cli list-dnsbl-allow

# Elimina una entrada
rolodex-dns-cli remove-dnsbl-allow --name vendor.example.com
```

## Ámbitos de red

Los ámbitos de red proporcionan vistas DNS de horizonte partido, permitiendo respuestas DNS distintas según con qué ámbito de red esté asociada la IP de un cliente.

### Conceptos

- **Ámbito de red**: una vista DNS con nombre, con su propio conjunto de registros DNS y un dominio `.home` reservado (p. ej. `office.home.`). El dominio `.home` se usa como dominio de búsqueda por omisión para los clientes DHCP.
- **Asociación de red**: una correspondencia de una IP de cliente a un ámbito, con un TTL que hay que refrescar con regularidad. Cuando el TTL expira, la IP pierde su asociación de ámbito y las consultas DNS se rechazan.
- **Registros con ámbito**: registros DNS que pertenecen a un ámbito concreto y solo son visibles para las IP asociadas a ese ámbito.

### Cómo funciona

1. Crea un ámbito de red (p. ej. `"office"` con el dominio `"office.home."`)
2. Agrega registros DNS con ámbito al ámbito
3. Las IP de cliente se unen a la red asociándose con un ámbito (con un TTL)
4. Cuando llega una consulta DNS:
   - Si llegó por una **escucha de ingreso** por TLD: se sirve dentro del ámbito propietario de esa escucha, para todos los nombres
   - Si la IP de origen está asociada a un ámbito: se comprueban primero los registros con ámbito, luego se cae a los registros globales, luego se resuelve externamente
   - Si la IP de origen está dentro de `security.overlay_cidrs` (un par de superposición/WireGuard) pero no se ha unido a ámbito alguno: **REFUSED**
   - Cualquier otro origen —loopback, LAN, puentes de contenedores— es de confianza: no se rechaza nunca y resuelve el espacio de nombres global
   - Si no existe ámbito alguno: comportamiento heredado (todas las consultas se sirven desde los registros globales)
5. Los dominios de búsqueda (por `GetSearchDomains`) devuelven el dominio `.home` para la integración con DHCP

### Orígenes de confianza contra pares de superposición

La imposición de ámbito se aplica **solo** a las IP de origen que están dentro de `security.overlay_cidrs` (por omisión `10.64.0.0/10`, el rango de la superposición WireGuard). Un par así tiene que estar unido a una red o se le rechaza, y ve solo los TLD particionados de su propio ámbito. Cualquier otro origen es de confianza y resuelve la vista global.

Esto es lo que hace útil el horizonte partido en la práctica: un nombre puede llevar un registro global que apunta a la dirección de LAN de la máquina y un registro con ámbito que apunta a su dirección de superposición, y a cada lado se le entrega una dirección a la que realmente puede enrutar.

### Control de acceso a la recursión

La imposición de ámbito decide *qué vista* recibe un origen. Un eje aparte, `security.recursion_cidrs`, decide si un origen recibe **resolución upstream** siquiera.

`dns.bind` por omisión es `0.0.0.0:53`, así que en una interfaz enrutable la escucha es alcanzable desde todo internet, y todo origen fuera de `overlay_cidrs` se clasifica como cliente local de confianza. Sin una segunda revisión eso es un **resolvedor recursivo abierto** — el clásico activo de reflexión/amplificación, donde una consulta pequeña con origen falsificado devuelve una respuesta grande apuntada a la víctima falsificada y el tráfico de resolución saliente se le carga a tu máquina.

La lista por omisión es todo rango no enrutable desde internet — `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `::1/128`, `fe80::/10`, `fc00::/7` — que cubre loopback, la LAN, los puentes de contenedores y la superposición WireGuard (`10.64.0.0/10` está dentro de `10.0.0.0/8`), así que nada que usara legítimamente este servidor pierde servicio. Una lista vacía cierra la recursión a todo el mundo, dejando un servidor puramente autoritativo.

- **La revisión se sitúa en la frontera local/remoto**: después de todo camino que responde con datos que este servidor tiene, antes de todo camino que va a por datos que no tiene. Un desconocido sigue recibiendo tus respuestas autoritativas y tus NXDOMAIN autoritativos —cerrar la recursión no debe convertir la máquina en un agujero negro para sus propias zonas— pero no puede hacer que vaya a preguntar a otro.
- **Se ejecuta antes del caché de respuestas**, porque una respuesta cacheada amplifica exactamente igual de bien que una recién resuelta, y calentar el caché es cómo se monta el ataque.
- **El rechazo es REFUSED con la sección de respuesta vacía**, así que la réplica no es nunca mayor que la pregunta que la provocó.
- **Todos los transportes están sujetos a la compuerta** — UDP, TCP, DoT, DoQ y DoH (que sirve con información de conexión para que su dirección de par llegue a la clasificación; de lo contrario el `:443` reabriría lo que el `:53` cierra).

### TLD propios por red

Más allá de su dominio `.home` implícito, un ámbito puede poseer TLD adicionales que particionan el espacio de nombres entre redes. Cada TLD propio es **globalmente único** para un ámbito, y los nombres bajo él no se reenvían nunca upstream — un nombre sin coincidencia da un NXDOMAIN autoritativo, después de consultar opcionalmente los *reenviadores pares* del TLD (las direcciones de superposición de otros miembros Rolodex de la misma red).

- Para un **par de superposición**, los TLD propios están estrictamente particionados: resuelve el TLD de su propia red y recibe NXDOMAIN para el TLD de cualquier otro ámbito, así que los TLD de dos redes nunca son ambos resolubles desde un mismo extremo.
- Para un **origen local de confianza** (loopback/LAN), *todo* TLD propio resuelve desde su ámbito propietario, así que todos los TLD de red son visibles en la LAN. Los nombres con doble hogar siguen devolviendo su valor global de cara a la LAN; solo los nombres exclusivos del ámbito se sirven desde el ámbito.

Un ámbito puede por tanto existir puramente para poseer un TLD —marcándolo como particionado contra los pares y resoluble desde la LAN— sin llegar a ligar nunca una superposición a él.

```bash
# Registra un TLD propio para un ámbito
rolodex-dns-cli add-scope-tld -s office --tld office.
# Apunta los nombres sin coincidencia bajo él a otros miembros Rolodex de la red
rolodex-dns-cli set-scope-tld-forwarders -s office --tld office. -f 10.64.0.2:53
rolodex-dns-cli list-scope-tlds -s office
```

### Escuchas DNS de ingreso

Un TLD propio se puede registrar con una **IP de ingreso** local (`add-scope-tld --listen-ip`), típicamente la dirección de superposición propia de la red:

```bash
rolodex-dns-cli add-scope-tld -s office --tld office. --listen-ip 10.64.0.1
rolodex-dns-cli list-scope-tld-listeners -s office
```

Eso hace tres cosas:

1. **Liga una escucha DNS** (UDP + TCP) en esa IP, en `dns.ingress_listen_port` (53 por omisión). Las escuchas se vuelven a crear al arrancar a partir de la base de datos, y se desmontan cuando se elimina el último TLD que referencia la IP. Una ligadura que falla —el caso habitual al arrancar, cuando la interfaz de superposición todavía no existe— se reintenta en el siguiente registro en vez de recordarse como «ya está escuchando».
2. **Sirve la vista del ámbito propietario para todos los nombres.** La escucha es el resolvedor dedicado de esa red, así que una consulta que llega por ella pertenece al ámbito propietario sea cual sea el nombre: los TLD propios siguen particionados, y todo lo demás cae a la resolución global y a la resolución upstream — que es lo que permite a un par usarla como su resolvedor de uso general.
3. **Reescribe los nombres programados hacia la IP de ingreso.** Un nombre bajo el TLD que tiene un registro A/AAAA almacenado se responde con la IP de ingreso en vez de con su valor de backend almacenado, así que el controlador de ingreso de la red recibe el tráfico y enruta por Host/SNI. Esta parte sigue sujeta al nombre: un nombre de paso conserva su valor resuelto, el mismo nombre en la escucha principal de `:53` resuelve a su valor almacenado, y un nombre sin registro sigue devolviendo NXDOMAIN (sin síntesis de comodines).

### Orden de resolución (con ámbitos)

1. Interpretar el registro OPT de EDNS (negociación del tamaño de payload, bit DO para DNSSEC)
2. Revisar la lista de bloqueo local (para las consultas de DNS inverso)
3. Revisar el caché de respuestas DNS
4. Revisar los registros con ámbito del ámbito del cliente
5. Revisar los registros CNAME con ámbito
6. Revisar los registros DNAME con ámbito (reescritura de subárbol)
7. Revisar si el nombre está bajo una zona administrada con ámbito (NXDOMAIN autoritativo)
8. Revisar los registros globales de la base de datos
9. Revisar los registros CNAME globales
10. Revisar los registros DNAME globales (reescritura de subárbol)
11. Revisar los registros ANAME (resolver el alias en el ápice de la zona)
12. Revisar si el nombre está bajo una zona administrada global (NXDOMAIN autoritativo)
13. Revisar los registros comodín (`*.zone.`)
14. Revisar la lista de bloqueo local y los proveedores DNSBL (un nombre listado es NXDOMAIN, con prioridad sobre cualquier respuesta externa)
15. Imponer `security.recursion_cidrs` — un origen fuera de ella recibe REFUSED antes de que nada salga de la máquina
16. Resolver externamente según `resolution.mode` (con aleatorización de mayúsculas del QNAME si está activa, por proxy si está configurado), validando DNSSEC en el camino iterativo
17. Aplicar la síntesis DNS64 (si está activa y la consulta AAAA volvió vacía pero existe un registro A)
18. Cachear la respuesta (las respuestas bogus no se cachean nunca)
19. Aplicar el ajuste por deriva de TTL (si está configurado)
20. Descartar las respuestas A/AAAA de una familia de direcciones no enrutable (si `address_family.mode: auto`)

## Servidor DHCP

Rolodex DNS incluye un servidor DHCPv4 integrado con administración de direcciones IP y registro DNS automático. Está desactivado salvo que haya una sección `dhcp` en la configuración.

- **Conjuntos por ámbito.** Cada conjunto pertenece a un ámbito de red y define un único rango contiguo, pasarela, máscara de subred y servidores DNS. Cuando un conjunto se agota, la asignación falla — no hay agregación entre conjuntos. Las vinculaciones MAC-IP son pegajosas: la misma MAC recupera siempre la misma IP.
- **Registro DNS automático.** Un cliente que manda un nombre de host (opción 12) obtiene un registro A en `<hostname>.lan.<dhcp.tld>.` y un PTR `in-addr.arpa` correspondiente, ambos como registros con ámbito en el ámbito del conjunto. La concesión además se une al ámbito de red (`JoinNetwork`), así que el cliente ve de inmediato la vista de horizonte partido de esa red. Ambos registros se eliminan cuando la concesión se libera o expira.
- **Estados de la concesión.** `active`, `expired` (pasada su duración), `released` (el cliente la liberó) y `reclaimable` (pasado el `reclaim_timeout`, así que la IP se puede volver a entregar).
- **Entrega de certificados.** Los certificados se pueden entregar a los clientes mediante opciones DHCP específicas del lugar (códigos 224–254), configuradas por ámbito.
- **Barrido en segundo plano.** Cada `sweep_interval` segundos, las concesiones expiradas se retiran (eliminando sus registros DNS y su asociación de ámbito) y las concesiones pasado el `reclaim_timeout` liberan su IP.

```bash
# Un conjunto para el ámbito "office"
rolodex-dns-cli add-dhcp-pool -s office \
  --range-start 10.0.0.100 --range-end 10.0.0.200 \
  --gateway 10.0.0.1 --subnet-mask 255.255.255.0 --dns-servers 10.0.0.1

rolodex-dns-cli list-dhcp-pools -s office
rolodex-dns-cli list-dhcp-leases -s office
```

## Cliente Go

Se incluye una biblioteca cliente de Go en `go/` para el acceso programático a la API gRPC de Rolodex DNS. Se puede importar como dependencia de módulo Go.

### Instalación

```
go get gitea.com/town-os/rolodex-dns/go
```

### Conexión

El cliente admite dos transportes:

**TCP** (con autenticación por secreto compartido):

```go
client, err := rolodex_dns.Dial(ctx, "localhost:50051",
    rolodex_dns.WithAuthToken("my-secret"),
)
defer client.Close()
```

**Socket Unix** (autenticación omitida en el lado del servidor):

```go
client, err := rolodex_dns.Dial(ctx, "/var/run/rolodex-dns.sock",
    rolodex_dns.WithUnixSocket(),
)
defer client.Close()
```

### Opciones del cliente

| Opción | Descripción |
|--------|-------------|
| `WithAuthToken(token)` | Fija el secreto compartido que se manda con cada RPC para la autenticación por TCP. El servidor lo ignora en las conexiones por socket Unix. Por omisión: vacío (funciona si el servidor no tiene secreto configurado) |
| `WithUnixSocket()` | Marca la dirección como una ruta de socket de dominio Unix en vez de una dirección TCP. El servidor omite la autenticación en las conexiones por socket Unix |
| `WithGRPCDialOption(opt)` | Agrega una `grpc.DialOption` de bajo nivel (p. ej. para TLS o interceptores) |

### Métodos del cliente

Todos los métodos aceptan un `context.Context` para la cancelación y los plazos.

#### Administración de registros

| Método | Descripción |
|--------|-------------|
| `AddRecord(ctx, record) error` | Agrega un registro DNS |
| `RemoveRecord(ctx, name, opts) (uint32, error)` | Elimina registros DNS (devuelve cuántos se eliminaron) |
| `ListRecords(ctx, opts) ([]*DnsRecord, error)` | Lista/filtra registros DNS |

#### Reenviadores

| Método | Descripción |
|--------|-------------|
| `SetForwarders(ctx, forwarders) error` | Fija los reenviadores DNS upstream |
| `SetResolutionMode(ctx, mode) error` | Cambia el modo de resolución (`auto`, `recursive`, `forward`) en caliente |
| `GetResolutionMode(ctx) (string, error)` | Obtiene el modo actualmente en vigor |

#### Listas de bloqueo

| Método | Descripción |
|--------|-------------|
| `SetDnsblConfig(ctx, enabled, providers) error` | Configura los ajustes de DNSBL (lista de bloqueo de dominios) |
| `SetDnsblConfigWithRefusalCooldown(ctx, enabled, providers, secs) error` | Lo mismo, con la duración de salida de rotación para toda la lista de los proveedores que rechazan |
| `GetDnsblConfig(ctx) (*DnsblStatus, error)` | Obtiene la configuración DNSBL actual, los códigos de rechazo resueltos y los proveedores fuera de rotación |
| `FlushCache(ctx) error` | Vacía el caché de las listas de bloqueo y devuelve a la rotación a todos los proveedores sacados de ella |
| `AddLocalBlocklistEntry(ctx, entry) error` | Agrega una entrada a la lista de bloqueo local |
| `RemoveLocalBlocklistEntry(ctx, name) error` | Elimina una entrada de la lista de bloqueo local |
| `ListLocalBlocklistEntries(ctx) ([]*LocalBlocklistEntry, error)` | Lista las entradas de la lista de bloqueo local |
| `AddDnsblAllowlistEntry(ctx, entry) error` | Exime a un nombre (y a sus subdominios) de la revisión de listas de bloqueo |
| `RemoveDnsblAllowlistEntry(ctx, name) error` | Elimina una entrada de la lista de permitidos de DNSBL |
| `ListDnsblAllowlistEntries(ctx) ([]*DnsblAllowlistEntry, error)` | Lista las entradas de la lista de permitidos de DNSBL |

#### Ámbitos de red

| Método | Descripción |
|--------|-------------|
| `CreateNetworkScope(ctx, scope) error` | Crea un ámbito de red |
| `DeleteNetworkScope(ctx, name) error` | Elimina un ámbito y sus datos |
| `ListNetworkScopes(ctx) ([]*NetworkScope, error)` | Lista todos los ámbitos |
| `JoinNetwork(ctx, ip, scope, ttl) error` | Asocia una IP con un ámbito |
| `LeaveNetwork(ctx, ip) error` | Elimina la asociación de ámbito de una IP |
| `GetNetworkAssociations(ctx, scope) ([]*NetworkAssociation, error)` | Lista las asociaciones |
| `AddScopedRecord(ctx, scope, record) error` | Agrega un registro DNS con ámbito |
| `RemoveScopedRecord(ctx, scope, name, opts) (uint32, error)` | Elimina registros con ámbito |
| `ListScopedRecords(ctx, scope, opts) ([]*DnsRecord, error)` | Lista los registros con ámbito |
| `GetSearchDomains(ctx, ip) ([]string, error)` | Obtiene los dominios de búsqueda de una IP |
| `AddScopeTld(ctx, scope, tld) error` | Registra un TLD propio globalmente único para un ámbito |
| `AddScopeTldWithListener(ctx, scope, tld, listenIP) error` | Registra un TLD propio y liga una escucha DNS de ingreso |
| `RemoveScopeTld(ctx, scope, tld) error` | Elimina un TLD propio de un ámbito |
| `ListScopeTlds(ctx, scope) ([]string, error)` | Lista los TLD que posee un ámbito |
| `SetScopeTldForwarders(ctx, scope, tld, forwarders) error` | Fija los reenviadores pares de un TLD |
| `ListScopeTldForwarders(ctx, scope, tld) ([]string, error)` | Lista los reenviadores pares de un TLD |
| `ListScopeTldListeners(ctx, scope) ([]*TldListener, error)` | Lista las escuchas DNS de ingreso de un ámbito |

#### DHCP

| Método | Descripción |
|--------|-------------|
| `AddDhcpPool(ctx, pool) (string, error)` | Agrega un conjunto de direcciones DHCP para un ámbito |
| `RemoveDhcpPool(ctx, poolID) error` | Elimina un conjunto DHCP |
| `ListDhcpPools(ctx, scope) ([]*DhcpPool, error)` | Lista los conjuntos DHCP |
| `ListDhcpLeases(ctx, scope) ([]*DhcpLease, error)` | Lista las concesiones DHCP |
| `DeleteDhcpLease(ctx, mac) error` | Elimina una concesión DHCP por MAC |
| `SetDhcpCertOption(ctx, opt) error` | Entrega un certificado mediante una opción DHCP |
| `RemoveDhcpCertOption(ctx, scope, optionCode) error` | Elimina una opción DHCP de certificado |
| `ListDhcpCertOptions(ctx, scope) ([]*DhcpCertOption, error)` | Lista las opciones DHCP de certificado |

#### Zonas autoritativas

| Método | Descripción |
|--------|-------------|
| `AddAuthoritativeZone(ctx, zone) error` | Declara una zona como autoritativa |
| `RemoveAuthoritativeZone(ctx, zone) error` | Elimina una zona autoritativa |
| `ListAuthoritativeZones(ctx) ([]string, error)` | Lista las zonas autoritativas |

#### Caché

| Método | Descripción |
|--------|-------------|
| `GetCacheStats(ctx) (*CacheStats, error)` | Obtiene las estadísticas del caché (entradas, aciertos, fallos) |
| `FlushDnsCache(ctx) error` | Vacía el caché de respuestas DNS |

#### Transportes cifrados

| Método | Descripción |
|--------|-------------|
| `SetDotConfig(ctx, config) error` | Configura DNS-over-TLS |
| `GetDotConfig(ctx) (*DotConfig, error)` | Obtiene la configuración de DoT |
| `SetDohConfig(ctx, config) error` | Configura DNS-over-HTTPS |
| `GetDohConfig(ctx) (*DohConfig, error)` | Obtiene la configuración de DoH |
| `SetDoqConfig(ctx, config) error` | Configura DNS-over-QUIC |
| `GetDoqConfig(ctx) (*DoqConfig, error)` | Obtiene la configuración de DoQ |

#### Proxy

| Método | Descripción |
|--------|-------------|
| `SetProxyConfig(ctx, config) error` | Configura el proxy HTTP |
| `GetProxyConfig(ctx) (*ProxyConfig, error)` | Obtiene la configuración del proxy |

#### DNSSEC

| Método | Descripción |
|--------|-------------|
| `GenerateDnssecKey(ctx, zone, algorithm, keyType) (*DnssecKey, error)` | Genera un par de llaves DNSSEC |
| `ListDnssecKeys(ctx, zone) ([]*DnssecKey, error)` | Lista las llaves DNSSEC de una zona |
| `DeleteDnssecKey(ctx, keyID) error` | Elimina una llave DNSSEC |
| `GetDsRecords(ctx, zone) ([]string, error)` | Obtiene los registros DS para el registrador |
| `SignZone(ctx, zone) error` | Firma una zona con sus llaves |

#### DANE / ACME

| Método | Descripción |
|--------|-------------|
| `GenerateTlsaRecord(ctx, opts) (string, error)` | Genera un registro TLSA a partir de un certificado |
| `ListTlsaRecords(ctx, domain) ([]*DnsRecord, error)` | Lista los registros TLSA de un dominio |
| `GenerateDaneRootCa(ctx, name) (string, error)` | Genera una CA raíz DANE autofirmada |
| `RequestAcmeCert(ctx, domain, providerURL) error` | Solicita un certificado ACME DNS-01 |
| `GetAcmeStatus(ctx, domain) (*AcmeStatus, error)` | Obtiene el estado del certificado ACME |
| `EnsureZoneCa(ctx, zone) (*ZoneCa, error)` | Se asegura de que existe la CA intermedia de la zona |
| `CreateEabCredential(ctx, zone) (*EabCredential, error)` | Acuña una credencial EAB con ámbito de zona |
| `RemoveEabCredential(ctx, kid) error` | Elimina una credencial EAB |
| `ListAcmeAccounts(ctx) ([]*AcmeAccount, error)` | Lista las cuentas ACME registradas |
| `ListAcmeCertificates(ctx, zone) ([]*AcmeCertificate, error)` | Lista los certificados emitidos |

#### Deriva de TTL

| Método | Descripción |
|--------|-------------|
| `SetTtlDriftConfig(ctx, config) error` | Configura la deriva de TTL |
| `GetTtlDriftConfig(ctx) (*TtlDriftConfig, error)` | Obtiene la configuración de deriva de TTL |

#### DNS64

| Método | Descripción |
|--------|-------------|
| `SetDns64Config(ctx, config) error` | Configura la síntesis DNS64 |
| `GetDns64Config(ctx) (*Dns64Config, error)` | Obtiene la configuración de DNS64 |

#### Observabilidad

| Método | Descripción |
|--------|-------------|
| `GetQueryLatencyStats(ctx) ([]*QueryLatencyStats, error)` | Obtiene las estadísticas de latencia por servidor |
| `SetTrackedTlds(ctx, tlds) ([]string, error)` | Reemplaza la lista de TLD rastreados; devuelve el conjunto efectivo |
| `ListTrackedTlds(ctx) (*TrackedTlds, error)` | Obtiene los conjuntos de TLD almacenado, efectivo y propio |

#### Conexión

| Método | Descripción |
|--------|-------------|
| `Close() error` | Cierra la conexión gRPC |

### Tipos de registro

| Constante | Valor | Descripción |
|----------|-------|-------------|
| `RecordTypeA` | 0 | Dirección IPv4 (por omisión) |
| `RecordTypeAAAA` | 1 | Dirección IPv6 |
| `RecordTypeCNAME` | 2 | Alias de nombre canónico |
| `RecordTypeMX` | 3 | Intercambiador de correo (usa Priority) |
| `RecordTypeTXT` | 4 | Registro de texto |
| `RecordTypeNS` | 5 | Servidor de nombres |
| `RecordTypeSOA` | 6 | Inicio de autoridad |
| `RecordTypeSRV` | 7 | Localizador de servicio (usa Priority) |
| `RecordTypePTR` | 8 | Puntero para DNS inverso |
| `RecordTypeURI` | 9 | Registro de recurso URI (RFC 7553) |
| `RecordTypeSSHFP` | 10 | Huella SSH (RFC 4255) |
| `RecordTypeDNAME` | 11 | Nombre de delegación (RFC 6672) |
| `RecordTypeANAME` | 12 | Nombre alias (alternativa al CNAME en el ápice de la zona) |
| `RecordTypeZONEMD` | 13 | Resumen del mensaje de zona (RFC 9156) |
| `RecordTypeTLSA` | 14 | Asociación de certificado TLS (RFC 6698) |
| `RecordTypeDNSKEY` | 15 | Llave pública DNSSEC |
| `RecordTypeDS` | 16 | Firmante de delegación DNSSEC |
| `RecordTypeRRSIG` | 17 | Firma de registro de recurso DNSSEC |
| `RecordTypeNSEC` | 18 | Registro «siguiente seguro» de DNSSEC |
| `RecordTypeNSEC3` | 19 | Registro «siguiente seguro» v3 de DNSSEC |
| `RecordTypeNSEC3PARAM` | 20 | Parámetros NSEC3 de DNSSEC |
| `RecordTypeCERT` | 21 | Almacenamiento de certificados en el DNS (RFC 4398) |
| `RecordTypeSVCB` | 22 | Vinculación de servicio (RFC 9460); el tipo que usan las designaciones DDR |
| `RecordTypeHTTPS` | 23 | Forma SVCB específica de HTTPS (RFC 9460 §9) |

## Cumplimiento de RFC

| RFC | Nombre | Soporte |
|-----|------|---------|
| RFC 1034 / 1035 | Nombres de dominio — conceptos e implementación | Resolución iterativa desde los servidores raíz, seguimiento de delegaciones, manejo de NS con y sin glue |
| RFC 2308 | Cacheado negativo de consultas DNS | TTL negativo tomado como `min(SOA MINIMUM, SOA TTL)`, honrado tal como se publica |
| RFC 4033 / 4034 / 4035 | Protocolo, registros y modificaciones del protocolo DNSSEC | Firma de zonas (RRSIG sobre RRsets canónicos, roles KSK/ZSK, cálculo de DS) y validación del upstream (cadena de confianza desde la raíz, los cuatro veredictos, manejo de AD/DO). NSEC/NSEC3 se validan pero no se generan nunca |
| RFC 4255 | Registro DNS SSHFP | Completo (almacenamiento, búsqueda, algoritmo/tipo de huella) |
| RFC 4398 | Registro DNS CERT | Completo (almacenamiento, búsqueda, distribución de la cadena de CA PKIX) |
| RFC 4592 | Comodines en el DNS | Completo (sustitución de una sola etiqueta, prioridad de la coincidencia exacta) |
| RFC 5155 | Denegación autenticada troceada de DNSSEC (NSEC3) | Solo validación (encerrador más cercano, opt-out, techo de iteraciones según el RFC 9276); no se genera nunca |
| RFC 5782 | DNSBL | Completo (formato de consulta basado en nombres, proveedores locales + externos, `127.0.0.1` no se lee nunca como un listado) |
| RFC 6147 | DNS64 | Completo (síntesis AAAA a partir de registros A, prefijo configurable) |
| RFC 6605 / 8080 | ECDSA y Ed25519 para DNSSEC | Completo (firma y verificación; Ed448 no soportado por `ring`) |
| RFC 6672 | DNAME | Completo (reescritura de subárbol, no se aplica al nombre propietario) |
| RFC 6698 | DANE TLSA | Completo (generación, almacenamiento y resolución DNS de registros TLSA) |
| RFC 6840 | Aclaraciones de DNSSEC | Las respuestas con algoritmo no soportado se tratan como Insecure (§5.11); AD se pone solo para un cliente que lo pidió (§5.7) |
| RFC 6891 | EDNS(0) | Completo (registro OPT, negociación de payload, bit DO, BADVERS). Las consultas iterativas salientes llevan DO con un payload de 1232 bytes cuando se valida |
| RFC 7553 | Registro DNS URI | Completo (almacenamiento y búsqueda) |
| RFC 7766 | Transporte DNS sobre TCP | Reutilización de conexión con un tiempo de espera de inactividad medido desde la última actividad, encuadre de longitud de 2 bytes, tope de conexiones por escucha |
| RFC 7858 | DNS-over-TLS | Completo (TCP envuelto en TLS, puerto 853) — escucha del servidor y cliente upstream |
| RFC 8484 | DNS-over-HTTPS | Completo (GET + POST, application/dns-message, Cache-Control) — escucha del servidor y cliente upstream |
| RFC 8555 | ACME | Lado servidor (autoridad de certificación integrada, autovalidación dns-01, EAB) |
| RFC 9250 | DNS-over-QUIC | Completo (transporte QUIC, flujos bidireccionales) |
| RFC 9276 | Guía de parámetros de NSEC3 | Los recuentos de iteración por encima de 100 se tratan como inseguros en vez de calcularse |

## Arquitectura

```
                                 ┌──────────────┐
                                 │  DNS Clients  │
                                 └──────┬───────┘
                                        │
            ┌───────────────────────────┼───────────────────────────┐
            │                           │                           │
     ┌──────▼───────┐           ┌──────▼───────┐           ┌──────▼───────┐
     │  DNS Server   │           │   DoT Server  │           │  DoH Server   │
     │  (UDP + TCP)  │           │  (TLS :853)   │           │ (HTTPS :443)  │
     └──────┬───────┘           └──────┬───────┘           └──────┬───────┘
            │                           │                           │
            │    ┌──────────────────────┘          ┌───────────────┘
            │    │    ┌────────────────────────────┘
            │    │    │    ┌──────────────┐
            │    │    │    │  DoQ Server   │
            │    │    │    │ (QUIC :8853)  │
            │    │    │    └──────┬───────┘
            ▼    ▼    ▼          ▼
     ┌────────────────────────────────┐
     │        Resolution Engine       │
     │  (EDNS, Cache, Wildcards,      │
     │   DNAME, ANAME, DNS64)         │
     └──────────────┬─────────────────┘
                    │
       ┌────────────┼────────────┬───────────────┐
       │            │            │               │
 ┌─────▼────┐ ┌────▼────┐ ┌────▼──────────┐ ┌──▼───────┐
 │ Local DB  │ │ DNSBL   │ │   Upstream     │ │  DNSSEC  │
 │ (SQLite)  │ │ Checker │ │   Resolution   │ │ Signing  │
 └──────────┘ └─────────┘ └────┬──────────┘ └──────────┘
       │                        │
       │        ┌───────────────┼───────────┬────────────┐
       │        │               │           │            │
       │  ┌────▼─────┐  ┌──────▼─────┐ ┌──▼──────┐ ┌───▼──────┐
       │  │ Iterative │  │ DoH / DoT  │ │Forwarder│ │  Public  │
       │  │ from roots│  │  upstream  │ │ (Do53)  │ │  (Do53)  │
       │  └────┬─────┘  └────────────┘ └─────────┘ └──────────┘
       │       │  (tier 0)     (tier 1)   (tier 2)    (tier 3)
       │  ┌────▼──────────────┐   ┌────────────────────┐
       │  │ Delegation cache   │   │ DNSSEC validation  │
       │  │ + record cache     │◄──┤ (chain from root)  │
       │  └───────────────────┘   │  + key cache       │
       │                           └────────────────────┘
       │
 ┌─────▼──────┐   ┌────────────┐   ┌─────────────┐   ┌────────────┐
 │ gRPC Mgmt   │   │ HTTP Proxy │   │ DHCPv4 + AF │   │ ACME + CA  │
 │ (TCP/Unix)  │   │ (optional) │   │    probe    │   │  (portal)  │
 └─────────────┘   └────────────┘   └─────────────┘   └────────────┘
```

Orden de resolución (cuando no hay ámbitos de red configurados):
1. Interpretar el registro OPT de EDNS (tamaño de payload, bit DO)
2. Revisar la lista de bloqueo local (para las consultas de DNS inverso)
3. Revisar el caché de respuestas DNS
4. Revisar la base de datos local (horizonte partido, siempre preferida)
5. Buscar registros CNAME en la base de datos local
6. Buscar registros DNAME (reescritura de subárbol)
7. Revisar los registros ANAME (resolución del alias en el ápice de la zona)
8. Si el nombre está bajo una zona administrada pero no se encuentra, devolver NXDOMAIN autoritativo
9. Revisar los registros comodín
10. Revisar la lista de bloqueo local y los proveedores DNSBL (NXDOMAIN si está listado, por delante de cualquier respuesta externa)
11. Imponer `security.recursion_cidrs` — un origen fuera de ella recibe REFUSED antes de que nada salga de la máquina
12. Resolver externamente según `resolution.mode` (mayúsculas del QNAME aleatorizadas si está activo, por proxy si está configurado), validando DNSSEC en el camino iterativo
13. Aplicar la síntesis AAAA de DNS64 (si está activa y procede)
14. Cachear la respuesta (las respuestas bogus no se cachean nunca)
15. Aplicar el ajuste por deriva de TTL (si está configurado)
16. Descartar las respuestas A/AAAA de una familia de direcciones que el equipo no puede enrutar (si `address_family.mode: auto`)

Cuando hay ámbitos de red configurados, véase [Ámbitos de red](#ámbitos-de-red) para el orden de resolución extendido.

## Licencia

Este proyecto está licenciado bajo la GNU Affero General Public License v3.0 (AGPL-3.0). Véase el archivo [LICENSE](LICENSE) para el texto completo de la licencia.
