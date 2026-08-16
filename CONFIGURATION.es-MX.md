# Guía de configuración de Rolodex DNS

> Idiomas: [English](CONFIGURATION.md) | [繁體中文](CONFIGURATION.zh-TW.md) | [简体中文](CONFIGURATION.zh-CN.md) | [Español (España)](CONFIGURATION.es-ES.md) | **Español (México)** | [日本語](CONFIGURATION.ja-JP.md)

Este es un recorrido orientado a tareas: cómo conseguir un servidor que funcione y, después, cómo encender cada subsistema y por qué querrías hacerlo. Para la lista exhaustiva de campos, consulta [Opciones de configuración](README.es-ES.md#opciones-de-configuración) en el README.

- [Cómo se carga la configuración](#cómo-se-carga-la-configuración)
- [La configuración mínima que funciona](#la-configuración-mínima-que-funciona)
- [Direcciones de escucha](#direcciones-de-escucha)
- [Formas de despliegue](#formas-de-despliegue) — cuatro ejemplos resueltos
- [Subsistemas](#subsistemas) — una sección para cada uno
- [En caliente contra reinicio](#en-caliente-contra-reinicio)
- [Con qué se niega a arrancar el servidor](#con-qué-se-niega-a-arrancar-el-servidor)
- [Resolución de problemas](#resolución-de-problemas)

## Cómo se carga la configuración

El servidor lee un único archivo YAML, `rolodex-dns.yml` por omisión:

```bash
rolodex-dns                        # lee ./rolodex-dns.yml
rolodex-dns -c /etc/rolodex-dns/config.yml
```

**Que falte el archivo no es un error.** El servidor registra `No config file found, using defaults` y arranca con los valores por omisión integrados, que son una configuración real y usable: DNS en `0.0.0.0:53`, resolución iterativa desde las raíces con validación DNSSEC, gRPC en *loopback* y en un socket Unix, listas de bloqueo desactivadas y transportes cifrados desactivados.

Toda sección es opcional y todo campo dentro de ella tiene un valor por omisión, así que un archivo de configuración solo tiene que nombrar lo que estás cambiando. Las secciones cuya *presencia* es el interruptor —`dot`, `doh`, `doq`, `proxy`, `dhcp`, `acme`, `metrics`— no arrancan nada cuando se omiten.

El registro se controla con la variable de entorno `RUST_LOG`, no con el archivo de configuración:

```bash
RUST_LOG=rolodex_dns=debug rolodex-dns -c /etc/rolodex-dns/config.yml
```

## La configuración mínima que funciona

```yaml
database_path: /var/lib/rolodex-dns/rolodex-dns.db

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"

grpc:
  unix_socket: /var/run/rolodex-dns.sock
  tcp_bind: ""          # administrar solo por el socket
```

Eso es un resolvedor recursivo validador con una base de datos local de registros. Agrega registros por el socket:

```bash
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-record \
  --name nas.example.com --record-type a --value 192.168.1.10
```

El puerto 53 requiere privilegios. Para desarrollo usa un puerto alto —`make dev` corre en `127.0.0.1:5300` mediante `dev.yml`— y en producción dale al binario `CAP_NET_BIND_SERVICE` o haz que lo enlace tu administrador de servicios en lugar de ejecutarlo como root.

## Direcciones de escucha

En todos los lugares donde se acepta una dirección (`dns.bind`, `dot.bind`, `doh.bind`, `doq.bind`, `grpc.tcp_bind`, `dhcp.bind`, `acme.bind`, `acme.portal_bind`, `metrics.bind`) se admiten cuatro formas:

(`dns.bind` toma una lista de pares protocolo/dirección, y `dot.bind`, `doh.bind` y `doq.bind` toman **o una dirección o una lista** — una lista es como una escucha cubre ambas familias de direcciones, ya que `0.0.0.0` es solo IPv4 y un socket `[::]` choca con él en el mismo puerto. Los demás toman una sola dirección.)

| Forma | Ejemplo | Resultado |
| ----- | ------- | --------- |
| `ip:puerto` | `192.168.1.1:53` | Un *listener* en esa dirección |
| `[ipv6]:puerto` | `[::1]:53` | Un *listener*; los corchetes son obligatorios |
| `primary:puerto` | `primary:53` | La IP de salida de la ruta por omisión del sistema, detectada al arrancar |
| `interfaz:puerto` | `eth0:53` | **Un *listener* por cada IP de esa interfaz** |

`primary` se resuelve con un *connect* UDP que no envía nada hacia `8.8.8.8:53`: le pregunta a la tabla de ruteo qué dirección de origen se usaría, y no manda nada. `interfaz:puerto` se expande a todas las direcciones asignadas a la interfaz, así que `eth0:53` en un host de doble pila crea dos *listeners*.

`dns.bind` es una lista de mapas de una sola llave, porque un *listener* es un protocolo *y* una dirección:

```yaml
dns:
  bind:
    - udp: "eth0:53"
    - tcp: "eth0:53"
    - udp: "127.0.0.1:53"
    - tcp: "127.0.0.1:53"
```

Los enlaces basados en interfaz se resuelven **al arrancar**, y no se vuelven a resolver después. Una interfaz que gana una dirección después del arranque (un túnel WireGuard que se levanta, pongamos) no se recoge hasta reiniciar, que es exactamente el motivo por el que los *listeners* de ingreso por TLD se pueden volver a registrar en caliente; véase [TLD propios e ingreso](#tld-propios-e-ingreso).

## Formas de despliegue

### 1. Resolvedor casero o de oficina pequeña

Validador, bloqueando publicidad y *malware*, sirviendo unos cuantos nombres locales, alcanzable solo desde la LAN.

```yaml
database_path: /var/lib/rolodex-dns/rolodex-dns.db

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"
  auto_ptr: true                # mantiene los PTR inversos al paso de los A/AAAA

resolution:
  mode: auto                    # primero las raíces, luego cifrado, luego el resolvedor del ISP

dnssec:
  validate: true                # es el valor por omisión; se pone aquí porque importa

dnsbl:
  enabled: true
  providers:
    - zone: dbl.spamhaus.org
      enabled: true

security:
  # el valor por omisión ya cubre RFC 1918; acótalo si tu LAN es un subconjunto
  recursion_cidrs: ["127.0.0.0/8", "192.168.0.0/16", "::1/128"]

grpc:
  unix_socket: /var/run/rolodex-dns.sock
  tcp_bind: ""

metrics:
  bind: "127.0.0.1:9153"
```

Notas sobre las decisiones: `resolution.mode: auto` significa que ningún tercero ve tus consultas mientras las raíces sean alcanzables, y la resolución sigue sobreviviendo a una red que filtra el `:53`. `recursion_cidrs` es lo que impide que un enlace a `0.0.0.0:53` sea un resolvedor abierto: la lista por omisión ya es segura, y acotarla a tus propios rangos es un refinamiento, no un requisito.

### 2. Servidor puramente autoritativo

Ninguna resolución ascendente: toda respuesta sale de la base de datos local, y lo que no se encuentra es un NXDOMAIN autoritativo.

```yaml
database_path: /var/lib/rolodex-dns/auth.db

forwarders: []
resolution:
  mode: forward                 # modo forward sin reenviadores = sin nada aguas arriba

dnssec:
  validate: false               # nada se resuelve aguas arriba, así que no hay nada que validar

security:
  recursion_cidrs: []           # por si acaso: recursión cerrada a todo el mundo

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"
```

`forwarders: []` con `mode: forward` es el interruptor. `recursion_cidrs: []` es redundante con él, pero documenta la intención y además cierra las rutas del proveedor de listas de bloqueo y del calentamiento de caché.

Declara las zonas de las que eres autoritativo, para que un fallo dentro de ellas sea NXDOMAIN en vez de una búsqueda que no lleva a ninguna parte:

```bash
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-auth-zone --zone example.com.
```

(Cualquier zona que *ya tenga* registros se trata como autoritativa automáticamente; véase [Zonas administradas y zonas autoritativas](#zonas-administradas-y-zonas-autoritativas)).

### 3. Nodo de superposición con horizonte dividido (la forma de Town OS)

La máquina está en una LAN y en una superposición WireGuard. Los pares de la superposición se reparten en ámbitos de red; la LAN lo ve todo.

```yaml
database_path: /var/lib/rolodex-dns/rolodex-dns.db

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"
  ingress_listen_port: 53

security:
  overlay_cidrs: ["10.64.0.0/10"]     # estos orígenes están sujetos a ámbito
  recursion_cidrs:                    # estos orígenes pueden resolver aguas arriba
    - "127.0.0.0/8"
    - "10.0.0.0/8"                    # incluye la superposición
    - "192.168.0.0/16"
    - "::1/128"

grpc:
  unix_socket: /var/run/rolodex-dns.sock
  tcp_bind: ""
```

Las dos listas de CIDR responden a **preguntas distintas** y están pensadas para fijarse de forma independiente:

- `overlay_cidrs` — «¿quién está sujeto a ámbito?» Un origen dentro de ella tiene que haberse unido a una red (`JoinNetwork`) o recibe REFUSED, y solo ve los TLD de su propio ámbito.
- `recursion_cidrs` — «¿quién puede hacer que este servidor pregunte a otro?» Un origen fuera de ella sigue obteniendo tus datos autoritativos; sencillamente no puede provocar una búsqueda aguas arriba.

Después construye los ámbitos en caliente, no en el archivo de configuración: viven en la base de datos.

```bash
CLI="rolodex-dns-cli -u /var/run/rolodex-dns.sock"
$CLI create-scope --name office                       # implica office.home.
$CLI add-scope-tld -s office --tld office. --listen-ip 10.64.0.1
$CLI add-scoped-record -s office --name git.office. --record-type a --value 10.64.0.5
$CLI join-network --ip 10.64.0.7 --scope office --ttl 300
```

### 4. Resolvedor en una red hostil o filtrada

Algunas redes descartan el `:53` saliente y hacen DPI del saludo DoT en `:853`. La cadena `auto` está construida para esto, y lo único que merece la pena cambiar es qué *upstreams* cifrados usa:

```yaml
resolution:
  mode: auto
  secure_upstreams:
    - transport: https            # DoH en :443 — parece HTTPS corriente
      addr: "1.1.1.1:443"         # se marca por IP, así que no necesita DNS previo
      hostname: cloudflare-dns.com
      path: /dns-query
    - transport: https
      addr: "8.8.8.8:443"
      hostname: dns.google
      path: /dns-query
  switch_grace_failures: 3        # consultas desviadas antes de consolidar una degradación
  recovery_probe_secs: 60         # cada cuánto una cadena degradada reintenta el nivel superior
```

Los *upstreams* seguros se marcan por **IP** y el certificado se valida contra `hostname`, de modo que el nivel arranca sin DNS propio. Ten en cuenta que una cadena `auto` degradada más allá del nivel 0 **no** está validada por DNSSEC (una respuesta reenviada es el resumen de otro), y lo dice dejando AD sin marcar.

## Subsistemas

### Resolución ascendente

```yaml
forwarders:                       # el nivel "local", y el único upstream en modo forward
  - "8.8.8.8:53"
  - "8.8.4.4:53"

resolution:
  mode: auto                      # auto | recursive | forward
  root_hints: []                  # sustituye las raíces IANA integradas
  public_fallback: ["1.1.1.1:53", "8.8.8.8:53"]
  delegation_persist_min_ttl: 300 # persiste delegaciones aprendidas por encima de este TTL
  default_ttl: 300                # se usa SOLO donde nada trae un TTL
```

| Modo | Úsalo cuando |
| ---- | ------------ |
| `auto` (por omisión) | Quieres privacidad ante todo, pero la resolución tiene que sobrevivir a una red filtrada |
| `recursive` | Quieres las raíces o nada: jamás se contacta con un resolvedor ascendente |
| `forward` | Quieres un reenviador simple (o, con `forwarders: []`, nada aguas arriba) |

**El `mode` de aquí es la semilla de arranque, no el ajuste en vigor.** Se lee una
vez al arrancar; a partir de ahí el modo es el que `SetResolutionMode` fijó por
última vez, y `GetResolutionMode` informa del que de verdad está resolviendo
consultas — así que los dos pueden discrepar, y manda el servidor en marcha.
`rolodex-dns-cli set-resolution-mode -m <modo>` / `get-resolution-mode` son esas dos
mismas llamadas desde la consola. Cambiar el archivo y reiniciar también funciona,
pero reiniciar el único resolvedor de una máquina es una caída de DNS para todo lo que
hay en ella, que es justo la razón de que exista la RPC. A diferencia del archivo, la
RPC **rechaza** un modo no reconocido en lugar de avisar y caer a `auto`.

`default_ttl` es un **valor de reserva, no un suelo**. Un TTL que viene presente se respeta exactamente como se envió, incluido el TTL negativo del SOA de una zona. Si lo que buscas es acortar o alargar TTL en vivo, eso es la [deriva de TTL](#dns64-deriva-de-ttl-familia-de-direcciones), no esto.

### DNSSEC

Dos mitades independientes. La **validación** está activada por omisión y no necesita configuración:

```yaml
dnssec:
  validate: true
  trust_anchors: []        # vacío = las llaves raíz de IANA
```

Se aplica solo a la ruta iterativa (modo `recursive`, y el nivel de raíces de `auto`), así que no hace nada en modo `forward`. Los datos espurios se convierten en SERVFAIL y nunca se cachean. Desactívala solo si tienes un motivo concreto: un *upstream* roto que no puedes arreglar, o una jerarquía privada que aún no has anclado.

`trust_anchors` toma la forma de presentación DNSKEY, los cuatro campos RDATA tal como los imprime `dig DNSKEY .`, y una sustitución **reemplaza** las llaves de IANA en lugar de sumarse a ellas:

```yaml
dnssec:
  trust_anchors:
    - "257 3 15 <llave en base64>"     # una raíz privada; IANA NO se confía también
```

Un anclaje malformado hace fallar el arranque en lugar de recaer en IANA: un anclaje que no puede casar con un DNSKEY real hace que toda zona firmada falle sin que nada señale al anclaje como la causa.

La **firma** no se configura en YAML en absoluto; es una operación en caliente sobre una zona:

```bash
CLI="rolodex-dns-cli -u /var/run/rolodex-dns.sock"
$CLI generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type KSK
$CLI generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type ZSK
$CLI sign-zone --zone example.com.
```

Vuelve a ejecutar `sign-zone` después de cambiar registros. Las firmas se reemplazan, no se acumulan. RSA (algoritmo 8) se rechaza en la generación de llaves —`ring` no puede generar llaves RSA— y la denegación autenticada (NSEC/NSEC3) se valida pero nunca se genera.

### Seguridad: las dos listas de CIDR

```yaml
security:
  qname_case_randomization: true      # codificación 0x20 en las consultas reenviadas
  overlay_cidrs: ["10.64.0.0/10"]     # orígenes sujetos a ámbito
  recursion_cidrs: [ ... ]            # orígenes con permiso para resolver aguas arriba
```

Confundir estas dos es el error de configuración más habitual, así que, sin rodeos:

| | `overlay_cidrs` | `recursion_cidrs` |
| --- | --- | --- |
| Pregunta | ¿Qué *vista* recibe este origen? | ¿Puede este origen hacernos preguntar aguas arriba? |
| Dentro de la lista | Debe haberse unido a una red, o REFUSED; ve solo su ámbito | Puede provocar resolución ascendente |
| Fuera de la lista | Origen local de confianza; espacio de nombres global | Sigue recibiendo respuestas locales/autoritativas; REFUSED para cualquier cosa fuera de la máquina |
| Por omisión | `10.64.0.0/10` | *loopback*, RFC 1918, enlace local, ULA, CGNAT |

Deja `recursion_cidrs` en paz salvo que la estés *acotando*. Ensancharla hacia la internet pública convierte la máquina en un resolvedor abierto, que es un activo de reflexión/amplificación tanto si alguien está abusando de él ahora mismo como si no.

`qname_case_randomization` debería quedarse activado. Desactívalo solo para un *upstream* que normaliza el uso de mayúsculas de la pregunta que devuelve: de lo contrario ese resolvedor fallará todas las consultas, porque la comparación de mayúsculas y minúsculas es lo que hace que 0x20 defienda algo de verdad.

### Listas de bloqueo (DNSBL)

**DNSBL bloquea por nombre**, y se revisa antes de cualquier resolución externa. Viene desactivada por omisión con la lista de proveedores vacía, así que no se consulta nada y ningún nombre llega a manos del operador de una lista de bloqueo hasta que agregas proveedores.

```yaml
dnsbl:
  enabled: true
  refusal_cooldown_secs: 3600
  providers:
    - zone: dbl.spamhaus.org
      enabled: true
```

Las direcciones las bloquea la **lista local**, no un proveedor: a un proveedor se le pregunta por el nombre que se está resolviendo, y en una búsqueda inversa ese es un nombre del que nadie publica reputación. Mira las entradas locales más abajo.

Tres cosas que conviene saber antes de encenderlas:

1. **Los registros locales siempre ganan.** Una lista de bloqueo se ejecuta después de los registros locales y las zonas administradas, así que un listado de terceros nunca puede tumbar un servicio interno. Se ejecuta *antes* que el caché de respuestas y que el resolvedor, así que un listado surte efecto incluso para un nombre que se cacheó antes.
2. **El bloqueo es por nombre consultado, no por sufijo.** Que `doubleclick.net` esté listado no bloquea `stats.g.doubleclick.net`: el proveedor tiene que listarlo también. La lista de permitidos *sí* casa por sufijo, porque una vía de escape que se dejara los subdominios no lo sería.
3. **Los códigos de rechazo importan a volumen.** Una lista de bloqueo te dice «has superado tu cuota» con el mismo tipo de registro `A` que usa para «listado». La administración de rechazos está activada por omisión con un conjunto de códigos integrado; la única razón para configurar `refusal_codes` es una lista de bloqueo privada cuyos listados reales colisionen con uno (`refusal_codes: ["none"]`), o el deseo de acotar el conjunto. Véase [Códigos de rechazo y rotación de proveedores](README.es-ES.md#códigos-de-rechazo-y-rotación-de-proveedores).

Las entradas locales y la lista de permitidos son estado en caliente, no configuración:

```bash
CLI="rolodex-dns-cli -u /var/run/rolodex-dns.sock"
$CLI add-local-blocklist --name 10.0.0.5 --reason "known spam source"
$CLI add-dnsbl-allow --name vendor.example.com --reason "false positive"
$CLI add-dnsbl-allow --name 192.168.1.100 --reason "our own relay"   # una IP también vale
```

### Zonas administradas y zonas autoritativas

No hay lista de zonas en el archivo de configuración. Una zona pasa a ser autoritativa de una de dos maneras:

- **Implícitamente**, por tener registros. Cualquier registro en cualquier punto de la zona convierte a este servidor en autoritativo para toda ella, así que agregar `foo.example.com` como sustitución local significa que `www.example.com` responde NXDOMAIN en vez de resolverse desde internet. Ese es el trato del horizonte dividido, y merece la pena ser deliberado al respecto: sustituye un dominio público solo cuando pretendas poseerlo.
- **Explícitamente**, con `add-auth-zone`, que es como reclamas una zona que aún no tiene registros, o una zona inversa (la regla implícita se salta a propósito `in-addr.arpa`/`ip6.arpa`, ya que ahí la heurística reclamaría el árbol inverso global entero).

### Transportes cifrados

La presencia de cada sección es el interruptor, y cada una necesita material TLS:

```yaml
dot:
  bind: "0.0.0.0:853"
  tls:
    cert_path: /etc/rolodex-dns/cert.pem
    key_path: /etc/rolodex-dns/key.pem
    auto_self_signed: false

doh:
  bind: "0.0.0.0:443"
  tls: { cert_path: /etc/rolodex-dns/cert.pem, key_path: /etc/rolodex-dns/key.pem, auto_self_signed: false }
  enable_h3: false

doq:
  bind: "0.0.0.0:8853"
  tls:
    auto_self_signed: true            # aceptable en una red de confianza
    self_signed_sans:                 # los nombres por los que la LAN marca este equipo
      - dns.home
      - town-os.local
```

`auto_self_signed: true` (el valor por omisión) genera un certificado al arrancar si no hay ninguno configurado, lo cual es cómodo en una red de confianza.

**Un certificado renovado no necesita reinicio.** Un *listener* configurado con `cert_path`/`key_path` vuelve a leer esos archivos cada 30 segundos y empieza a servir el par nuevo dentro de esa ventana: las conexiones ya abiertas terminan bajo el certificado con el que hicieron el saludo, y la siguiente en llegar recibe el nuevo. No hay nada que señalizar ni nada que coordinar con quien escribe los archivos: un sondeo que caiga entre las dos escrituras de un cliente ACME ve una llave que no corresponde al certificado, lo rechaza, sigue sirviendo el par antiguo y reintenta en el siguiente tic. Un certificado generado (`auto_self_signed`) no se sondea: no hay archivo detrás de él, y regenerarlo por temporizador entregaría a cada cliente un certificado distinto dos veces por minuto.

**Se puede nombrar un certificado que todavía no se ha emitido.** Apuntar `cert_path`/`key_path` a un archivo que no existe nada más es una falla dura cuando `auto_self_signed` está apagado. Con él prendido, la escucha arranca con material generado y el sondeo de arriba adopta el par real en cuanto aterriza. Eso es lo que permite escribir estas rutas antes de que haya corrido lo que emite el certificado — el caso corriente en una máquina cuya CA se crea después de que arranque el resolvedor, donde la alternativa es reiniciar el único resolvedor de la máquina una vez que el archivo existe.

**DoT, DoH y DoQ se reconfiguran en tiempo de ejecución**, con `SetDotConfig` / `SetDohConfig` / `SetDoqConfig`. Las direcciones de ligadura, las rutas del certificado y la lista de SAN pueden cambiarse en un servidor en marcha, y `Get*Config` informa de lo que está realmente ligado. El YAML de abajo es la configuración de arranque; no es la única vía de entrada, y deja de ser la autoridad en cuanto el servidor está en pie.

**HTTP/3 es un segundo escucha, y viene apagado.** `doh.enable_h3` abre uno en la dirección y el puerto de DoH sobre UDP, compartiendo el certificado del escucha TCP. El puerto es el mismo porque ahí es donde lo ubican los dos mecanismos de descubrimiento: un encabezado `Alt-Svc` en cada respuesta DoH, para clientes ya conectados, y `alpn=h2,h3` en la designación DDR, para clientes que nunca se han conectado. Un bind QUIC que falla hace fallar el transporte entero en vez de dejar h2 solo: un escucha que prometía HTTP/3 y servía h2 es una falla que ningún cliente puede ver.

**Si un cliente DoT informa de una discrepancia de nombre en el certificado, este es el ajuste.** Un certificado generado cubre `localhost`, `127.0.0.1`, `::1` y las direcciones de ligadura propias del *listener*, así que uno en `192.168.1.5:853` ya funciona para un cliente que marque esa dirección, sin configurar nada. Lo que no puede cubrir es cualquier otra cosa a la que responda el equipo: su nombre de host, su nombre mDNS `.local`, un CNAME por el que lo conozca la LAN, o la dirección con la que lo publique un NAT. Esos van en `self_signed_sans`. Un *listener* sobre un enlace **comodín** (`0.0.0.0:853`, el valor por omisión) no deriva nada en absoluto, porque `0.0.0.0` no es una identidad que nadie marque: sobre una ligadura comodín la lista es lo único que nombra al equipo.

Esto es una revisión de nombre, no una decisión de confianza, y falla antes. Al cliente todavía hay que decirle que confíe en el certificado —anclarlo, o publicarlo y revisarlo por DANE/TLSA— porque un certificado autofirmado no tiene cadena. Un cliente que no valida nada (`kdig +tls`, systemd-resolved en modo oportunista) no se ve afectado en ningún caso.

### Administración por gRPC

```yaml
grpc:
  tcp_bind: "127.0.0.1:50051"       # "" desactiva el TCP
  unix_socket: /var/run/rolodex-dns.sock   # "" desactiva el socket
  shared_secret: ""                 # obligatorio para un tcp_bind que no sea loopback
```

- **El socket Unix se salta la autenticación por completo**, así que su modo de archivo *es* el control de acceso. Se crea con `0660` (al margen de la *umask*), así que concede acceso haciendo `chgrp` a un grupo de administración en lugar de aflojar el modo.
- **El TCP exige el secreto compartido**, comparado en tiempo constante, con bloqueo por origen después de fallos repetidos. Un secreto vacío significa «sin autenticación», lo cual está bien en *loopback* y se rechaza al arrancar en cualquier dirección enrutable.
- Prefiere el socket. `tcp_bind: ""` con una ruta de socket es la forma recomendada para un despliegue en un solo host.

### DHCP

La presencia de la sección lo activa; `tld` es obligatorio y es donde aterrizan los nombres de host:

```yaml
dhcp:
  bind: "0.0.0.0:67"
  tld: example.com          # un cliente "laptop" se registra como laptop.lan.example.com.
  default_lease_duration: 3600
  reclaim_timeout: 86400
  sweep_interval: 60
```

Los *pools* son estado en caliente, por ámbito de red:

```bash
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-dhcp-pool -s office \
  --range-start 10.0.0.100 --range-end 10.0.0.200 \
  --gateway 10.0.0.1 --subnet-mask 255.255.255.0 --dns-servers 10.0.0.1
```

Un *pool* es un único rango contiguo, y la asignación falla cuando se agota: no hay agregación entre *pools*. Los enlaces MAC-a-IP son pegajosos. Un nombre de host suministrado por el cliente tiene que ser una etiqueta DNS única y válida (RFC 1123) o se omite el registro con un aviso; se rechaza en lugar de sanearse, así que nada se registra en silencio bajo un nombre que el cliente no envió.

### Emisor ACME y portal

La presencia de la sección crea la CA raíz en el arranque y levanta dos *listeners*: el extremo ACME de cara al cliente y el portal de alta.

```yaml
acme:
  bind: "0.0.0.0:8555"
  portal_bind: "127.0.0.1:8500"                       # solo red de confianza
  directory_url: "https://dns.example.com:8555/acme"  # ponlo — los clientes lo ven
  root_ca_cn: "Rolodex Root CA"
  leaf_validity_days: 90
  require_eab: true
  issuance_scope: managed_zones                       # o "any"
  tls: { auto_self_signed: true }
```

`directory_url` es aquello con lo que se les dice a los clientes ACME que hablen, así que tiene que ser la URL alcanzable desde fuera, no `localhost`. **`portal_bind` tiene que quedarse en una dirección de confianza**: cualquiera que alcance el portal puede darse de alta. El alta queda confinada a las zonas que este servidor administra realmente salvo que pongas `issuance_scope: any`, y `require_eab: true` mantiene el registro de cuentas detrás de una credencial acuñada.

### Métricas

```yaml
metrics:
  bind: "127.0.0.1:9153"
```

Ausente por omisión, de modo que una actualización no abre ningún puerto nuevo. HTTP simple y sin autenticación —solo lleva recuentos agregados, nunca nombres de consulta ni valores de registro—, así que lígalo a una dirección privada. Las series que más merece la pena mirar primero son `rolodex_dns_answers_total{source}` (qué etapa respondió), `rolodex_dns_dnssec_verdicts_total{verdict}` y `rolodex_dns_blocklist_rotated_out`.

### DNS64, deriva de TTL, familia de direcciones

```yaml
dns64:
  enabled: false
  prefix: "64:ff9b::"       # el prefijo bien conocido

ttl_drift:
  mode: disabled            # disabled | fixed | logarithmic
  fixed_adjustment: "5m"    # "5m", "-30s", "1h30m", "2d12h"
  log_multiplier: 0.1

address_family:
  mode: auto                # auto | off | force4 | force6
  probe_interval_secs: 30
  fail_threshold: 2
```

`address_family: auto` es el valor por omisión y suele ser lo que quieres: hace conexiones TCP a resolvedores públicos en `:443` para probar la accesibilidad *real* por familia, y suprime las respuestas A o AAAA de una familia que el host no puede enrutar, de forma que los clientes recurren a la otra en vez de quedarse colgados. Usa `force4`/`force6` para fijar una familia sin sondeos, y `off` para responder siempre ambas.

### TLD propios e ingreso

No son configuración —viven en la base de datos y se administran en caliente—, pero hay dos campos de configuración que interactúan con ellos:

- `dns.ingress_listen_port` (por omisión 53) es el puerto en el que se liga cada *listener* de ingreso por TLD. La IP es por TLD, y se indica con `add-scope-tld --listen-ip`.
- Los *listeners* de ingreso se reproducen desde la base de datos en el arranque. Si la interfaz de superposición todavía no existe, el enlace falla y la entrada se trata como ausente, así que volver a agregar el TLD una vez levantado el túnel reintenta el enlace sin reiniciar.

## En caliente contra reinicio

Buena parte de lo que parece configuración es estado en caliente en SQLite, cambiado por gRPC sin reiniciar:

| Cambiado en caliente (gRPC/CLI) | Requiere reinicio |
| ---- | ---- |
| Registros, registros con ámbito, ámbitos, asociaciones | `dns.bind` y todas las demás direcciones de escucha |
| Zonas autoritativas, TLD propios, *listeners* de ingreso | `resolution.*` **salvo `mode`**, y `forwarders` (valores iniciales; `set-forwarders` los cambia en vivo) |
| Configuración de DNSBL, entradas locales, lista de permitidos | `dnssec.*` |
| DNS64, deriva de TTL, *proxy*, configuración de DoT/DoH/DoQ | `security.*` |
| *Pools* DHCP, concesiones, opciones de certificado | `database_path`, `dhcp.*`, `acme.*`, `metrics.*` |
| Llaves DNSSEC y firma de zonas; CA de ACME y credenciales EAB | `<transport>.tls.*` — las rutas y la lista de SAN, no el certificado en sí |
| **Archivos** de certificado TLS — reescritos en su lugar, recogidos en 30 s | — |
| `resolution.mode` — `set-resolution-mode` lo cambia, `get-resolution-mode` lee el que está en vigor | — |

Los cambios de registros y de listas de bloqueo surten efecto en la siguiente consulta; las mutaciones de registros vacían el caché de respuestas automáticamente.

## Con qué se niega a arrancar el servidor

Estos son fallos duros deliberados, no avisos, porque cada uno produciría si no un servidor que parece sano mientras hace lo que no debe:

- **Un `grpc.tcp_bind` enrutable con un `shared_secret` vacío.** Esa combinación es un plano de administración sin autenticar en un puerto alcanzable. *Loopback* está bien y es la forma documentada para desarrollo; `0.0.0.0` y `::` no son *loopback*.
- **Un anclaje de confianza DNSSEC malformado.** Recaer en las llaves de IANA dejaría a un operador que configuró una raíz privada anclado a lo que no era, validando tan contento.
- **Un código de rechazo de lista de bloqueo que no se puede analizar.** Un código que en silencio no se aplica es un rechazo que se lee como un listado: todo nombre revisado contra ese proveedor daría NXDOMAIN.
- **Una dirección de escucha que no se puede resolver**: una interfaz sin direcciones, o un nombre que no es ni una IP ni una interfaz. Esto es fatal para los *listeners* de DNS, DoT, DoH, DoQ, gRPC, DHCP y métricas; los dos *listeners* de ACME registran el error y el resto del servidor continúa.

Un error de análisis del YAML también es fatal. Un archivo que no existe, no.

Un **enlace que se resuelve pero falla en el sistema operativo** —el puerto está ocupado, o la dirección aún no existe— no es fatal: se registra por *listener* y el resto del servidor funciona. Así que un `EADDRINUSE` en `:53` aparece como una línea de error, no como un arranque fallido; mira el registro en vez de dar por hecho que un arranque limpio significa que todos los *listeners* se levantaron.

## Resolución de problemas

| Síntoma | Causa probable |
| ------- | -------------- |
| Los clientes de fuera de la LAN reciben REFUSED para todo salvo tus propias zonas | Funciona según lo previsto: `security.recursion_cidrs`. Agrega su rango si deben tener recursión |
| Un par de la superposición recibe REFUSED para todos los nombres | Está dentro de `security.overlay_cidrs` pero no ha llamado a `JoinNetwork`, o su TTL de asociación ha caducado |
| Un nombre público bajo un dominio que sustituiste devuelve NXDOMAIN | Agregar un registro hizo a este servidor autoritativo para toda la zona. Agrega el nombre localmente, o mueve la sustitución a un nombre que sí poseas |
| Un nombre resuelve en todas partes menos aquí, donde da SERVFAIL | La validación DNSSEC lo está rechazando. Revisa `rolodex_dns_dnssec_verdicts_total{verdict="bogus"}`; confírmalo con `dig +cd` (revisión desactivada) |
| **Todos** los nombres dan SERVFAIL, y la cadena nunca degrada al *upstream* cifrado | La propia zona raíz no valida: un anclaje de confianza que esta compilación no conoce (un relevo de KSK), un `dnssec.trust_anchors` equivocado, o algo en el `:53` respondiendo a las consultas DNSKEY con material propio. Esto es deliberado: una raíz que no valida es un veredicto, no un fallo de nivel, así que la consulta se rechaza en lugar de repreguntarse calladamente a un *upstream* que no valida. `dnssec.validate: false` es la vía de escape mientras arreglas el anclaje |
| Un nombre bajo `arpa.` recibe REFUSED (`ipv4only.arpa`, un `dig -x` para una dirección que no posees) | Funciona según lo previsto: `arpa.` y todo lo que hay debajo se responde desde datos locales o no se responde, en todos los modos de resolución. Nada de ese subárbol se envía aguas arriba. Agrega el registro localmente, o espera al trabajo de zonas inversas |
| `rolodex_dns_dnssec_blamed_roots` no es cero | Un servidor raíz respondió con DNSSEC que no valida contra tu anclaje y se ha retirado del conjunto de raíces durante 15 minutos, duplicándose por cada reincidencia. Si están retiradas **todas**, sospecha del anclaje o de la zona raíz, no de los servidores: el registro lo dice explícitamente. La culpa vive solo en memoria y se reinicia al arrancar |
| Todos los nombres revisados contra una lista de bloqueo empezaron a dar NXDOMAIN | Comportamiento previo a la administración de rechazos. Mira `get-dnsbl-config` por proveedores rotados fuera, y la cuota de ese proveedor |
| El nombre de host de un cliente DHCP nunca aparece en el DNS | No es una etiqueta DNS única válida: los nombres de host se rechazan, no se sanean. El aviso lo nombra |
| `dig -x` falla para un host que está perfectamente | Una entrada de la lista local coincidió con la dirección. `add-dnsbl-allow --name <ip>` lo levanta |
| Un certificado renovado no se está sirviendo | Dale 30 segundos. Si persiste, el registro dice por qué: una recarga que falla se registra en cada sondeo. La causa habitual es un certificado y una llave que no corresponden, que es también el aspecto de una escritura a medias; una renovación que se quede a medias para siempre nunca termina. Un *listener* con `auto_self_signed` no se sondea en absoluto: no tiene archivos |
| Un cliente DoT informa de discrepancia de nombre para el nombre de host o la dirección LAN del equipo | El certificado generado nombra solo el conjunto de loopback y las direcciones de ligadura del *listener*, y una ligadura comodín no aporta nada. Agrega el nombre a `dot.tls.self_signed_sans` y reinicia. Esto es distinto de confiar en el certificado, que un autofirmado sigue exigiendo |
| Un cliente DoT falla el saludo con `no_application_protocol` | Está ofreciendo un protocolo ALPN distinto de `dot`. El *listener* anuncia `dot` y rechaza a un cliente que ofrece solo otra cosa; un cliente que no ofrece ALPN alguno se sirve con normalidad |
| Un *listener* de ingreso nunca se levantó | Su IP no existía en el arranque. Vuelve a agregar el TLD una vez levantada la interfaz |

Para la referencia completa de campos, véase [Opciones de configuración](README.es-ES.md#opciones-de-configuración).
