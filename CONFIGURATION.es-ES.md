# Guía de configuración de Rolodex DNS

> Idiomas: [English](CONFIGURATION.md) | [繁體中文](CONFIGURATION.zh-TW.md) | [简体中文](CONFIGURATION.zh-CN.md) | **Español (España)** | [Español (México)](CONFIGURATION.es-MX.md) | [日本語](CONFIGURATION.ja.md)

Este es un recorrido orientado a tareas: cómo conseguir un servidor que funcione y, después, cómo encender cada subsistema y por qué querrías hacerlo. Para la lista exhaustiva de campos, consulta [Opciones de configuración](README.es-ES.md#opciones-de-configuración) en el README.

- [Cómo se carga la configuración](#cómo-se-carga-la-configuración)
- [La configuración mínima que funciona](#la-configuración-mínima-que-funciona)
- [Direcciones de escucha](#direcciones-de-escucha)
- [Formas de despliegue](#formas-de-despliegue) — cuatro ejemplos resueltos
- [Subsistemas](#subsistemas) — una sección para cada uno
- [En caliente frente a reinicio](#en-caliente-frente-a-reinicio)
- [Con qué se niega a arrancar el servidor](#con-qué-se-niega-a-arrancar-el-servidor)
- [Resolución de problemas](#resolución-de-problemas)

## Cómo se carga la configuración

El servidor lee un único fichero YAML, `rolodex-dns.yml` por defecto:

```bash
rolodex-dns                        # lee ./rolodex-dns.yml
rolodex-dns -c /etc/rolodex-dns/config.yml
```

**Que falte el fichero no es un error.** El servidor registra `No config file found, using defaults` y arranca con los valores por defecto integrados, que son una configuración real y utilizable: DNS en `0.0.0.0:53`, resolución iterativa desde las raíces con validación DNSSEC, gRPC en *loopback* y en un socket Unix, listas de bloqueo desactivadas y transportes cifrados desactivados.

Toda sección es opcional y todo campo dentro de ella tiene un valor por defecto, así que un fichero de configuración solo tiene que nombrar lo que estás cambiando. Las secciones cuya *presencia* es el interruptor —`dot`, `doh`, `doq`, `proxy`, `dhcp`, `acme`, `metrics`— no arrancan nada cuando se omiten.

El registro se controla con la variable de entorno `RUST_LOG`, no con el fichero de configuración:

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
  tcp_bind: ""          # gestionar solo por el socket
```

Eso es un resolutor recursivo validador con una base de datos local de registros. Añade registros por el socket:

```bash
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-record \
  --name nas.example.com --record-type a --value 192.168.1.10
```

El puerto 53 requiere privilegios. Para desarrollo usa un puerto alto —`make dev` corre en `127.0.0.1:5300` mediante `dev.yml`— y en producción dale al binario `CAP_NET_BIND_SERVICE` o haz que lo enlace tu gestor de servicios en lugar de ejecutarlo como root.

## Direcciones de escucha

En todos los sitios donde se acepta una dirección (`dns.bind`, `dot.bind`, `doh.bind`, `doq.bind`, `grpc.tcp_bind`, `dhcp.bind`, `acme.bind`, `acme.portal_bind`, `metrics.bind`) se admiten cuatro formas:

| Forma | Ejemplo | Resultado |
| ----- | ------- | --------- |
| `ip:puerto` | `192.168.1.1:53` | Un *listener* en esa dirección |
| `[ipv6]:puerto` | `[::1]:53` | Un *listener*; los corchetes son obligatorios |
| `primary:puerto` | `primary:53` | La IP de salida de la ruta por defecto del sistema, detectada al arrancar |
| `interfaz:puerto` | `eth0:53` | **Un *listener* por cada IP de esa interfaz** |

`primary` se resuelve con un *connect* UDP que no envía nada hacia `8.8.8.8:53`: le pregunta a la tabla de rutas qué dirección de origen se usaría, y no manda nada. `interfaz:puerto` se expande a todas las direcciones asignadas a la interfaz, así que `eth0:53` en un host de doble pila crea dos *listeners*.

`dns.bind` es una lista de mapas de una sola clave, porque un *listener* es un protocolo *y* una dirección:

```yaml
dns:
  bind:
    - udp: "eth0:53"
    - tcp: "eth0:53"
    - udp: "127.0.0.1:53"
    - tcp: "127.0.0.1:53"
```

Los enlaces basados en interfaz se resuelven **al arrancar**, y no se vuelven a resolver después. Una interfaz que gana una dirección tras el arranque (un túnel WireGuard que se levanta, pongamos) no se recoge hasta reiniciar, que es exactamente el motivo por el que los *listeners* de ingreso por TLD se pueden volver a registrar en caliente; véase [TLD propios e ingreso](#tld-propios-e-ingreso).

## Formas de despliegue

### 1. Resolutor doméstico o de oficina pequeña

Validador, bloqueando publicidad y *malware*, sirviendo unos pocos nombres locales, accesible solo desde la LAN.

```yaml
database_path: /var/lib/rolodex-dns/rolodex-dns.db

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"
  auto_ptr: true                # mantiene los PTR inversos al paso de los A/AAAA

resolution:
  mode: auto                    # primero las raíces, luego cifrado, luego el resolutor del ISP

dnssec:
  validate: true                # es el valor por defecto; se pone aquí porque importa

dnsbl:
  enabled: true
  providers:
    - zone: dbl.spamhaus.org
      enabled: true

security:
  # el valor por defecto ya cubre RFC 1918; acótalo si tu LAN es un subconjunto
  recursion_cidrs: ["127.0.0.0/8", "192.168.0.0/16", "::1/128"]

grpc:
  unix_socket: /var/run/rolodex-dns.sock
  tcp_bind: ""

metrics:
  bind: "127.0.0.1:9153"
```

Notas sobre las decisiones: `resolution.mode: auto` significa que ningún tercero ve tus consultas mientras las raíces sean alcanzables, y la resolución sigue sobreviviendo a una red que filtra el `:53`. `recursion_cidrs` es lo que impide que un enlace a `0.0.0.0:53` sea un resolutor abierto: la lista por defecto ya es segura, y acotarla a tus propios rangos es un refinamiento, no un requisito.

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

(Cualquier zona que *ya tenga* registros se trata como autoritativa automáticamente; véase [Zonas gestionadas y zonas autoritativas](#zonas-gestionadas-y-zonas-autoritativas)).

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

Después construye los ámbitos en caliente, no en el fichero de configuración: viven en la base de datos.

```bash
CLI="rolodex-dns-cli -u /var/run/rolodex-dns.sock"
$CLI create-scope --name office                       # implica office.home.
$CLI add-scope-tld -s office --tld office. --listen-ip 10.64.0.1
$CLI add-scoped-record -s office --name git.office. --record-type a --value 10.64.0.5
$CLI join-network --ip 10.64.0.7 --scope office --ttl 300
```

### 4. Resolutor en una red hostil o filtrada

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
| `auto` (por defecto) | Quieres privacidad ante todo, pero la resolución tiene que sobrevivir a una red filtrada |
| `recursive` | Quieres las raíces o nada: jamás se contacta con un resolutor ascendente |
| `forward` | Quieres un reenviador simple (o, con `forwarders: []`, nada aguas arriba) |

`default_ttl` es un **valor de reserva, no un suelo**. Un TTL que viene presente se respeta exactamente como se envió, incluido el TTL negativo del SOA de una zona. Si lo que buscas es acortar o alargar TTL en vivo, eso es la [deriva de TTL](#dns64-deriva-de-ttl-familia-de-direcciones), no esto.

### DNSSEC

Dos mitades independientes. La **validación** está activada por defecto y no necesita configuración:

```yaml
dnssec:
  validate: true
  trust_anchors: []        # vacío = las claves raíz de IANA
```

Se aplica solo a la ruta iterativa (modo `recursive`, y el nivel de raíces de `auto`), así que no hace nada en modo `forward`. Los datos espurios se convierten en SERVFAIL y nunca se cachean. Desactívala solo si tienes un motivo concreto: un *upstream* roto que no puedes arreglar, o una jerarquía privada que aún no has anclado.

`trust_anchors` toma la forma de presentación DNSKEY, los cuatro campos RDATA tal como los imprime `dig DNSKEY .`, y una sustitución **reemplaza** las claves de IANA en lugar de sumarse a ellas:

```yaml
dnssec:
  trust_anchors:
    - "257 3 15 <clave en base64>"     # una raíz privada; IANA NO se confía también
```

Un anclaje malformado hace fallar el arranque en lugar de recaer en IANA: un anclaje que no puede casar con un DNSKEY real hace que toda zona firmada falle sin que nada señale al anclaje como la causa.

La **firma** no se configura en YAML en absoluto; es una operación en caliente sobre una zona:

```bash
CLI="rolodex-dns-cli -u /var/run/rolodex-dns.sock"
$CLI generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type KSK
$CLI generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type ZSK
$CLI sign-zone --zone example.com.
```

Vuelve a ejecutar `sign-zone` después de cambiar registros. Las firmas se reemplazan, no se acumulan. RSA (algoritmo 8) se rechaza en la generación de claves —`ring` no puede generar claves RSA— y la denegación autenticada (NSEC/NSEC3) se valida pero nunca se genera.

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
| Por defecto | `10.64.0.0/10` | *loopback*, RFC 1918, enlace local, ULA, CGNAT |

Deja `recursion_cidrs` en paz salvo que la estés *acotando*. Ensancharla hacia la internet pública convierte la máquina en un resolutor abierto, que es un activo de reflexión/amplificación tanto si alguien está abusando de él ahora mismo como si no.

`qname_case_randomization` debería quedarse activado. Desactívalo solo para un *upstream* que normaliza el uso de mayúsculas de la pregunta que devuelve: de lo contrario ese resolutor fallará todas las consultas, porque la comparación de mayúsculas y minúsculas es lo que hace que 0x20 defienda algo de verdad.

### Listas de bloqueo (RBL y DNSBL)

Dos listas, la misma maquinaria, claves distintas: **RBL bloquea por IP** (se comprueba en las búsquedas de DNS inverso) y **DNSBL bloquea por nombre** (se comprueba antes de cualquier resolución externa). Ambas están desactivadas por defecto con listas de proveedores vacías, así que no se consulta nada y ningún nombre llega a manos del operador de una lista de bloqueo hasta que añades proveedores.

```yaml
rbl:
  enabled: true
  refusal_cooldown_secs: 3600
  providers:
    - zone: zen.spamhaus.org
      enabled: true

dnsbl:
  enabled: true
  providers:
    - zone: dbl.spamhaus.org
      enabled: true
```

Tres cosas que conviene saber antes de encenderlas:

1. **Los registros locales siempre ganan.** Una lista de bloqueo se ejecuta después de los registros locales y las zonas gestionadas, así que un listado de terceros nunca puede tumbar un servicio interno. Se ejecuta *antes* que la caché de respuestas y que el resolutor, así que un listado surte efecto incluso para un nombre que se cacheó antes.
2. **El bloqueo es por nombre consultado, no por sufijo.** Que `doubleclick.net` esté listado no bloquea `stats.g.doubleclick.net`: el proveedor tiene que listarlo también. La lista de permitidos *sí* casa por sufijo, porque una vía de escape que se dejara los subdominios no lo sería.
3. **Los códigos de rechazo importan a volumen.** Una lista de bloqueo te dice «has superado tu cuota» con el mismo tipo de registro `A` que usa para «listado». La gestión de rechazos está activada por defecto con un conjunto de códigos integrado; la única razón para configurar `refusal_codes` es una lista de bloqueo privada cuyos listados reales colisionen con uno (`refusal_codes: ["none"]`), o el deseo de acotar el conjunto. Véase [Códigos de rechazo y rotación de proveedores](README.es-ES.md#códigos-de-rechazo-y-rotación-de-proveedores).

Las entradas locales y la lista de permitidos son estado en caliente, no configuración:

```bash
CLI="rolodex-dns-cli -u /var/run/rolodex-dns.sock"
$CLI add-local-rbl --name 10.0.0.5 --reason "known spam source"
$CLI add-dnsbl-allow --name vendor.example.com --reason "false positive"
$CLI add-dnsbl-allow --name 192.168.1.100 --reason "our own relay"   # una IP también vale
```

### Zonas gestionadas y zonas autoritativas

No hay lista de zonas en el fichero de configuración. Una zona pasa a ser autoritativa de una de dos maneras:

- **Implícitamente**, por tener registros. Cualquier registro en cualquier punto de la zona convierte a este servidor en autoritativo para toda ella, así que añadir `foo.example.com` como sustitución local significa que `www.example.com` responde NXDOMAIN en vez de resolverse desde internet. Ese es el trato del horizonte dividido, y merece la pena ser deliberado al respecto: sustituye un dominio público solo cuando pretendas poseerlo.
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
  tls: { auto_self_signed: true }     # aceptable en una red de confianza
```

`auto_self_signed: true` (el valor por defecto) genera un certificado al arrancar si no hay ninguno configurado, lo cual es cómodo en una red de confianza e inútil para un cliente que comprueba nombres. Ten en cuenta que la recarga de certificados **aún no está conectada a los *listeners***: cada uno toma una instantánea al arrancar, así que un certificado renovado necesita un reinicio para servirse.

### Gestión por gRPC

```yaml
grpc:
  tcp_bind: "127.0.0.1:50051"       # "" desactiva el TCP
  unix_socket: /var/run/rolodex-dns.sock   # "" desactiva el socket
  shared_secret: ""                 # obligatorio para un tcp_bind que no sea loopback
```

- **El socket Unix se salta la autenticación por completo**, así que su modo de fichero *es* el control de acceso. Se crea con `0660` (al margen de la *umask*), así que concede acceso haciendo `chgrp` a un grupo de administración en lugar de aflojar el modo.
- **El TCP exige el secreto compartido**, comparado en tiempo constante, con bloqueo por origen tras fallos repetidos. Un secreto vacío significa «sin autenticación», lo cual está bien en *loopback* y se rechaza al arrancar en cualquier dirección enrutable.
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

`directory_url` es aquello con lo que se les dice a los clientes ACME que hablen, así que tiene que ser la URL alcanzable desde fuera, no `localhost`. **`portal_bind` tiene que quedarse en una dirección de confianza**: cualquiera que alcance el portal puede darse de alta. El alta queda confinada a las zonas que este servidor gestiona realmente salvo que pongas `issuance_scope: any`, y `require_eab: true` mantiene el registro de cuentas detrás de una credencial acuñada.

### Métricas

```yaml
metrics:
  bind: "127.0.0.1:9153"
```

Ausente por defecto, de modo que una actualización no abre ningún puerto nuevo. HTTP simple y sin autenticación —solo lleva recuentos agregados, nunca nombres de consulta ni valores de registro—, así que enlázalo a una dirección privada. Las series que más merece la pena mirar primero son `rolodex_dns_answers_total{source}` (qué etapa respondió), `rolodex_dns_dnssec_verdicts_total{verdict}` y `rolodex_dns_blocklist_rotated_out`.

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

`address_family: auto` es el valor por defecto y suele ser lo que quieres: hace conexiones TCP a resolutores públicos en `:443` para probar la accesibilidad *real* por familia, y suprime las respuestas A o AAAA de una familia que el host no puede enrutar, de forma que los clientes recurren a la otra en vez de quedarse colgados. Usa `force4`/`force6` para fijar una familia sin sondeos, y `off` para responder siempre ambas.

### TLD propios e ingreso

No son configuración —viven en la base de datos y se gestionan en caliente—, pero hay dos campos de configuración que interactúan con ellos:

- `dns.ingress_listen_port` (por defecto 53) es el puerto en el que se enlaza cada *listener* de ingreso por TLD. La IP es por TLD, y se indica con `add-scope-tld --listen-ip`.
- Los *listeners* de ingreso se reproducen desde la base de datos en el arranque. Si la interfaz de superposición todavía no existe, el enlace falla y la entrada se trata como ausente, así que volver a añadir el TLD una vez levantado el túnel reintenta el enlace sin reiniciar.

## En caliente frente a reinicio

Buena parte de lo que parece configuración es estado en caliente en SQLite, cambiado por gRPC sin reiniciar:

| Cambiado en caliente (gRPC/CLI) | Requiere reinicio |
| ---- | ---- |
| Registros, registros con ámbito, ámbitos, asociaciones | `dns.bind` y todas las demás direcciones de escucha |
| Zonas autoritativas, TLD propios, *listeners* de ingreso | `resolution.*` y `forwarders` (valores iniciales; `set-forwarders` los cambia en vivo) |
| Configuración de RBL/DNSBL, entradas locales, lista de permitidos | `dnssec.*` |
| DNS64, deriva de TTL, *proxy*, configuración de DoT/DoH/DoQ | `security.*` |
| *Pools* DHCP, concesiones, opciones de certificado | `database_path`, `dhcp.*`, `acme.*`, `metrics.*` |
| Claves DNSSEC y firma de zonas; CA de ACME y credenciales EAB | Ficheros de certificado TLS (aún no se intercambian en caliente en los *listeners*) |

Los cambios de registros y de listas de bloqueo surten efecto en la siguiente consulta; las mutaciones de registros vacían la caché de respuestas automáticamente.

## Con qué se niega a arrancar el servidor

Estos son fallos duros deliberados, no avisos, porque cada uno produciría si no un servidor que parece sano mientras hace lo que no debe:

- **Un `grpc.tcp_bind` enrutable con un `shared_secret` vacío.** Esa combinación es un plano de gestión sin autenticar en un puerto alcanzable. *Loopback* está bien y es la forma documentada para desarrollo; `0.0.0.0` y `::` no son *loopback*.
- **Un anclaje de confianza DNSSEC malformado.** Recaer en las claves de IANA dejaría a un operador que configuró una raíz privada anclado a lo que no era, validando tan contento.
- **Un código de rechazo de lista de bloqueo que no se puede analizar.** Un código que en silencio no se aplica es un rechazo que se lee como un listado: todo nombre comprobado contra ese proveedor daría NXDOMAIN.
- **Una dirección de escucha que no se puede resolver**: una interfaz sin direcciones, o un nombre que no es ni una IP ni una interfaz. Esto es fatal para los *listeners* de DNS, DoT, DoH, DoQ, gRPC, DHCP y métricas; los dos *listeners* de ACME registran el error y el resto del servidor continúa.

Un error de análisis del YAML también es fatal. Un fichero que no existe, no.

Un **enlace que se resuelve pero falla en el sistema operativo** —el puerto está ocupado, o la dirección aún no existe— no es fatal: se registra por *listener* y el resto del servidor funciona. Así que un `EADDRINUSE` en `:53` aparece como una línea de error, no como un arranque fallido; mira el registro en vez de dar por hecho que un arranque limpio significa que todos los *listeners* se levantaron.

## Resolución de problemas

| Síntoma | Causa probable |
| ------- | -------------- |
| Los clientes de fuera de la LAN reciben REFUSED para todo salvo tus propias zonas | Funciona según lo previsto: `security.recursion_cidrs`. Añade su rango si deben tener recursión |
| Un par de la superposición recibe REFUSED para todos los nombres | Está dentro de `security.overlay_cidrs` pero no ha llamado a `JoinNetwork`, o su TTL de asociación ha caducado |
| Un nombre público bajo un dominio que sustituiste devuelve NXDOMAIN | Añadir un registro hizo a este servidor autoritativo para toda la zona. Añade el nombre localmente, o mueve la sustitución a un nombre que sí poseas |
| Un nombre resuelve en todas partes menos aquí, donde da SERVFAIL | La validación DNSSEC lo está rechazando. Comprueba `rolodex_dns_dnssec_verdicts_total{verdict="bogus"}`; confírmalo con `dig +cd` (comprobación desactivada) |
| **Todos** los nombres dan SERVFAIL, y la cadena nunca degrada al *upstream* cifrado | La propia zona raíz no valida: un anclaje de confianza que esta compilación no conoce (un relevo de KSK), un `dnssec.trust_anchors` equivocado, o algo en el `:53` respondiendo a las consultas DNSKEY con material propio. Esto es deliberado: una raíz que no valida es un veredicto, no un fallo de nivel, así que la consulta se rechaza en lugar de repreguntarse calladamente a un *upstream* que no valida. `dnssec.validate: false` es la vía de escape mientras arreglas el anclaje |
| Un nombre bajo `arpa.` recibe REFUSED (`ipv4only.arpa`, un `dig -x` para una dirección que no posees) | Funciona según lo previsto: `arpa.` y todo lo que hay debajo se responde desde datos locales o no se responde, en todos los modos de resolución. Nada de ese subárbol se envía aguas arriba. Añade el registro localmente, o espera al trabajo de zonas inversas |
| `rolodex_dns_dnssec_blamed_roots` no es cero | Un servidor raíz respondió con DNSSEC que no valida contra tu anclaje y se ha retirado del conjunto de raíces durante 15 minutos, duplicándose por cada reincidencia. Si están retiradas **todas**, sospecha del anclaje o de la zona raíz, no de los servidores: el registro lo dice explícitamente. La culpa vive solo en memoria y se reinicia al arrancar |
| Todos los nombres comprobados contra una lista de bloqueo empezaron a dar NXDOMAIN | Comportamiento previo a la gestión de rechazos. Mira `get-rbl-config` por proveedores rotados fuera, y la cuota de ese proveedor |
| El nombre de host de un cliente DHCP nunca aparece en el DNS | No es una etiqueta DNS única válida: los nombres de host se rechazan, no se sanean. El aviso lo nombra |
| `dig -x` falla para un host que está perfectamente | Un falso positivo de RBL. `add-dnsbl-allow --name <ip>` lo levanta |
| Un certificado renovado no se está sirviendo | La recarga de certificados aún no está conectada a los *listeners*; reinicia |
| Un *listener* de ingreso nunca se levantó | Su IP no existía en el arranque. Vuelve a añadir el TLD una vez levantada la interfaz |

Para la referencia completa de campos, véase [Opciones de configuración](README.es-ES.md#opciones-de-configuración).
