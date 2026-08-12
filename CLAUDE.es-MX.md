# Reglas de desarrollo de Rolodex DNS

> Idiomas: [English](CLAUDE.md) | [繁體中文](CLAUDE.zh-TW.md) | [简体中文](CLAUDE.zh-CN.md) | [Español (España)](CLAUDE.es-ES.md) | **Español (México)** | [日本語](CLAUDE.ja.md)

Rolodex DNS es un servidor DNS de horizonte dividido (*split-horizon*) y un resolvedor recursivo/de reenvío con administración remota mediante gRPC, escrito en Rust y publicado bajo la licencia AGPL-3.0-only.

Este archivo contiene las reglas para trabajar en él. Es deliberadamente breve: **lo que hace el software** está en `DESIGN.md`, y aquí no cabe nada relativo al comportamiento, la arquitectura o la superficie de la API.

## Dónde está documentado cada asunto

| Documento | Contenido |
| --------- | --------- |
| `DESIGN.md` | La especificación funcional: arquitectura, orden de resolución, todas las superficies de administración (gRPC, CLI, cliente de Go, cliente de JavaScript, métricas, configuración), el diseño del conjunto de pruebas y el sistema de compilación. Léelo antes de cambiar el comportamiento. |
| `README.md` | Referencia de cara al usuario, incluido el recetario de PromQL. |
| `CONFIGURATION.md` | Guía de configuración orientada a tareas: formas de despliegue resueltas, qué requiere reiniciar y solución de problemas por síntoma. |
| `CHANGELOG.md` | Historial de versiones. |
| `CLAUDE.md` | Este archivo. Solo reglas de desarrollo. |

Cada uno de los cinco tiene junto a él una traducción al chino tradicional (`.zh-TW.md`), al chino simplificado (`.zh-CN.md`), al español de España (`.es-ES.md`), al español de México (`.es-MX.md`) y al japonés (`.ja.md`). **El inglés es la fuente de la verdad**: cámbialo primero y trata las traducciones como algo que hay que actualizar después, no como un segundo lugar donde editar. Nada verifica que coincidan: `tests/promql_docs_test.rs` lee únicamente el `README.md` y el `DESIGN.md` en inglés, así que un bloque de PromQL o un conteo de familias dentro de una traducción es documentación, no una aserción verificada.

## Reglas

- por favor, no ejecutes tareas de make a menos que se te indique
- asegúrate de que deny(dead_code) y deny(unsafe) estén al principio y se respeten
- maneja todo std::result::Result de forma adecuada
- no uses unwrap
- no uses código unsafe
- nunca ejecutes las pruebas tú mismo
- escribe pruebas para todo, incluidas pruebas de integración y pruebas reales
- usa make test para validar cualquier cambio
- las pruebas de integración no deben alterar el host, nunca
- pruebas: a menos que se indique lo contrario, funcionan con entrada simulada y producen salida sobre las operaciones que se realizarían. Nunca afectan al sistema en ejecución.
- ejecución de las pruebas: usa las tareas de make siempre.
- las pruebas deben incluir siempre las verificaciones de linting
- las verificaciones de lint deben ser un conjunto de linters estándar de la comunidad de Rust, ejecutados mediante las tareas de make `lint`
- nunca uses `let _ = expr;` para silenciar advertencias de variables sin usar ni para darle la vuelta al *borrow checker*. Arregla el problema real: usa la variable, quita el parámetro o reestructura el código.
- `#![deny(dead_code)]` y `#![deny(unsafe_code)]` están puestos a nivel de *crate* tanto en lib.rs como en main.rs. Nunca agregues `#[allow(dead_code)]` ni `#[allow(unsafe_code)]` para evadirlos: elimina el código muerto y usa abstracciones seguras (por ejemplo, el *crate* nix) en lugar de unsafe.
- no modifiques el sistema más allá de configurar el hardware
- nunca borres, muevas ni modifiques etiquetas de git a menos que se te indique explícitamente

## Validar un cambio

`make test` es la barrera, y le toca ejecutarla al operador (ve las reglas de arriba). Corre, en este orden: `lint` (`cargo fmt -- --check` y `cargo clippy --all-targets -- -D warnings`), las pruebas de integración y unitarias de Go, `prometheus-test`, cada archivo de pruebas de integración de Rust de forma explícita, `cargo test` y las pruebas de lint/integración/unitarias de JavaScript. `make test-log` captura la corrida completa en un archivo de registro con marca de tiempo, que es la mejor opción cuando la corrida es larga.

Existen objetivos más acotados, listados en `DESIGN.md` bajo *Build System*: `make lint`, `make rust-test`, `make go-test`, `make js-test`, `make bench`.

Dos obligaciones recaen sobre quien agrega una prueba, no sobre quien la ejecuta:

- **Un nuevo archivo de pruebas de integración de Rust debe agregarse a la receta `rust-integration-test` del Makefile.** Esa receta nombra cada archivo de forma explícita; un archivo que solo recoge el `cargo test` final se sigue ejecutando, pero deja de ser visible como paso propio y una falla dentro de él se lee como una falla de todo.
- **Una prueba no debe tocar el host.** Solo directorios temporales, puertos efímeros y archivos SQLite en memoria o por prueba. Nada escribe en el árbol de trabajo, ni ocupa un puerto privilegiado fijo, ni alcanza la internet pública: los conjuntos que ejercitan la resolución hacia arriba apuntan sus raíces a una dirección de *loopback* muerta o a las jerarquías simuladas en proceso, precisamente para que una corrida en verde nunca dependa de la red.

## Escribir pruebas

Los conjuntos de pruebas de este repositorio se construyen sobre una sola idea, enunciada en la documentación de módulo al principio de cada archivo y que vale la pena repetir aquí: **una aserción sin su control no demuestra nada.** Una lista de bloqueo que bloquea todo satisface «el nombre listado es rechazado»; una que no bloquea nada satisface «el nombre de la lista de permitidos resuelve». Un validador de DNSSEC que rechaza todo pasa todas las pruebas de ataque, y uno que acepta todo pasa todas las pruebas del camino feliz. Escribe el par.

- **Nunca debilites una aserción para que una prueba pase.** Esto aplica con especial fuerza a los conjuntos `tests/security_*.rs`: cada uno fija el comportamiento que exige un hallazgo de seguridad, y una falla ahí es el hallazgo, no una prueba rota.
- Prefiere demostrar la propiedad antes que demostrar que la llamada devolvió `success`. Los *conteos* de consultas son lo que distingue un error de caché de su corrección; un *veredicto* es lo que distingue un validador de un analizador sintáctico; una firma vuelta a derivar es lo que distingue una firma verificable de un *blob* almacenado.
- No compares un codificador consigo mismo. Las expectativas de formato de cable se escriben a mano y por extenso.
- Provoca las mutaciones a través del plano de control real (gRPC) y lee los resultados de vuelta por un *socket* real ahí donde lo que importa es que la tubería esté conectada. Las pruebas unitarias siguen en verde a través de una regresión que movió una compuerta respecto a la caché de respuestas.

## Métricas

- **Toda dimensión de etiqueta debe estar acotada**: un *enum* fijo, o acotada por configuración. Cualquier cosa que controle un cliente se pliega a un cajón de sastre (`OTHER` para los tipos de consulta, `other` para los TLD). Los nombres de consulta nunca son etiquetas.
- **Los nuevos valores de etiqueta se agregan al final, nunca se insertan.** Las constantes del estilo `BLOCK_*` son posiciones dentro de un arreglo preasignado; una inserción reetiqueta en silencio todos los contadores existentes.
- Agregar o renombrar una métrica implica actualizar el conteo de familias y las consultas afectadas en `README.md` y `DESIGN.md`: `tests/promql_docs_test.rs` lee ambos, fija el conteo de familias documentado contra lo que emite el registro y resuelve cada consulta PromQL documentada contra la salida de exposición en vivo. `tests/prometheus_integration_test.rs` corre después esas mismas consultas a través de un Prometheus real.

## Documentación

- Los cambios de comportamiento aterrizan en `DESIGN.md` dentro del mismo cambio que los introduce. Es la especificación, no un resumen escrito después.
- Un nuevo archivo de documentación de primer nivel debe agregarse a la lista `include` de `Cargo.toml`. El paquete distribuye sus propias pruebas, y un paquete que lleva una prueba pero no su entrada es una prueba que no se puede ejecutar, que es exactamente la relación que `tests/promql_docs_test.rs` tiene con `README.md` y `DESIGN.md`.
- `README.md` y `DESIGN.md` son los dos archivos que se escanean en busca de bloques ```promql. Un bloque reetiquetado a otro lenguaje deja de verificarse.
