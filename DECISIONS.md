# DECISIONS.md - husksec (CSI::nano)

Registro de decisiones de la capa de seguridad. Mismo formato ADR ligero que el
núcleo. El núcleo (`husk`) está **congelado**: aquí solo se documentan decisiones
de la capa que se monta encima.

---

## S1. La capa es un paquete hermano (`husksec`), no un subpaquete del núcleo

**Decisión:** `husksec` vive en su propio directorio, con su propio `pyproject`,
y **depende** de `husk` (lo importa, no lo modifica).
**Por qué:** mantiene el núcleo literalmente intacto, su presupuesto de SLOC
(solo mide `src/husk`) sigue siendo honesto, y el argumento de arquitectura es
demostrable con `git`: *"la capacidad ofensiva son ficheros nuevos, cero diffs
en el núcleo"*. Refuerza la tesis "núcleo mínimo + plugins opcionales".
**Descartado:** meter `security/` dentro de `husk`. Contaminaría la neutralidad
de dominio del núcleo y falsearía su presupuesto.

## S2. Cero dependencias de runtime más allá de `husk`

**Decisión:** `dependencies = ["husk"]` y nada más. `husk` ya trae solo `httpx`.
**Por qué:** la tesis es eficiencia (cobertura/LOC, cobertura/€). Si la capa de
seguridad arrastrase media docena de dependencias, el "nano" dejaría de ser
cierto. Las herramientas de seguridad serán envoltorios finos sobre utilidades
estándar **del sandbox** (nmap, curl…), no librerías Python pesadas.

## S3. El scope como frontera de autorización, fail-closed (`scope.py`)

**Decisión:** un fichero `scope.yaml` declara, *por un humano*, qué objetivos se
pueden tocar. `Scope.check(target)` decide. Dos reglas duras:
1. **Fail-closed:** fichero ausente / malformado / sin `authorized: true` ⇒ se
   deniega **todo**. Un allowlist que falla *abierto* es peor que no tenerlo.
2. **Deny-overrides-allow:** un objetivo se autoriza solo si casa con `in_scope`
   **y** no casa con `out_of_scope`. La lista de exclusión siempre gana (sacar
   del scope un gateway o una caja de producción dentro de un rango permitido).
**Por qué:** es el equivalente estructurado de la deny-list genérica del núcleo.
Es el **filtro barato y disparador de HITL**, NO la frontera final: esa sigue
siendo el sandbox (y, para red, una salida con scope encima — pendiente B2).

## S4. Parser propio de un subconjunto de YAML, no PyYAML

**Decisión:** parseamos a mano un subconjunto explícito y documentado de YAML
(`parse_scope_text`), rechazando todo lo que quede fuera.
**Por qué:** un fichero de scope es **config de seguridad**. Parsearlo con una
gramática grande y sorprendente es, en sí, superficie de ataque (YAML tiene
coerción de tipos, anchors, tags `!!python`). Un subconjunto minúsculo que
**rechaza lo desconocido** garantiza que una errata (`out_scope:` en vez de
`out_of_scope:`) no ensanche el scope en silencio: lanza `ScopeError`. Coste
cero dependencias. Decisión consciente (alternativa viva: `scope.toml`
con `tomllib` de la stdlib si algún día se quiere un parser completo sin dep).

## S5. Nunca resolvemos DNS en el matcher

**Decisión:** un patrón CIDR solo casa con un target que ya es IP literal; un
patrón hostname solo casa con un target hostname. No convertimos nombres en IPs.
**Por qué:** resolver DNS dentro del control de autorización deja que un
resolver controlado por el atacante reapunte un nombre "en scope" a cualquier
IP. Separar los dos dominios (nombre vs dirección) cierra esa vía. Limitación
honesta documentada: el scope es **a nivel de host**, no de path de URL.

## S6. Herramientas tipadas + `run` genérico (modelo híbrido)

**Decisión (deliberada):** se conserva la herramienta `run` del
núcleo para flexibilidad bash-first, y se añaden **pocas herramientas tipadas**
para acciones de red, donde el objetivo es un **argumento estructurado**
comprobable contra el scope. (Implementación del enganche: bloque B2.)
**Por qué:** parsear shell arbitraria para extraer el objetivo es frágil e
inseguro; un campo `target` estructurado hace el scope **garantizable y
auditable** sin renunciar del todo a bash-first. El enforcement real de red
seguirá viviendo en el sandbox (defensa en profundidad).

## S7. Verdad de terreno como primitiva de primer nivel (`verify.py`)

**Decisión:** un hallazgo solo se marca `confirmed` si un verificador determinista
lo prueba: flag presente, crash (firma o exit 128+señal; **timeout 124 NO es
crash**), o el parche cierra el PoC (reprodujo antes, ya no después).
**Por qué:** en seguridad la verdad suele ser binaria y barata, al contrario que
en ciencia abierta donde el modelo alucina. Es el ancla anti-humo de todo el
autoresearch: *ningún hallazgo sin verificación reproducible*. Los negativos
(`refuted`) también se registran: un resultado negativo es un resultado.

## S8. Metering por envoltura, coste etiquetado como estimación (`metering.py`)

**Decisión:** el eje coste/€ se obtiene envolviendo el proveedor y **estimando**
tokens (~4 chars/token), porque el núcleo descarta el bloque `usage` para seguir
diminuto. Los costes se reportan como estimación, no como factura.
**Por qué:** mantiene el núcleo intacto y da una cifra suficiente para comparar
runs y scaffolds (los tres ejes del estudio CSI: cobertura/coste/tiempo). Si un proveedor expone
`usage` real, se sustituye aquí en un solo sitio.

## S9. Adaptadores de benchmark: runner genérico + extractor por benchmark

**Decisión:** el runner y el scoring (por **flag en la traza**, no por lo que diga
el modelo) son nuestros y están testeados. Cada benchmark aporta su **extractor**
(`parse(data, path) -> BenchmarkTask`), no un mapa de claves planas; los ficheros
malformados se **saltan y se listan** (nunca se infla la cobertura).
**Por qué:** "adaptar, no reimplementar". La primera versión asumía un mapa de
campos plano **sin verificar** (y el propio código lo avisaba). Al confirmarlo
contra las fuentes reales —sin clonar— resultó que **ninguno casaba**; de ahí el
cambio a extractores y las correcciones de S9b.

## S9b. Estructura real verificada de Cybench y CAIBench (y qué implica)

**Cybench** (github.com/andyzorigin/cybench, `main`): el metadata de cada tarea
vive en `<task>/metadata/metadata.json`. Claves reales: `categories` (lista),
`easy_prompt`/`hard_prompt`, `subtasks`. El **nombre** sale del directorio, el
**prompt** de `easy_prompt`, la **flag** del último subtask (`subtasks[-1].answer`)
y el **target** de `target_host`. No existe `name`/`prompt`/`answer`/`target`
planos. Encaja con nuestro scoring (flag estática en la traza).

**CAIBench** (arXiv 2510.24317): **no es un repo propio** — vive dentro de
`aliasrobotics/cai` (rama `archive`), y **no hay `challenge.json` por reto**: todos
los retos están en un **array JSON agregado** (`ctf-jsons/ctf_configs.jsonl`).
Clave decisiva: **CAIBench no trae un valor de flag estático**; la flag se obtiene
ejecutando `flag_commands` dentro del contenedor. Por eso el adaptador **carga**
los retos pero deja `flag=None`: son honestamente **no puntuables** por nuestro
método hasta implementar la resolución de flag en contenedor (siguiente paso, no
entregado). Preferimos decirlo a fingir cobertura.

## S10. Red del sandbox: enforcement tipado ahora, proxy de egress como siguiente paso

**Decisión v1:** las acciones de red van por herramientas tipadas con scope
comprobado antes de ejecutar; el `run` libre solo **rechaza lo claramente fuera
de scope**. El aislamiento real sigue siendo el sandbox. El **proxy de egress con
scope** (que haría imposible físicamente tocar fuera de scope aunque el modelo lo
intente por shell) queda **documentado como endurecimiento**, no construido hoy.
**Por qué:** honestidad — no sobre-prometer una garantía que v1 no da. Es la misma
postura del núcleo: "la deny-list no es la frontera, el sandbox sí".

## S11. Presupuesto de la capa como invariante (`tests/test_loc_budget.py`)

**Decisión:** la capa completa ≤ **1400 SLOC** y **0 dependencias** más allá de
`husk`. Hoy: ~1181 SLOC, 0 deps extra.
**Por qué:** el "nano" tiene que ser verificable, no una intención. Igual criterio
que el núcleo (cuenta docstrings, no infra-cuenta).

## S12. Revisión adversarial de la capa (igual que la del núcleo)

**Qué:** tras construir B2–B6 se pasó una revisión adversarial por dimensiones
(bypass de scope, inyección/ejecución, correctness, honestidad docs↔código), un
revisor escéptico por dimensión, aceptando solo hallazgos con escenario
reproducible. Salieron 13; los reales se corrigieron **con test de regresión**
([tests/test_review_regressions.py](tests/test_review_regressions.py)):

- **Scope (crítico):** un `target` con sufijo CIDR/rango (`10.10.11.4/31`)
  normalizaba al host base y pasaba el check, pero nmap recibía el crudo y
  escaneaba el rango (saltándose una IP excluida). Fix: las tools por host
  **construyen el comando desde el host normalizado** y **rechazan** CIDR/rango/lista.
- **Scope:** un `*.zona` en `out_of_scope` no denegaba el apex de la zona → ahora
  la exclusión con comodín cubre también el apex (deny amplio, allow estrecho).
- **Scope:** IPs ofuscadas (entero/octal/hex) evadían el filtro de `run` → se
  decodifican (SSRF a metadata). IPv4-mapped IPv6 evadía exclusión IPv4 → se mapea.
- **Correctness:** benchmark marcaba `solved` por regex de flag genérica aunque la
  tarea no definiera flag → ahora es **no puntuable**. `exit 137` (SIGKILL/timeout)
  se contaba como crash → fuera. El replay del store perdía la nota del cambio de
  estado → ahora se reconstruye igual. Los `steps` del bench eran siempre el tope.
- **Honestidad docs:** "nunca en el host" era falso con el fallback local → el CLI
  ahora **rehúsa sin Docker** salvo `--no-docker` explícito. HITL no estaba en
  `research`/`bench` → cableado. El alcance real de `run` (deny-first, no exige
  `in_scope`) se documentó sin adornos.

**Lección (repetida del núcleo):** casi ningún fallo estaba en el camino feliz;
estaban en los bordes (encodings, apex, timeout vs crash) y en afirmaciones de
los docs que el código no respaldaba. La revisión adversarial los sacó.

---

## Estado

B1–B6 construidos, revisados y verdes (84 tests). Capa: ~1304 SLOC / 1400, 0 deps
extra. Adaptadores de benchmark **verificados contra las fuentes reales** y
corregidos (S9/S9b): Cybench puntúa por flag estática; CAIBench se carga pero
queda no puntuable hasta resolver la flag en contenedor. Siguiente posible: esa
resolución de flag en CAIBench, proxy de egress con scope (S10), y medición real
en Cybench desde un entorno Linux con Docker.
