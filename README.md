# HackTheBox — Writeups

Repositorio personal de writeups de HackTheBox, enfocado en la metodología: procedimiento paso a paso, comandos ejecutados, decisiones, pistas que llevan a cada hallazgo, intentos fallidos y evidencia visual.

**Máquinas documentadas: 2**

## Índice

| Máquina | OS | Dificultad | Fecha | Writeup |
|---|---|---|---|---|
| Touch (KIOSK-042) | Windows | Fácil | 2026-10-10 | [Machines/Windows/Facil/Touch](Machines/Windows/Facil/Touch/README.md) |
| Layover (airside-ws01) | Linux | Media | 2026-10-10 | [Machines/Linux/Media/Layover](Machines/Linux/Media/Layover/README.md) |

## Resumen del compromiso — Touch (KIOSK-042)

**Escenario:** kiosco de autoservicio de una aerolínea ficticia ("HTB Airways") sobre Windows, gestionado por el portal "Nexion DeviceHub" (8443) y con RDP expuesto.

**Cómo se comprometió (cadena):**

1. **Fuga no autenticada.** El endpoint `GET /api/status` del portal entrega el número de serie del dispositivo sin autenticación, y ese serial **se reutiliza como contraseña del portal** → acceso al dashboard.
2. **Credenciales de la app → acceso remoto.** El dashboard muestra las credenciales de la cuenta de kiosco. WinRM la rechaza por política, pero **RDP la acepta** → sesión gráfica en el host.
3. **Kiosk breakout.** Apagando por API el escáner de pasaportes y la impresora se fuerza un **error de la aplicación de kiosco**; el diálogo de error abre **Microsoft Edge** vía enlace de soporte, y desde Edge `Ctrl+O` expone el **diálogo nativo de archivos** desde el que se lanza `cmd.exe`.
4. **Escalada a SYSTEM.** Credenciales de `root` de MySQL en claro en un `.bat` + servicio **MySQL80 ejecutándose como `LocalSystem`** + permiso **Modify para `Authenticated Users`** en `C:\MySQL\lib\plugin` → DLL UDF `sys_eval` → `NT AUTHORITY\SYSTEM`.

**Fallos explotados:** serial tratado como credencial y expuesto sin autenticar · credenciales en claro en el dashboard y en disco · cuenta de kiosco con RDP y sin confinamiento real (navegador y diálogo nativo alcanzables) · servicio SYSTEM con directorio de plugins escribible por cualquier usuario autenticado.

**Qué funcionó:** reconocimiento con `-p-` y enumeración del portal para localizar `/api/status` · la técnica clásica *provocar error → el handler abre un navegador completo → diálogo nativo de archivos → `cmd.exe`* · reverse shell por **HTTP** (el recurso compartido SMB fue bloqueado por política) · **UDF de MySQL** depositando la DLL por el sistema de archivos, ya que `secure_file_priv=NULL` cierra la ruta de escritura por SQL.

**Resultado:** `user.txt` como cuenta de kiosco y `root.txt` como `NT AUTHORITY\SYSTEM` (valores enmascarados en la versión pública). Detalle completo en el [writeup de Touch](Machines/Windows/Facil/Touch/README.md).

## Resumen del compromiso — Layover (airside-ws01)

**Escenario:** entorno corporativo de aeropuerto. Un host de paso (`airside-ws01`, Linux) con acceso RDP **y** presencia en una red Wi-Fi interna mal segmentada, más un portal de empleados y un Craft CMS en la red interna (assumed breach: se parte de credenciales válidas, no de un escaneo ciego).

**Cómo se comprometió (cadena):**

1. **Acceso inicial.** Credenciales de contratista válidas → **RDP** (xrdp/XFCE) a `airside-ws01`. La cuenta está en los grupos `sudo`, `netdev` y **`wireshark`**.
2. **Red interna por Wi-Fi.** `wlan2` conecta el host de paso a `10.13.37.0/24`; el portal cautivo anuncia el portal de empleados `portal.international.htb/miles/`.
3. **Captura en claro.** Abusando del grupo `wireshark` se pone `wlan2` en **modo monitor** y se esnifa un `POST` **HTTP** a `/miles/login.php` con `username`/`password`.
4. **RCE autenticada en Craft CMS 5.9.8.** La credencial capturada accede al control panel; el endpoint `element-search` instancia objetos desde JSON y un *behavior* de Yii2 apunta a `ConsoleProcessus::execute()` → ejecución ciega como `www-data` y webshell en `/assets/shell.php`.
5. **Secretos y pivote.** `.env` → `CRAFT_SECURITY_KEY` + MySQL; el secreto del relé de correo cifrado en `htbairways_settings` se descifra reutilizando la clave (Yii2 `Security`) → `aporter`; la credencial se reutiliza por **SSH** a `10.13.37.10` → `user.txt`.
6. **Escalada a root.** **CUPS 2.4.16** (`CVE-2026-34990`): se filtra el token de autenticación local de `cupsd` (sólo `127.0.0.1:631`) vía servidor IPP malicioso y se abusa de un `device-uri` `file://` para escribir en `/etc/sudoers.d/` → `root.txt`.

**Fallos explotados:** portal de empleados por **HTTP** sin cifrar en una red Wi-Fi compartida · cuenta de bajo privilegio con capacidades de **captura de paquetes** (`wireshark`) · **doble encolado** del host de paso (gestión + Wi-Fi interna) · Craft CMS con `element-search` que instancia objetos desde JSON · **reutilización de la `CRAFT_SECURITY_KEY`** para cifrar secretos de integración · **reutilización de credenciales** correo ↔ sistema · CUPS vulnerable.

**Qué funcionó:** tratar el RDP como *assumed breach* y enumerar la cuenta (grupos) para descubrir la capacidad de sniffing · **modo monitor + tshark** para leer el `POST` en claro · reutilizar la credencial capturada en el panel de Craft · **RCE ciega** por behavior de Yii2 (con `curl --output` en lugar de `>` por `escapeshellcmd()`) · descifrar el blob de correo con la clave de Craft · y el **LPE de CUPS** por fuga del token local + escritura `file://`.

**Resultado:** `user.txt` como `aporter` y `root.txt` como `root` (valores enmascarados en la versión pública). Detalle completo en el [writeup de Layover](Machines/Linux/Media/Layover/README.md).

## Estructura

```
HackTheBox-Writeups/
├── README.md
├── Machines/
│   ├── Linux/
│   │   ├── Facil/   (pendiente)
│   │   ├── Media/
│   │   │   └── Layover/
│   │   │       ├── README.md          (writeup técnico)
│   │   │       └── screenshots/       (evidencia numerada por fase)
│   │   ├── Dificil/ (pendiente)
│   │   └── Insane/  (pendiente)
│   └── Windows/
│       ├── Facil/
│       │   └── Touch/
│       │       ├── README.md          (writeup técnico)
│       │       └── screenshots/       (evidencia numerada por fase)
│       ├── Media/   (pendiente)
│       ├── Dificil/ (pendiente)
│       └── Insane/  (pendiente)
├── Challenges/
└── Sherlocks/
```

Las máquinas se organizan por sistema operativo y, dentro de cada uno, por dificultad (`Facil`, `Media`, `Dificil`, `Insane`). Cada carpeta de máquina contiene su `README.md` (writeup) y `screenshots/` con las capturas referenciadas por el documento. Las imágenes usan prefijo de fase (`04_*` acceso, `05_*` breakout, `06_*` shell+user flag, `07_*` post-explotación, `08_*`/`09_*` privesc/root, `A_*` anexos).
