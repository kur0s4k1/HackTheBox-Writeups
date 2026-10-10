<div align="center">

<!-- Banner ASCII -->
```
██╗░░██╗██████╗░██████╗░██╗░░░██╗
██║░░██║██╔══██╗██╔══██╗╚██╗░██╔╝
███████║██████╔╝██████╦╝░╚████╔╝░
██╔══██║██╔═══╝░██╔══██╗░░╚██╔╝░░
██║░░██║██║░░░░░██████╦╝░░░██║░░░
╚═╝░░╚═╝╚═╝░░░░░╚═════╝░░░░╚═╝░░░
```

# ⚡ kur0s4k1 · HackTheBox Writeups

<img src="https://readme-typing-svg.demolab.com/?font=Fira+Code:wght@500&size=22&pause=1000&color=F7931E&center=true&vCenter=true&width=640&lines=Recon+%E2%86%92+Foothold+%E2%86%92+Pivoting+%E2%86%92+Root;Assumed+Breach+%C2%B7+Web+%C2%B7+Active+Directory+%C2%B7+Post-explotaci%C3%B3n;Writeups+reales%3A+con+fallos%2C+pistas+y+evidencia;Cada+flag+tiene+su+historia" alt="Typing SVG" />

[![HackTheBox](https://img.shields.io/badge/HackTheBox-Writeups-9FEF00?style=for-the-badge&logo=hackthebox&logoColor=white)](https://www.hackthebox.com/)
[![Máquinas](https://img.shields.io/badge/m%C3%A1quinas_documentadas-2-9FEF00?style=for-the-badge&logo=hackthebox&logoColor=white)](#-m%C3%A1quinas)
[![Flags](https://img.shields.io/badge/flags_capturadas-4%20%2F%204-F7931E?style=for-the-badge&logo=hackthebox&logoColor=white)](#-m%C3%A1quinas)
[![Metodología](https://img.shields.io/badge/enfoque-metodolog%C3%ADa%20%2B%20pistas-2159D6?style=for-the-badge&logo=target&logoColor=white)](#-c%C3%B3mo-est%C3%A1-escrito-cada-writeup)
[![Visitas](https://komarev.com/ghpvc/?username=kur0s4k1&label=visitas&color=F7931E&style=flat-square)](https://github.com/kur0s4k1)

<!-- Terminal animada (SVG propio, sin dependencias externas) -->
<img src="assets/terminal-animation.svg" alt="Terminal animada: del reconocimiento a root" width="100%" />

<!-- Snake sobre la grilla de contribuciones (generado por GitHub Actions en la rama `output`) -->
<img src="https://raw.githubusercontent.com/kur0s4k1/HackTheBox-Writeups/output/github-contribution-grid-snake.svg" alt="snake animation" width="100%" />

</div>

---

> 🛡️ **Política de divulgación:** sólo se documentan máquinas **retiradas** (o con permiso expreso de la plataforma). En la versión pública las **flags, contraseñas y claves van enmascaradas** (`deadb33f****`, `C0ntr4s****`) para no regalar hashes a quien esté resolviendo el box. Los procedimientos, comandos y evidencia quedan íntegros.

---

## 📡 Qué vas a encontrar aquí

Writeups **de operaciones reales**, no resúmenes de 5 líneas. Cada máquina se documenta como se vivió:

- 🧭 **Metodología completa** — qué pistas llevaron de un hallazgo al siguiente y por qué se tomó cada decisión.
- 💥 **Comandos y payloads ejecutables** — tal cual se lanzaron, con su salida real.
- 🧨 **Anexo de fallos** — lo que *no* funcionó y por qué (aquí es donde se aprende de verdad).
- 📸 **Evidencia visual por fases** — capturas numeradas por etapa del ataque.
- 🛠️ **Mitigaciones** — qué controles habrían roto la cadena.

<div align="center">

```mermaid
flowchart LR
    A[🎯 Acceso inicial] --> B[🔎 Recon & Enumeración]
    B --> C[🧪 Validación de hallazgo]
    C --> D[💀 Foothold]
    D --> E[🧭 Pivoting / Post-explotación]
    E --> F[⬆️ Privesc]
    F --> G[🚩 root.txt]
    style A fill:#0d1117,stroke:#9FEF00,color:#9FEF00
    style D fill:#0d1117,stroke:#F7931E,color:#F7931E
    style F fill:#0d1117,stroke:#ff3e3e,color:#ff3e3e
    style G fill:#0d1117,stroke:#9FEF00,color:#9FEF00
```

</div>

---

## 🖥️ Máquinas

| Máquina | OS | Dificultad | Cadena de ataque | Writeup |
|---|---|---|---|---|
| **Touch** (KIOSK-042) | ![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat-square&logo=windows&logoColor=white) | ![Fácil](https://img.shields.io/badge/F%C3%A1cil-9FEF00?style=flat-square) | Serial como contraseña → kiosk breakout (Edge → `cmd.exe`) → UDF de MySQL → **SYSTEM** | 📄 [Abrir](Machines/Windows/Facil/Touch/README.md) |
| **Layover** (airside-ws01) | ![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat-square&logo=linux&logoColor=black) | ![Media](https://img.shields.io/badge/Media-F7931E?style=flat-square) | RDP contractor → sniffing Wi-Fi en claro → RCE en Craft CMS → CUPS LPE (`CVE-2026-34990`) → **root** | 📄 [Abrir](Machines/Linux/Media/Layover/README.md) |

<details>
<summary>💣 <b>Touch (KIOSK-042)</b> — Kiosk breakout → SYSTEM vía MySQL UDF</summary>

Kiosco de autoservicio de una aerolínea ficticia ("HTB Airways") sobre Windows, gestionado por el portal "Nexion DeviceHub" (8443).

1. **Fuga no autenticada.** `GET /api/status` entrega el número de serie del dispositivo sin autenticación, y ese serial **se reutiliza como contraseña del portal** → acceso al dashboard.
2. **Credenciales de la app → acceso remoto.** El dashboard muestra las credenciales de la cuenta de kiosco. WinRM la rechaza por política, pero **RDP la acepta** → sesión gráfica en el host.
3. **Kiosk breakout.** Apagando por API el escáner de pasaportes y la impresora se fuerza un **error de la aplicación de kiosco**; el diálogo de error abre **Microsoft Edge** vía enlace de soporte, y desde Edge `Ctrl+O` expone el **diálogo nativo de archivos** desde el que se lanza `cmd.exe`.
4. **Escalada a SYSTEM.** Credenciales de MySQL `root` en claro en un `.bat` + servicio **MySQL80 corriendo como `LocalSystem`** + permiso **Modify para Authenticated Users** en `C:\MySQL\lib\plugin` → DLL UDF `sys_eval` → `NT AUTHORITY\SYSTEM`.

📄 Writeup completo: [Machines/Windows/Facil/Touch](Machines/Windows/Facil/Touch/README.md)

</details>

<details>
<summary>✈️ <b>Layover</b> — RDP pivot → sniffing Wi-Fi → Craft CMS RCE → CUPS LPE</summary>

Entorno corporativo de aeropuerto sobre Linux. Host de paso (`airside-ws01`) con acceso RDP **y** presencia en una red Wi-Fi interna mal segmentada, más un portal de empleados y un Craft CMS en la red interna (*assumed breach*: se parte de credenciales válidas).

1. **Acceso inicial.** Credenciales de contratista válidas → **RDP** (xrdp/XFCE) a `airside-ws01`. La cuenta está en los grupos `sudo`, `netdev` y **`wireshark`**.
2. **Red interna por Wi-Fi.** `wlan2` conecta el host de paso a `10.13.37.0/24`; el portal cautivo anuncia el portal de empleados `portal.international.htb/miles/`.
3. **Captura en claro.** Abusando del grupo `wireshark` se pone `wlan2` en **modo monitor** y se esnifa un `POST` **HTTP** a `/miles/login.php` con `username`/`password`.
4. **RCE autenticada en Craft CMS 5.9.8.** El endpoint `element-search` instancia objetos desde JSON y un *behavior* de Yii2 apunta a `ConsoleProcessus::execute()` → ejecución ciega como `www-data` y webshell.
5. **Secretos y pivote.** `.env` → `CRAFT_SECURITY_KEY`; el secreto cifrado del relé de correo se descifra reutilizando la clave (Yii2 `Security`) → `aporter` → **SSH** → `user.txt`.
6. **Escalada a root.** **CUPS 2.4.16** (`CVE-2026-34990`): fuga del token de autenticación local de `cupsd` vía servidor IPP malicioso + escritura arbitraria con `device-uri` `file://` sobre `/etc/sudoers.d/` → `root.txt`.

📄 Writeup completo: [Machines/Linux/Media/Layover](Machines/Linux/Media/Layover/README.md)

</details>

---

## 🧠 Cómo está escrito cada writeup

Estructura fija, pensada para que cualquiera pueda seguir la cadena de ataque y entender el razonamiento:

```
0. Resumen ejecutivo     → la cadena en 6 pasos, el "quién, cómo y desde dónde"
1. Recon                 → superficie expuesta y primeras decisiones
2..N. Cadena de ataque   → cada paso con comandos, salidas reales y las PISTAS
                           que llevaron al siguiente hallazgo
Anexo A. Intentos fallidos → lo que NO funcionó y por qué (la parte valiosa)
Anexo B. Indicadores     → endpoints, credenciales (enmascaradas), gadget, CVE
Anexo C. Cronología      → el ataque de un vistazo (ASCII)
```

**Principio:** una flag sin contexto no enseña nada. Aquí el valor está en **cómo se llegó a ella** — qué pista del entorno la delató, qué suposición falló antes, y qué técnica cerró el paso.

---

## 🛠️ Arsenal habitual

![Nmap](https://img.shields.io/badge/Nmap-2159D6?style=flat-square&logoColor=white&label=nmap)
![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=flat-square&logo=wireshark&logoColor=white&label=tshark)
![Burp Suite](https://img.shields.io/badge/Burp_Suite-F7931E?style=flat-square&label=burp)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white&label=python)
![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white&label=bash)
![Impacket](https://img.shields.io/badge/Impacket-9FEF00?style=flat-square&label=impacket)
![Metasploit](https://img.shields.io/badge/Metasploit-2596CD?style=flat-square&label=metasploit)
![SQLMap](https://img.shields.io/badge/SQLMap-CB171E?style=flat-square&label=sqlmap)
![ffuf](https://img.shields.io/badge/ffuf-9FEF00?style=flat-square&label=ffuf)
![ssh](https://img.shields.io/badge/OpenSSH-2159D6?style=flat-square&label=ssh)

---

<div align="center">

### 📊 Estadísticas

<img src="https://github-readme-stats.vercel.app/api?username=kur0s4k1&show_icons=true&theme=radical&hide_border=true&count_private=true" alt="GitHub stats" height="165" />
<img src="https://streak-stats.demolab.com?user=kur0s4k1&theme=radical&hide_border=true" alt="Streak stats" height="165" />

<img src="assets/terminal-animation.svg" alt="Terminal animada: del reconocimiento a root" width="100%" />

---

> *"Root no es el final del writeup. Es el final de la cadena."*

**kur0s4k1** · writeups en español, orientados a metodología · [GitHub](https://github.com/kur0s4k1)

</div>
