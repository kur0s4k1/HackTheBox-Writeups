# HackTheBox — Writeups

Repositorio personal de writeups de HackTheBox, con formato orientado a auditoría: procedimiento paso a paso, comandos ejecutados, decisiones, intentos fallidos y evidencia visual verificable.

**Máquinas documentadas: 1**

## Índice

| Máquina | OS | Dificultad | Fecha | Writeup |
|---|---|---|---|---|
| Touch (KIOSK-042) | Windows | Fácil | 2026-10-10 | [Machines/Windows/Facil/Touch](Machines/Windows/Facil/Touch/README.md) |

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

## Estructura

```
HackTheBox-Writeups/
├── README.md
├── Machines/
│   ├── Linux/
│   │   └── <Dificultad>/
│   │       └── <Máquina>/
│   └── Windows/
│       └── Facil/
│           └── Touch/
│               ├── README.md          (writeup técnico)
│               └── screenshots/       (evidencia numerada por fase)
├── Challenges/
└── Sherlocks/
```

Las máquinas se organizan por sistema operativo y, dentro de cada uno, por dificultad (`Facil`, `Media`, `Dificil`, `Insane`). Cada carpeta de máquina contiene su `README.md` (writeup) y `screenshots/` con las capturas referenciadas por el documento. Las imágenes usan prefijo de fase (`04_*` acceso, `05_*` breakout, `06_*` shell+user flag, `07_*` post-explotación, `08_*`/`09_*` privesc/root, `A_*` anexos).
