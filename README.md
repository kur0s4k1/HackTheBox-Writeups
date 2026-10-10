# HackTheBox — Writeups

Repositorio personal de writeups de HackTheBox, con formato orientado a auditoría: procedimiento paso a paso, comandos ejecutados, decisiones, intentos fallidos y evidencia visual verificable.

> **Nota de cumplimiento (reglas HTB) y divulgación responsable:** no se deben publicar writeups de máquinas mientras estén **activas**. Si se publica una máquina aún activa como referencia metodológica, **las flags, contraseñas, seriales y nombres de usuario deben ir enmascarados o redactados** (texto e imágenes). En este repositorio las credenciales sensibles aparecen enmascaradas (p. ej. `1416fd69****`, `K!0sk****`) y las capturas con secretos están **redactadas**. Mientras la máquina siga activa, mantén el repositorio **privado**.

## Índice

| Máquina | OS | Dificultad | Fecha | Writeup |
|---|---|---|---|---|
| Touch (KIOSK-042) | Windows | Fácil | 2026-10-10 | [Machines/Windows/Touch](Machines/Windows/Touch/README.md) |

## Estructura

```
HackTheBox-Writeups/
├── README.md
├── Machines/
│   ├── Linux/
│   └── Windows/
│       └── Touch/
│           ├── README.md          (writeup técnico)
│           └── screenshots/       (evidencia numerada por fase)
├── Challenges/
└── Sherlocks/
```

Cada carpeta de máquina contiene su `README.md` (writeup) y `screenshots/` con las capturas referenciadas por el documento. Las imágenes usan prefijo de fase (`04_*` acceso, `05_*` breakout, `06_*` shell+user flag, `07_*` post-explotación, `08_*`/`09_*` privesc/root, `A_*` anexos).
