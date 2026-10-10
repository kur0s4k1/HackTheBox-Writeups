# HackTheBox — Writeups

Repositorio personal de writeups de HackTheBox, con formato orientado a auditoría: procedimiento paso a paso, comandos ejecutados, decisiones, intentos fallidos y evidencia visual verificable.

**Máquinas documentadas: 1**

## Índice

| Máquina | OS | Dificultad | Fecha | Writeup |
|---|---|---|---|---|
| Touch (KIOSK-042) | Windows | Fácil | 2026-10-10 | [Machines/Windows/Facil/Touch](Machines/Windows/Facil/Touch/README.md) |

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
