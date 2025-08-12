# 🛡 Sherminator - OS Detector by OIHEC

Herramienta sencilla en Go para detectar el sistema operativo probable (Windows, Linux, macOS, Android o iOS) en una máquina remota  
basándose en la apertura de puertos TCP característicos y exclusivos para cada sistema.

---

## 🚀 Instalación

### Requisitos

- Tener instalado Go (versión 1.15+ recomendada)  
  [Descarga Go](https://go.dev/dl/)

### Pasos

1. Clona o descarga este repositorio:  
```bash
git clone https://github.com/tu_usuario/sherminator.git
cd sherminator
Compila la herramienta:


go build sherminator.go
Esto generará un ejecutable llamado sherminator (o sherminator.exe en Windows).

🛠 Uso
Ejecuta la herramienta indicando el IP o dominio que quieres escanear:


./sherminator -target 192.168.1.4
La herramienta escaneará puertos clave y mostrará el sistema operativo probable junto con un icono representativo:

🪟 Windows

🐧 Linux

🍏 macOS

🤖 Android

📱 iOS

📋 Cómo funciona
Sherminator detecta puertos TCP típicos y exclusivos en cada sistema operativo, como:

Windows: 135, 139, 445, 3389, 5985, etc.

Linux: 22, 25, 53, 111, 2049, 3306, etc.

macOS: 548, 427, 3689, 62078, etc.

Android: 5228, 8081, 5353, etc.

iOS: 62078, 5353, 3689, etc.

Luego reporta el SO que tenga más coincidencias de puertos abiertos.

⚠ Advertencia
Esta herramienta es para fines educativos y auditorías en sistemas propios o con permiso.

El escaneo de puertos puede generar alertas en sistemas de seguridad.

No se recomienda usar en entornos no autorizados.
