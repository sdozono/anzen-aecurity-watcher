<div align="center">

# 🛡️ Anzen Security Watcher

**Vea lo invisible. Detenga las amenazas silenciosas. Visibilidad de seguridad en tiempo real e inteligencia artificial para todos.**

*Un radar de seguridad ultraligero en tiempo real para Windows 11 y asistente de diagnóstico SOC con IA, desarrollado en C# / .NET 8 WPF nativo.*

[![Language: English](https://img.shields.io/badge/Language-English-0078D4?style=for-the-badge)](./README.md)
[![Language: 日本語](https://img.shields.io/badge/言語-日本語-DC143C?style=for-the-badge)](./README.ja.md)
[![Language: 简体中文](https://img.shields.io/badge/语言-简体中文-DE2910?style=for-the-badge)](./README.zh-CN.md)
[![Language: Español](https://img.shields.io/badge/Idioma-Español-FFC400?style=for-the-badge)](./README.es.md)

[![Platform](https://img.shields.io/badge/Platform-Windows%2011-0078D6?style=flat-square&logo=windows11)](https://www.microsoft.com/windows)
[![Runtime](https://img.shields.io/badge/.NET-8.0%20WPF-512BD4?style=flat-square&logo=dotnet)](https://dotnet.microsoft.com/)
[![Architecture](https://img.shields.io/badge/Engine-Win32%20%26%20NT%20Native%20API-00A4EF?style=flat-square)](#características-principales)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](./LICENSE)

</div>

---

## 🌍 Seleccionar idioma / Choose Your Language

- 🇺🇸 **[English (Default)](./README.md)**
- 🇯🇵 **[日本語 (Japanese)](./README.ja.md)**
- 🇨🇳 **[简体中文 (Simplified Chinese)](./README.zh-CN.md)**
- 🇪🇸 **[Español (Spanish)](./README.es.md)** — Estás aquí

---

## 💡 Descripción general: ¿Por qué "Anzen Security Watcher"?

¿Alguna vez ha visto parpadear una ventana negra de terminal en su pantalla durante apenas **0.2 segundos** y se ha preguntado: *"¿Fue una actualización normal de Windows o acaba de ejecutarse un malware?"*  
¿Alguna vez le ha preocupado si una herramienta de acceso remoto en segundo plano está transmitiendo su pantalla en silencio, o con qué país se está comunicando su PC en este mismo instante?

Los antivirus tradicionales funcionan como una caja negra: hasta que salta una alerta, usted no tiene ninguna visibilidad de lo que realmente hace su computadora. Por otro lado, las soluciones EDR empresariales son demasiado costosas, complejas y pesadas para usuarios individuales o equipos ágiles.

**Anzen Security Watcher** (*"Anzen" significa Seguridad en japonés*) cierra esa brecha. Creado como un proyecto de código abierto personal por un **arquitecto de sistemas con 20 años de experiencia**, transforma la telemetría de bajo nivel de Windows (Win32/NT API) en un panel visual intuitivo en tiempo real, y convierte los registros sospechosos en **prompts listos para pegar en IA** (con anonimización automática de datos privados) para que cualquiera pueda obtener un diagnóstico de nivel analista SOC al instante usando ChatGPT, Claude o Gemini.

---

## 🎯 ¿Para quién es esta herramienta?

| Público objetivo | Cómo le ayuda Anzen Security Watcher |
| :--- | :--- |
| 🧑‍💻 **Usuarios domésticos y teletrabajadores** | Vea al instante si su pantalla, cámara o micrófono se están compartiendo sin su permiso. Obtenga una **Puntuación de Seguridad de 0 a 100 (Grado A–E)** y consulte a la IA con un solo clic si nota algo extraño. |
| 🛡️ **Administradores de TI, SysAdmins y Blue Teams** | Capture **terminales fugaces de 50 ms (0.05 s)**, decodifique PowerShell ofuscado (`-enc`), detecte beacons C2 periódicos, audite claves de persistencia y descubra DLL sideloading sin instalar pesados controladores de kernel. |
| 🏢 **Líderes de Equipo y Administradores** | Obtenga visibilidad instantánea sobre pantallas compartidas no autorizadas, sesiones de escritorio remoto y telemetría sospechosa en equipos de trabajo para proteger datos confidenciales. |
| ⚙️ **Desarrolladores e Investigadores de Seguridad** | Explore una base de código nativa y limpia en C# / .NET 8 WPF que demuestra el uso de Win32 IP Helper API, `NtQueryInformationProcess`, inspección de sesiones WTS y detección estadística de beacons. |

---

## ✨ Características principales

### 1. 🌐 Monitor de tráfico TCP/UDP por país en tiempo real
- **Atribución de sockets a nivel de proceso**: Utiliza las API Win32 IP Helper (`GetExtendedTcpTable` / `GetExtendedUdpTable`) para asociar cada conexión TCP activa y endpoint UDP directamente con su PID, nombre de proceso y ruta del ejecutable.
- **Motor GeoIP híbrido**: Combina resolución CIDR instantánea sin conexión para redes locales/LAN y nubes principales con consultas GeoIP asíncronas sin clave API (`ipwho.is` / `ip-api.com`), guardadas en caché persistente (`Data/geoip_cache.json`).
- **Filtrado por país con un clic**: Haga clic en cualquier tarjeta de resumen de país en la parte superior para aislar el tráfico hacia o desde naciones específicas.
- **Resaltado automático de amenazas**: Marca inmediatamente conexiones externas iniciadas por LOLBins (`powershell`, `cmd`, `rundll32`, `mshta`), puertos de alto riesgo (`3389`, `5900`, `4444`) y jurisdicciones bajo vigilancia.

### 2. 🖥️ Detector en vivo de pantalla compartida y control remoto (Alerta Topmost)
- **Detección integral de Windows RDP**: Verifica simultáneamente las API WTS (`WTSEnumerateSessions` / `WTSQuerySessionInformation`), `GetSystemMetrics(SM_REMOTESESSION)`, el proceso `rdpclip.exe` y el tráfico en el puerto `3389`.
- **Distinción inteligente entre "Servicio en espera" y "Sesión ACTIVA transmitiendo pantalla"**: Supervisa AnyDesk, TeamViewer, UltraVNC/TightVNC/RealVNC, RustDesk, Chrome Remote Desktop, Asistencia rápida de Windows, Parsec, Splashtop, ScreenConnect y LogMeIn, diferenciando si solo están en segundo plano o si **realmente están transmitiendo su pantalla al exterior (ACTIVE)**.
- **Detección de pantalla compartida en videollamadas**: Usa Win32 `EnumWindows` para detectar procesos de captura de Zoom (`CptHost.exe`, bordes verdes `ZPFTEWndClass`), Microsoft Teams, Discord, Slack e indicadores de navegadores web.
- **Sistema de alerta imposible de ignorar**: Muestra un banner rojo superior, abre una **ventana emergente siempre visible (Topmost) en la esquina inferior derecha** y envía una notificación a la bandeja del sistema en cuanto su pantalla comienza a compartirse.

### 3. ⚡ Francotirador de "Terminales Fugaces" (50 ms) y Analizador de Línea de Comandos
- **Motor Sniper de 0.05 segundos (50 ms)**: Mediante sondeo ultrarrápido con Win32 `CreateToolhelp32Snapshot`, captura procesos efímeros que aparecen solo 0.1–0.3 segundos antes de desaparecer, registrando sus **argumentos completos**, **proceso padre** (`svchost/Schedule`, `WmiPrvSE`), **tiempo exacto de vida en milisegundos** y la **tarea programada asociada**.
- **⏰ Correlación con el Programador de tareas (últimos 60 min)**: Con un solo clic escanea todas las carpetas del Programador de tareas de Windows (incluyendo `\Microsoft\Windows`) para identificar qué tarea automática lanzó una ventana fugaz.
- **Detección estadística de Beacons periódicos**: Rastrea el historial de marcas de tiempo de inicio y calcula la media ($\mu$), la desviación estándar ($\sigma$) y el coeficiente de variación ($CV = \sigma / \mu$) para descubrir procesos que se ejecutan en intervalos regulares.
- **Cazador de procesos nuevos, raros o sin firma digital**: Compara los procesos activos con la línea base (`Data/process_baseline.json`) y destaca ejecutables sin firma digital que corren desde `Temp`, `Downloads` o `AppData`.
- **Desofuscación profunda de comandos**: Consulta `NtQueryInformationProcess` para extraer argumentos completos, decodifica automáticamente comandos PowerShell en Base64 (`-enc`) y detecta `IEX`, `DownloadString`, borrado de copias de sombra (`vssadmin delete shadows`) y shells iniciados desde documentos de Office.

### 4. 🛡️ Puntuación de Defensa del Sistema (100 puntos) y Auditoría de 10 Capas
- **📊 Calificación automática de seguridad (0–100 puntos / Grado A–E)**: Evalúa 10 pilares (protección en tiempo real de Microsoft Defender, Firewall de Windows, UAC, SmartScreen, RDP/NLA, UEFI Secure Boot, desactivación de SMBv1, bloqueo de AutoRun, integridad del archivo `hosts` y configuración de proxy) con accesos directos para corregir debilidades.
- **🚀 Monitor de inicio automático y persistencia**: Compara claves `Run`/`RunOnce`, carpetas de inicio, `Winlogon` (`Shell`/`Userinit`), `IFEO` (`Debugger`), servicios y tareas programadas frente a su línea base.
- **🧩 Detector de DLL Sideloading**: Identifica archivos DLL sin firma colocados junto a ejecutables legítimos firmados digitalmente.
- **📷 Privacidad en vivo de Cámara y Micrófono**: Inspecciona `CapabilityAccessManager\ConsentStore` para mostrar qué aplicación está usando su cámara o micrófono en este momento (`LastUsedTimeStop == 0`).
- **🎹 Detección de Keyloggers y 📋 Monitoreo del Portapapeles**: Advierte sobre procesos sospechosos que importan hooks globales de teclado (`SetWindowsHookEx`) o que leen/retienen el portapapeles en segundo plano.
- **🔌 BadUSB, 📜 Certificados Raíz y 🔐 Auditoría de Cuentas**: Alerta sobre nuevos dispositivos USB-HID compuestos, inyección de certificados raíz no autorizados (ataques MITM), eventos de seguridad `4625` (fallos de inicio de sesión) / `4720` (creación de cuentas) y cambios en el grupo local `Administrators`.

### 5. 🤖 Generador de Prompts para IA de Nivel Analista SOC (Privacidad Primero)
- **Prompts de diagnóstico estructurados**: Convierte eventos sospechosos o instantáneas completas del PC en un prompt técnico optimizado para copiar y pegar en ChatGPT, Claude o Gemini.
- **Anonimización automática de privacidad**: Enmascara automáticamente el nombre de su PC (`[MY_PC]`), su usuario de Windows (`[USER_NAME]`) y las direcciones IP privadas (`192.168.x.x`) antes de copiar al portapapeles.

### 6. 🔋 Modo de Ahorro de Energía y Batería (Intervalos de Escaneo Configurables)
- **Frecuencia de escaneo flexible**: Seleccione en Configuración entre «Rápido: 3s», «Estándar: 5s» y «Ahorro: 15s» para maximizar la duración de la batería en portátiles.
- **Escalado automático de escaneos pesados**: Los escaneos detallados de alto consumo (COM de tareas, servicios de Windows, registro) se escalan proporcionalmente (18s / 30s / 90s), y los tiempos de espera del francotirador de procesos se adaptan para reducir el uso de CPU.

---

## 🚀 Instalación y Uso Rápido

### Requisitos del sistema
- **Sistema Operativo**: Windows 11 (se recomienda x64; también compatible con Windows 10)
- **Runtime**: [.NET 8.0 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/8.0) (necesario para ejecutar el instalador MSI o binarios; [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) requerido para compilar desde el código fuente)
- **Privilegios**: Funciona como usuario estándar, pero se recomienda **Ejecutar como administrador** para acceder al registro de eventos de seguridad (`4625`/`4720`) y analizar líneas de comandos de todos los procesos del sistema.

---

### 📦 Para usuarios generales: Instalación mediante el instalador MSI (Recomendado y más sencillo)
Para usuarios que no dispongan de herramientas de desarrollo (.NET SDK o Git), se recomienda utilizar el instalador precompilado:

1. Descargue el archivo **`AnzenSecurityWatcher-Setup-*-x64.msi`** más reciente desde la página de **[Releases](../../releases)**.
2. Ejecute el archivo MSI descargado y siga las instrucciones del asistente de instalación.
   - Se crearán accesos directos automáticamente en el Escritorio y en el Menú Inicio.
   - Tras la instalación, haga clic derecho en el acceso directo y seleccione **"Ejecutar como administrador"**.

---

### 🛠️ Para desarrolladores: Compilación y ejecución desde el código fuente
Para desarrolladores e investigadores de seguridad que deseen inspeccionar el código, personalizar reglas o colaborar. (*Requiere [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)*)

#### 1. Clonar el repositorio
```powershell
git clone https://github.com/sdozono/Anzen-Security-Watcher.git
cd anzen-security-watcher
```

#### 2. Iniciar la aplicación (Dos opciones)
- **Opción A: Inicio rápido con un clic mediante script por lotes**  
  Haga doble clic en **`run-watcher.bat`** en la raíz del proyecto.  
  *(En la primera ejecución compilará e iniciará automáticamente mediante `dotnet run --configuration Release`. En ejecuciones posteriores, iniciará instantáneamente el binario generado `bin\Release\net8.0-windows\AnzenSecurityWatcher.exe`)*

- **Opción B: Compilación y ejecución manual mediante .NET CLI**  
  ```powershell
  dotnet build --configuration Release
  dotnet run --configuration Release
  ```

#### (Opcional) Compilación local del instalador MSI
Para compilar el instalador MSI localmente mediante WiX Toolset v5:
```powershell
powershell -ExecutionPolicy Bypass -File .\build-installer.ps1
```
*(Generará `installer\output\AnzenSecurityWatcher-Setup-*-x64.msi`)*

---

## 🎙️ Mensaje del Desarrollador

> *"A lo largo de dos décadas diseñando sistemas de misión crítica, he visto de primera mano cómo los sistemas operativos modernos pueden ser una 'caja negra' para los usuarios cotidianos e ingenieros.*  
> *Aunque publiqué **Anzen Security Watcher** como un proyecto de código abierto para uso personal, **si está interesado en aprovechar estas ideas para entornos empresariales, gestión centralizada de flotas de miles de PCs o integraciones con IA privada en redes cerradas, no dude en ponerse en contacto.**"*

---

## 🤝 Contribuciones y Consultas（Contributing & Inquiries）

Este es un proyecto personal de código abierto bajo la Licencia MIT. ¡Son bienvenidas las consultas de uso empresarial, los informes de errores y las contribuciones de código!

- 💬 **Consultas Empresariales y de Gran Escala**: Si desea aplicar estos conceptos a la administración centralizada o despliegues corporativos, contáctenos con gusto a través de [GitHub Discussions](../../discussions) o [GitHub Issues](../../issues).
- 🐛 **Reportar Errores o Sugerencias**: Envíe un reporte a través de [GitHub Issues](../../issues).
- 🛠️ **Pull Requests**: Se aceptan con entusiasmo colaboraciones y mejoras de código.

---

## 📄 Licencia（License）

Este proyecto se distribuye bajo los términos de la **[Licencia MIT](./LICENSE)**.

---

<div align="center">
  <sub>Desarrollado con ❤️ y 20 años de artesanía en ingeniería como proyecto personal de código abierto.</sub>
</div>
