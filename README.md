Network Reconnaissance Tool (Improved)

Herramienta en Python para reconocimiento de red: validación de objetivos, ping sweep, escaneo TCP multihilo, banner grabbing, búsquedas DNS y una aproximación de detección de sistema operativo por TTL.
Esta versión corrige problemas del prototipo y añade robustez, seguridad y salida en JSON/CSV.

Aviso legal: usa esta herramienta únicamente en redes y sistemas que te pertenezcan o para los que tengas permiso explícito. Escanear sin autorización puede ser ilegal.

📑 Tabla de contenidos

✨ Características

⚙ Requisitos

📦 Instalación

▶ Uso rápido (ejemplos)

📘 Referencia CLI

🛠️ Recomendaciones y buenas prácticas

🐞 Solución de problemas

🧭 Roadmap

🤝 Contribuciones

📜 Licencia

✨ Características

Escaneo TCP multihilo (configurable).

Ping sweep sobre rangos de red (CIDR).

Banner grabbing con enfoque best-effort.

Detección básica de SO mediante TTL (heurística).

Validación estricta de puertos (1–65535).

Exportación de resultados a JSON y CSV.

Manejo seguro de concurrencia y timeouts por socket.

Manejo de interrupciones (Ctrl+C) y mensajes informativos.

⚙ Requisitos

Python 3.8 o superior.

No requiere paquetes externos para las funciones básicas.

Opcionales (para ampliar funcionalidad):

scapy — detección de SO más precisa y captura de paquetes.

python-whois o una API de WHOIS — para consultas WHOIS reales.

📦 Instalación
git clone https://github.com/pentesttjp-spec/network-recon-tool.git
cd network-recon-tool

# (opcional) entorno virtual
python3 -m venv venv
source venv/bin/activate   # Linux / macOS
# venv\Scripts\activate    # Windows PowerShell

# comprobar ayuda
python3 scanner.py --help

▶ Uso rápido (ejemplos)

Nota: el script toma como primer argumento el target (IP, hostname o rango CIDR para ping sweep).

Ping sweep en una red (ejemplo /24):
python3 scanner.py 192.168.1.0/24 --ping-sweep

Escaneo de puertos (rango 1–1024) y resolución DNS:
python3 scanner.py example.com -p 1-1024 --port-scan --dns

Escaneo de puertos específicos y guardar resultados:
python3 scanner.py 10.0.0.5 -p 22,80,443 --port-scan --output results
# Crea results.json y/o results.csv (según extensión elegida)

Combinar acciones (DNS + reverse DNS + whois (placeholder)):
python3 scanner.py example.com --dns --reverse-dns --whois

📘 Referencia CLI
Usage: python3 scanner.py <target> [options]

Positional:
  target                Target IP, hostname, or network range (for ping sweep)

Options:
  -p, --ports           Port range (e.g., 1-1000 or 22,80,443)
  -t, --threads         Number of threads (default: 100)
  --ping-sweep          Perform ping sweep (requires CIDR, e.g. 192.168.1.0/24)
  --port-scan           Perform TCP port scan
  --dns                 Perform DNS lookup (A record)
  --reverse-dns         Perform reverse DNS lookup
  --whois               Perform WHOIS lookup (placeholder; integra python-whois para real)
  --output              Save results to file (basename or .json/.csv)

🛠️ Recomendaciones y buenas prácticas

Permiso: obtén autorización antes de escanear redes ajenas.

Rate limiting: para redes grandes, reduce hilos y añade pausas para evitar saturación.

Entorno de pruebas: usa máquinas virtuales o laboratorios (p. ej. TryHackMe, laboratorio local).

Registro de cambios: guarda resultados con --output para trazabilidad.

Extensiones: para detección avanzada añade scapy o python-nmap.

🐞 Solución de problemas

Falla: permission denied al capturar paquetes
Algunas operaciones (raw sockets, sniffing) requieren permisos de root. Ejecuta con sudo si es necesario y tienes permiso:
sudo python3 scanner.py 192.168.1.0/24 --ping-sweep

Ping no responde / hosts no aparecen

El host puede bloquear ICMP (firewall).

Prueba --port-scan contra puertos conocidos si ICMP está bloqueado.

Salida JSON/CSV vacía

Asegurate de ejecutar con las opciones correctas (--port-scan o --ping-sweep).

Revisa permisos de escritura en la carpeta actual.

Timeouts frecuentes

Reduce --threads o aumenta tiempo de espera en el código si tu red es lenta.

🧭 Roadmap (próximas mejoras)

 Escaneo UDP.

 Integración con python-whois / API WHOIS real.

 Integración con python-nmap o scapy para detección avanzada.

 Interfaz web (FastAPI) y reportes HTML.

 Tests unitarios y CI (GitHub Actions).

🤝 Contribuciones

¡Contribuciones bienvenidas!

Abre un issue para reportar bugs o proponer features.

Envía un pull request con pruebas y descripción clara de cambios.

Sigue las buenas prácticas: formatea código (PEP8), añade tests, documenta.

📜 Licencia

Proyecto con licencia MIT. Consulta el archivo LICENSE para el texto completo.

📎 Recursos y agradecimientos

Este proyecto parte de un prototipo de reconocimiento de red; agradecimientos a la comunidad de seguridad por inspiración y buenas prácticas.





