# 🚀 Network Reconnaissance Tool (Improved)

Herramienta en Python para reconocimiento de red: validación de objetivos, ping sweep, escaneo de puertos TCP, banner grabbing, DNS y una aproximación de detección de SO por TTL.

## ✨ Características
- Timeouts por socket (no globales).
- Recolección thread-safe de resultados.
- Banner grabbing más robusto.
- Validación estricta de puertos.
- Guardado de resultados (JSON/CSV).
- Mejor manejo de interrupciones y mensajes informativos.

> ⚠️ **Aviso legal:** Usa esta herramienta **solo** en redes y sistemas bajo tu control o con permiso explícito. Escanear sin autorización puede ser ilegal.

## ⚙️ Requisitos
- Python 3.8+  
- No requiere dependencias externas para las funciones incluidas.

Opcionales:
- `scapy` para detección de SO avanzada.  
- `python-whois` o API de WHOIS para consultas reales.

## 🚀 Instalación
```bash
git clone https://github.com/pentesttjp-spec/network-recon-tool.git
cd network-recon-tool
python3 -m venv venv
source venv/bin/activate
python3 scanner.py --help
```

## 📊 Ejemplos de uso
```bash
# Ayuda
python3 scanner.py --help

# Ping sweep en una red
python3 scanner.py 192.168.1.0/24 --ping-sweep

# Escaneo de puertos y DNS
python3 scanner.py example.com -p 1-1024 --port-scan --dns

# Escanear puertos concretos y guardar resultados
python3 scanner.py 10.0.0.5 -p 22,80,443 --port-scan --output results
```





