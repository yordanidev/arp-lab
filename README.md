# ARP Lab

Herramienta de escritorio (PyQt5 + Scapy) para practicar envenenamiento de cachés ARP/NDP **exclusivamente en redes de laboratorio aisladas**. Permite verificar cómo se deja sin conectividad a un host, y restaurar la red automáticamente al detener.

Esta es una implementación propia: la interfaz está hecha con **PyQt5**, no con Tkinter, y el código no procede de ningún tutorial externo. Partimos de la idea general de ARP spoofing y desarrollamos la herramienta desde cero, con correcciones propias para IPv6, `ip_forward`, hilos y restauración.

> **Aviso legal y de uso:** este software es solo para enseñanza y pruebas en entornos controlados propios (VM en red interna/host-only) o con autorización explícita por escrito. Usarlo contra redes o dispositivos ajenos puede ser ilegal. El autor no se hace responsable de su uso indebido.

## Inicio rápido

Descarga el proyecto y ejecuta una sola orden:

```bash
git clone <URL_DEL_REPO> arp-lab && cd arp-lab
bash start.sh
```

`start.sh` crea `.venv`, instala `PyQt5` y `scapy` desde `requirements.txt`, pide la contraseña de `sudo` y abre la ventana. No necesitas instalar nada más. Si el sistema te pide antes `python3-venv`:

```bash
sudo apt install python3-venv
```

## Qué hace

- Detecta interfaces, IP local, gateway IPv4 y subred (leyendo `/proc/net/route`).
- Barrido ARP para listar hosts de la subred con su MAC.
- Envenenamiento ARP bidireccional: al víctima le anuncia que el gateway tiene la MAC del atacante, y al gateway que la víctima tiene esa MAC.
- Bloqueo IPv6 opcional mediante anuncios NDP (`ICMPv6ND_NA`) falsos para los gateways de la vecindad.
- Si `net.ipv4.ip_forward` está a `1`, lo desactiva durante la prueba y restaura el valor original al terminar; si no, el atacante reenviaría el tráfico y la víctima seguiría con internet.
- Detección automática de objetivo desaparecido o con MAC cambiada: detiene la prueba y restaura.
- Restauración siempre en `finally` (ARP, IPv6 e `ip_forward`), también al cerrar la ventana.
- Registro con marcas de tiempo y exportación a archivo de texto como evidencia.

## Requisitos

- Linux (usa `AF_PACKET`, `/proc/net/route` y `/proc/sys/net/ipv4/ip_forward`).
- Python 3.9 o superior.
- Dependencias: `PyQt5`, `scapy` (ver `requirements.txt`); `start.sh` las instala solas en `.venv`.
- Privilegios de root para abrir raw sockets y modificar `ip_forward`; `start.sh` solicita `sudo` por ti.

Instalación manual (opcional, si no quieres usar `start.sh`):

```bash
sudo apt install python3-venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo -E .venv/bin/python run.py
```

La opción `-E` conserva `DISPLAY` y `XAUTHORITY` para que la ventana aparezca en tu sesión gráfica. Si ya instalaste las dependencias a nivel sistema, basta con `sudo -E python3 run.py`.

## Uso

1. **Preflight:** la franja roja indica si hay permisos para raw sockets. Si no, los botones quedan deshabilitados; pulsa *Reintentar permisos* tras relanzar con `sudo`.
2. **Red:** elige la interfaz; la IP local, MAC y gateway se rellenan automáticamente. Puedes corregir el gateway a mano.
3. **Escanear hosts (ARP):** lista los hosts vivos; selecciona el objetivo en el desplegable editable.
4. Marca la casilla de **autorización/laboratorio aislado** y, si quieres cubrir también IPv6, *Bloquear también IPv6 (NDP)* (activada por defecto).
5. **Iniciar prueba.** Ajusta el intervalo de envío (1-10 s).
6. **Detener y restaurar** cuando termines. La restauración es automática; *Solo restaurar* permite repetirla sin atacar.
7. **Exportar log** guarda la evidencia. Revísala antes de compartirla: puede contener IPs y MACs internas.

### Verificación en la víctima

Durante la prueba, en el equipo objetivo:

```bash
arp -a                 # Windows
ip neigh show          # Linux
```

La IP del gateway debe aparecer con la MAC de la máquina atacante. Tras detener, debe volver a la MAC real del router. Si con `ip_forward=0` el objetivo pierde toda conectividad, se trata de un DoS de capa 2: esta herramienta no captura payload ni hace interceptación completa.

## Solución de problemas

| Síntoma | Causa probable | Acción |
| --- | --- | --- |
| `PermissionError: Operación no permitida` | Sin raw sockets | Ejecutar con `sudo -E` (o aplicar `cap_net_raw` al intérprete). |
| El corte dura solo un instante | `ip_forward=1` en el atacante | La app lo corrige; confirma en el log que aparece `ip_forward desactivado`. |
| YouTube u otros servicios siguen funcionando | Tráfico IPv6 o datos móviles del teléfono | Mantén activado el bloqueo NDP; desactiva los datos móviles en el móvil. |
| El objetivo deja de responder | Cambió de Wi‑Fi, de IP o rotó su MAC privada | La app se detiene sola; vuelve a escanear y selecciona la nueva IP. |
| No aparece ningún host | Otra SSID, segmento distinto o aislamiento de clientes en el AP | Coloca el atacante en la misma capa 2 que el objetivo. |
| El móvil sigue con internet tras todo lo anterior | Pasó a 4G/5G | No se puede frenar desde la LAN: usa control parental del router o del dispositivo. |

## Detección y defensa

- **MITRE ATT&CK:** T1557.003 — Adversary-in-the-Middle: ARP Cache Poisoning.
- En switches: **DHCP snooping + DAI** (DAI depende de la tabla de binding de DHCP snooping), port-security y 802.1X.
- En hosts: entradas IP-MAC estáticas en activos críticos, `arpwatch`, `arptables`.
- En IDS/IPS: alertas por ARP gratuitos repetidos, una IP con dos MAC o la IP del gateway con MAC de host final (filtro Wireshark: `arp`).

## Estructura

```
start.sh         Lanzador: crea .venv, instala dependencias, pide sudo y abre la app
arp_lab.py       Aplicación PyQt5, detección de red, workers QThread y restauración
run.py           Punto de entrada
requirements.txt Dependencias
README.md        Esta guía
LICENSE          Licencia MIT
```

Los apuntes del vídeo que inspiraron la idea general del proyecto se conservan solo en local y están excluidos del repositorio: no forman parte de esta documentación ni de esta implementación. `evidencia_arp.txt` también es un artefacto local de pruebas y está excluido.

## Licencia

MIT. Ver `LICENSE`.
