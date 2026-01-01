import urwid
from widgets import SimpleButton, SimpleButtonBlue, Collapsible
from config import DEFAULT_THRESHOLDS

class SecurityAnalysisScreen:
    @staticmethod
    def get_widget(security_data, filename, on_back, on_exit, thresholds=None, on_apply=None):
        if thresholds is None:
            thresholds = DEFAULT_THRESHOLDS.copy()

        header = urwid.Text(f"Security Analysis - {filename}", align='center')
        header = urwid.AttrMap(urwid.LineBox(header), 'box')

        def boxed_section(title, lines, alert=False):
            title_style = 'title_alert' if alert else 'title'
            box_style = 'box_alert' if alert else 'box'
            title_text = urwid.Text((title_style, f'● {title}'), align='left')
            body = [title_text, urwid.Divider()] + [urwid.Text(line) for line in lines]
            pile = urwid.Pile(body)
            return urwid.AttrMap(urwid.LineBox(pile), box_style)

        sections = []

        # 1. Escaneo de Puertos
        port_scan_ips = security_data.get("port_scan_ips", [])
        port_scan_lines = (
            [f"{ip} (posible escaneo SYN)" for ip in port_scan_ips]
            if port_scan_ips else ["No se detectaron IPs sospechosas."]
        )
        port_scan_alert = bool(port_scan_ips)
        sections.append(boxed_section("🛑 Detección de Escaneo de Puertos", port_scan_lines, port_scan_alert))

        # 2. Posible ataque DoS/DDoS
        dos_ips = security_data.get("dos_ips", [])
        dos_lines = (
            [f"{ip} (envió muchos paquetes a múltiples destinos)" for ip in dos_ips]
            if dos_ips else ["No se detectaron IPs sospechosas."]
        )
        dos_alert = bool(dos_ips)
        sections.append(boxed_section("🪓 Posible Ataque DoS/DDoS", dos_lines, dos_alert))

        # 3. Reconocimiento o tráfico sospechoso
        icmp_count = security_data.get("icmp_count", 0)
        arp_count = security_data.get("arp_count", 0)
        icmp_susp = security_data.get("icmp_suspicious", False)
        arp_susp = security_data.get("arp_suspicious", False)
        recon_lines = [
            f"ICMP (ping): {icmp_count} {'⚠️ Sospechoso' if icmp_susp else ''}",
            f"ARP: {arp_count} {'⚠️ Sospechoso' if arp_susp else ''}"
        ]
        recon_alert = icmp_susp or arp_susp
        sections.append(boxed_section("🧻 Reconocimiento / Tráfico Sospechoso", recon_lines, recon_alert))

        # 4. Tasa anormal de tráfico
        pps = security_data.get("pps", 0)
        bps = security_data.get("bps", 0)
        pps_alert = security_data.get("pps_alert", False)
        bps_alert = security_data.get("bps_alert", False)
        traffic_lines = [
            f"Paquetes por segundo (PPS): {pps:.2f} {'⚠️ Elevado' if pps_alert else ''}",
            f"Bytes por segundo (BPS): {bps:.2f} {'⚠️ Elevado' if bps_alert else ''}"
        ]
        traffic_alert = pps_alert or bps_alert
        sections.append(boxed_section("🧨 Tasa Anormal de Tráfico", traffic_lines, traffic_alert))

        # 5. IPs más activas
        top_src_ips = security_data.get("top_src_ips", [])
        top_lines = [f"{ip}: {count} paquetes" for ip, count in top_src_ips] if top_src_ips else ["No hay datos."]
        sections.append(boxed_section("👁 Top 5 IPs que más envían tráfico", top_lines))

        # --- Threshold configuration section with individual collapsibles ---
        explanations = {
            "SYN_THRESHOLD": (
                "SYN Threshold without ACK",
                "What it is: \nMinimum number of TCP packets with the SYN flag (connection initiation) and without the ACK flag sent from a single IP.\n\n"
                "Purpose:\nDetect potential port scans. A scanner typically sends many SYN packets to different ports without completing the connection (no ACK).\n\n"
                "Why modify it:\nAdjusts sensitivity to detect scans. If set too low, it might flag legitimate traffic as suspicious; if too high, it might miss small scans."
            ),
            "DST_THRESHOLD": (
                "Distinct Destination Threshold per IP",
                "What it is: \nMinimum number of distinct destinations to which a single IP sends packets.\n\n"
                "Purpose:\nAlso helps detect scanning activity, as scanners often attempt to reach many different destinations or ports.\n\n"
                "Why modify it:\nIf your network has many legitimate connections to multiple destinations, you might want to increase this to reduce false positives."
            ),
            "DOS_PACKET_THRESHOLD": (
                "Packet Threshold to Detect DoS/DDoS",
                "What it is: \nMinimum number of packets sent by a single IP within a small time window (DOS_TIME_WINDOW).\n\n"
                "Purpose:\nDetect denial-of-service (DoS) attacks, where an IP sends a large number of packets in a short time.\n\n"
                "Why modify it:\nAdjust the threshold to filter out normal traffic spikes or highlight abnormal ones."
            ),
            "DOS_TIME_WINDOW": (
                "Time Window for DoS/DDoS",
                "What it is: \nTime (in seconds) during which packets are counted to detect a possible DoS.\n\n"
                "Purpose:\nDefines the time interval for measuring the packet count.\n\n"
                "Why modify it:\nMake it shorter to detect very fast bursts, or longer to detect slow, persistent attacks."
            ),
            "ICMP_THRESHOLD": (
                "Suspicious ICMP Packet Threshold",
                "What it is: \nMinimum number of ICMP packets detected before marking ICMP traffic as suspicious.\n\n"
                "Purpose:\nExcessive ICMP traffic can be used for reconnaissance (ping sweep) or attacks (e.g., Smurf).\n\n"
                "Why modify it:\nAdjust to avoid false positives in networks where ICMP traffic is common."
            ),
            "ARP_THRESHOLD": (
                "Suspicious ARP Packet Threshold",
                "What it is: \nMinimum number of ARP packets required to mark ARP traffic as suspicious.\n\n"
                "Purpose:\nA high number of ARP packets may indicate an ARP poisoning attack (ARP spoofing).\n\n"
                "Why modify it:\nAdjust based on the size and normal activity of your network."
            ),
            "PPS_THRESHOLD": (
                "Packets Per Second (PPS)",
                "What it is: \nMaximum acceptable number of packets per second in the entire capture to avoid marking the rate as abnormal.\n\n"
                "Purpose:\nDetect high general traffic rates that may indicate attacks or congestion.\n\n"
                "Why modify it:\nAdjust according to your network’s capacity and typical traffic levels."
            ),
            "BPS_THRESHOLD": (
                "Bytes Per Second (BPS)",
                "What it is: \nMaximum acceptable number of bytes per second to avoid marking the byte rate as abnormal.\n\n"
                "Purpose:\nSimilar to PPS, but measures volume in bytes to detect excessive traffic.\n\n"
                "Why modify it:\nAdjust based on available bandwidth and normal traffic volume."
            ),
        }


        threshold_widgets = []
        SecurityAnalysisScreen.threshold_edits = {}

        for key, (title, explanation) in explanations.items():
            value = thresholds.get(key, '')
            edit = urwid.Edit(('text_blue', f"{key} ({title}): "), str(value))
            expl_text = urwid.Text(('text_white', explanation))
            content_pile = urwid.Pile([edit, urwid.Divider(), expl_text, urwid.Divider()])
            collapsible = Collapsible(
                title=f"{key} ({title})",
                content_widget=content_pile,
                expanded=False  # empieza cerrado
            )
            threshold_widgets.append(collapsible)
            SecurityAnalysisScreen.threshold_edits[key] = edit

        # Botón aplicar cambios
        apply_button = SimpleButtonBlue("Apply thresholds", on_press=lambda btn: on_apply())
        apply_button_padded = urwid.Padding(apply_button, align='center', width=20)


        # Unimos collapsibles y botón en un solo Pile para que el LineBox los contenga a ambos
        threshold_content_with_button = urwid.Pile(threshold_widgets + [urwid.Divider(), apply_button_padded])

        # El LineBox incluye todo: collapsibles + botón
        threshold_linebox = urwid.LineBox(threshold_content_with_button, title="Configuración de Umbrales (Thresholds)")

        # Color y estilo del recuadro completo
        threshold_box = urwid.AttrMap(threshold_linebox, 'box_blue')

        # Añadimos la sección de thresholds a las secciones
        sections.append(threshold_box)

        list_box = urwid.ListBox(urwid.SimpleFocusListWalker(sections))

        back_btn = SimpleButton("← Return (R)", on_press=lambda _: on_back())
        exit_btn = SimpleButton("Exit (ESC)", on_press=lambda _: on_exit())
        footer = urwid.Columns([
            ('weight', 1, urwid.AttrMap(urwid.LineBox(back_btn), 'button_box')),
            ('weight', 1, urwid.AttrMap(urwid.LineBox(exit_btn), 'button_box')),
        ], dividechars=2)
        footer = urwid.Padding(footer, left=2, right=2)

        return urwid.Frame(body=list_box, header=header, footer=footer)

