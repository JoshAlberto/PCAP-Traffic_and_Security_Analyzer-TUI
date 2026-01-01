import os
import urwid
import pyshark
import threading
import asyncio
from collections import defaultdict
from datetime import datetime

import screens.menu_screen
import screens.actions_screen
import screens.packets_screen
import screens.traffic_analysis_screen
import screens.security_analysis_screen
from screens.security_analysis_screen import SecurityAnalysisScreen

import config
from config import DEFAULT_THRESHOLDS


from paleta.palette import palette



class PcapViewerApp:
    def __init__(self):
        self.spinner_position = 0
        self.spinner_widget = None
        self._spinner_running = False
        self.packets = None
        self.current_file = None
        self.current_screen = None  
        self.thresholds = DEFAULT_THRESHOLDS.copy()

        self.frame = urwid.Frame(urwid.SolidFill())
        self.main_loop = urwid.MainLoop(
            self.frame,
            palette,
            unhandled_input=self.handle_input,
            screen=urwid.raw_display.Screen()
        )

        self.show_menu()
        self.main_loop.run()

    def show_menu(self, *_):
        self.current_screen = 'menu' 

        def on_file_selected(path):
            self.current_file = path
            self.packets = None
            self.show_loading_screen(path)
            self._spinner_running = True
            self.spinner_position = 0
            self.main_loop.set_alarm_in(0.1, self.start_loading_spinner, path)
            threading.Thread(target=self.load_packets_thread, args=(path,), daemon=True).start()

        def on_exit(_):
            self.exit_program()

        frame = screens.menu_screen.MenuScreen.get_widget(
            on_file_selected=on_file_selected,
            on_exit=on_exit
        )
        self.frame.body = frame.body
        self.frame.header = frame.header
        self.frame.footer = frame.footer
        self.current_file = None

    def show_loading_screen(self, filename):
        self.current_screen = 'loading'  

        basename = os.path.basename(filename)
        self.loading_text = urwid.Text(f"Cargando '{basename}'...", align='center')
        spinner_text = urwid.Text("", align='center')
        self.spinner_widget = urwid.AttrMap(spinner_text, 'title')
        pile = urwid.Pile([
            urwid.Filler(urwid.AttrMap(self.loading_text, 'title'), valign='middle', height='pack'),
            urwid.Filler(self.spinner_widget, valign='middle', height='pack')
        ])
        fill = urwid.Filler(pile, valign='middle')
        self.frame.body = urwid.AttrMap(fill, 'body')
        self.frame.footer = None
        self.frame.header = None
        self.spinner_position = 0

    def start_loading_spinner(self, loop, filename):
        spinner_chars = ['|', '/', '-', '\\']
        char = spinner_chars[self.spinner_position % len(spinner_chars)]
        self.spinner_widget.base_widget.set_text(f"{char}")
        self.spinner_position += 1

        if self._spinner_running:
            loop.set_alarm_in(0.1, self.start_loading_spinner, filename)

    def load_packets_thread(self, filename):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            packets = self.read_all_packets(filename)
        except Exception as e:
            packets = []
            print(f"[ERROR] Cargando paquetes: {e}")

        self.packets = packets

        self._spinner_running = False

        def update_ui(loop=None, user_data=None):
            self.show_actions_screen()

        self.main_loop.set_alarm_in(0, update_ui)

    def read_all_packets(self, filepath):
        packets = []
        try:
            cap = pyshark.FileCapture(filepath, keep_packets=False)
            for pkt in cap:
                ip_src = getattr(getattr(pkt, 'ip', None), 'src', 'N/A')
                ip_dst = getattr(getattr(pkt, 'ip', None), 'dst', 'N/A')

                # Mantener los datos originales que tenías:
                packet_dict = {
                    'number': pkt.number,
                    'time': pkt.sniff_time.strftime('%H:%M:%S.%f')[:-3],
                    'proto': pkt.highest_layer,
                    'length': pkt.length,
                    'ip_src': ip_src,
                    'ip_dst': ip_dst,
                    # Agregamos las nuevas claves necesarias para el análisis de seguridad:
                    'sniff_timestamp': float(pkt.sniff_timestamp),
                    'tcp_flags': '',
                    'has_icmp': hasattr(pkt, 'icmp'),
                    'has_arp': hasattr(pkt, 'arp'),
                }

                # Obtener flags TCP si existe capa tcp
                if hasattr(pkt, 'tcp'):
                    tcp_flags = pkt.tcp.get_field_value('flags')
                    packet_dict['tcp_flags'] = tcp_flags if tcp_flags else ''

                packets.append(packet_dict)
            cap.close()
        except Exception as e:
            print(f"[ERROR] Excepción leyendo archivo '{filepath}': {e}")
        return packets

    def show_actions_screen(self):
        self.current_screen = 'actions'

        frame = screens.actions_screen.ActionsScreen.get_widget(
            on_back=self.show_menu,
            on_exit=self.exit_program,
            on_analisis=self.show_traffic_analysis,
            on_resume=self.show_packets,
            on_security=self.show_security_analysis,
        )
        self.frame.body = frame.body
        self.frame.header = frame.header
        self.frame.footer = frame.footer

    def show_packets(self, button=None):
        self.current_screen = 'packets' 

        if not self.packets or not self.current_file:
            self.show_menu()
            return

        basename = os.path.basename(self.current_file)
        frame = screens.packets_screen.PacketsScreen.get_widget(
            self.packets,
            basename,
            on_back=lambda btn: self.show_actions_screen(),
            on_exit=self.exit_program
        )
        self.frame.body = frame.body
        self.frame.header = frame.header
        self.frame.footer = frame.footer

    def show_traffic_analysis(self, button=None):
        if not self.packets or not self.current_file:
            self.show_menu()
            return

        self.current_screen = 'analysis'
        analysis_data = self.analyze_packets(self.packets)
        basename = os.path.basename(self.current_file)
        frame = screens.traffic_analysis_screen.TrafficAnalysisScreen.get_widget(
            analysis_data,
            basename,
            on_back=self.show_actions_screen,
            on_exit=self.exit_program
        )
        self.frame.body = frame.body
        self.frame.header = frame.header
        self.frame.footer = frame.footer

    def show_security_analysis(self, button=None, thresholds=None):
        if not self.packets or not self.current_file:
            self.show_menu()
            return

        if thresholds is None:
            # Extraer timestamps válidos
            timestamps = [
                pkt.get('sniff_timestamp')
                for pkt in self.packets
                if pkt.get('sniff_timestamp') is not None
            ]

            # Determinar duración de la captura
            if timestamps:
                if isinstance(timestamps[0], datetime):
                    duration = (max(timestamps) - min(timestamps)).total_seconds()
                else:
                    duration = max(timestamps) - min(timestamps)
            else:
                duration = 10  # Valor por defecto si no hay timestamps

            # Ajustar thresholds en base a la duración
            thresholds = self.adjust_thresholds_by_duration(duration)

        self.current_screen = 'security'

        #calcular stats con los threshold actualizados
        security_stats = self.analyze_security(self.packets, thresholds)
        
        basename = os.path.basename(self.current_file)

        frame = screens.security_analysis_screen.SecurityAnalysisScreen.get_widget(
            security_stats,
            basename,
            on_back=self.show_actions_screen,
            on_exit=self.exit_program,
            thresholds=thresholds,
            on_apply=self.on_apply_thresholds
        )
        self.frame.body = frame.body
        self.frame.header = frame.header
        self.frame.footer = frame.footer

    def on_apply_thresholds(self):

        new_thresholds = {}

        # Empieza con una copia del threshold actual
        new_thresholds = dict(config.DEFAULT_THRESHOLDS)

        # Solo sobreescribe los que el usuario ha editado
        for key, edit_widget in SecurityAnalysisScreen.threshold_edits.items():
            text = edit_widget.edit_text.strip()
            try:
                if not text:
                    continue  # deja el valor por defecto
                elif key == 'BPS_THRESHOLD':
                    new_thresholds[key] = int(text)
                elif key in ['PPS_THRESHOLD', 'DOS_TIME_WINDOW']:
                    new_thresholds[key] = float(text)
                else:
                    new_thresholds[key] = int(text)
            except ValueError:
                pass  # ignora errores, mantiene el valor por defecto


        # Actualizar los thresholds almacenados en self
        self.thresholds.update(new_thresholds)

        # Ahora recalcula el análisis con los nuevos thresholds
        security_stats = self.analyze_security(self.packets, self.thresholds)

        # Actualizar UI con datos nuevos y thresholds actualizados
        frame = screens.security_analysis_screen.SecurityAnalysisScreen.get_widget(
            security_stats,
            filename=os.path.basename(self.current_file),
            on_back=self.show_actions_screen,
            on_exit=self.exit_program,
            thresholds=self.thresholds,
            on_apply=self.on_apply_thresholds
        )
        self.frame.body = frame.body
        self.frame.header = frame.header
        self.frame.footer = frame.footer

    def adjust_thresholds_by_duration(sel,duration_seconds):
        factor = max(duration_seconds / 10, 0.1)
        adjusted = config.DEFAULT_THRESHOLDS.copy()

        fixed_keys = ['PPS_THRESHOLD', 'BPS_THRESHOLD', 'DST_THRESHOLD', 'DOS_TIME_WINDOW', 'DOS_PACKET_THRESHOLD']

        for key in adjusted:
            if key in fixed_keys:
                # No cambiar el valor
                adjusted[key] = adjusted[key]
            else:
                # Ajustar con el factor
                adjusted[key] = round(adjusted[key] * factor)

        return adjusted

    def analyze_security(self, packets, thresholds):
        from collections import defaultdict

        syn_packets_from_ip = defaultdict(int)
        unique_dst_per_src = defaultdict(set)
        packet_counts_per_ip = defaultdict(int)
        packet_timestamps_per_ip = defaultdict(list)
        icmp_count = 0
        arp_count = 0
        total_bytes = 0
        total_packets = len(packets)

        if total_packets == 0:
            return {
                'port_scan_ips': [],
                'dos_ips': [],
                'icmp_count': 0,
                'arp_count': 0,
                'icmp_suspicious': False,
                'arp_suspicious': False,
                'pps': 0,
                'bps': 0,
                'pps_alert': False,
                'bps_alert': False,
                'top_src_ips': [],
            }

        start_time = None
        end_time = None
        # Buscar el primer y último timestamp válido
        for pkt in packets:
            ts = pkt.get('sniff_timestamp')
            if ts is not None:
                if start_time is None or ts < start_time:
                    start_time = ts
                if end_time is None or ts > end_time:
                    end_time = ts

        if start_time is None or end_time is None:
            # No hay timestamps válidos, no se puede analizar
            return {
                'port_scan_ips': [],
                'dos_ips': [],
                'icmp_count': 0,
                'arp_count': 0,
                'icmp_suspicious': False,
                'arp_suspicious': False,
                'pps': 0,
                'bps': 0,
                'pps_alert': False,
                'bps_alert': False,
                'top_src_ips': [],
            }

        duration = max(end_time - start_time, 1)  # evitar división por cero

        SYN_THRESHOLD = thresholds.get('SYN_THRESHOLD', config.DEFAULT_THRESHOLDS['SYN_THRESHOLD'])
        DST_THRESHOLD = thresholds.get('DST_THRESHOLD', config.DEFAULT_THRESHOLDS['DST_THRESHOLD'])
        ICMP_THRESHOLD = thresholds.get('ICMP_THRESHOLD', config.DEFAULT_THRESHOLDS['ICMP_THRESHOLD'])
        ARP_THRESHOLD = thresholds.get('ARP_THRESHOLD', config.DEFAULT_THRESHOLDS['ARP_THRESHOLD'])
        PPS_THRESHOLD = thresholds.get('PPS_THRESHOLD', config.DEFAULT_THRESHOLDS['PPS_THRESHOLD'])
        BPS_THRESHOLD = thresholds.get('BPS_THRESHOLD', config.DEFAULT_THRESHOLDS['BPS_THRESHOLD'])
        DOS_PACKET_THRESHOLD = thresholds.get('DOS_PACKET_THRESHOLD', config.DEFAULT_THRESHOLDS['DOS_PACKET_THRESHOLD'])
        DOS_TIME_WINDOW = thresholds.get('DOS_TIME_WINDOW', config.DEFAULT_THRESHOLDS['DOS_TIME_WINDOW'])


        for pkt in packets:
            try:
                total_bytes += int(pkt.get('length', 0))
            except Exception:
                pass

            src_ip = pkt.get('ip_src', 'N/A')
            dst_ip = pkt.get('ip_dst', 'N/A')

            packet_counts_per_ip[src_ip] += 1

            timestamp = pkt.get('sniff_timestamp')
            if timestamp is not None:
                packet_timestamps_per_ip[src_ip].append(timestamp)

            unique_dst_per_src[src_ip].add(dst_ip)

            flags_str = pkt.get('tcp_flags', '')
            if 'S' in flags_str and 'A' not in flags_str:
                syn_packets_from_ip[src_ip] += 1

            if pkt.get('has_icmp', False):
                icmp_count += 1

            if pkt.get('has_arp', False):
                arp_count += 1


        port_scan_ips = [ip for ip in syn_packets_from_ip if syn_packets_from_ip[ip] > SYN_THRESHOLD or len(unique_dst_per_src[ip]) > DST_THRESHOLD]

        dos_ips = []
        for ip, timestamps in packet_timestamps_per_ip.items():
            timestamps.sort()
            start_idx = 0
            for end_idx in range(len(timestamps)):
                while timestamps[end_idx] is not None and timestamps[start_idx] is not None and timestamps[end_idx] - timestamps[start_idx] > DOS_TIME_WINDOW:
                    start_idx += 1
                if (end_idx - start_idx + 1) >= DOS_PACKET_THRESHOLD:
                    dos_ips.append(ip)
                    break

        icmp_suspicious = icmp_count >= ICMP_THRESHOLD
        arp_suspicious = arp_count >= ARP_THRESHOLD

        packets_per_sec = total_packets / duration
        bytes_per_sec = total_bytes / duration
        pps_alert = packets_per_sec > PPS_THRESHOLD
        bps_alert = bytes_per_sec > BPS_THRESHOLD

        top_src_ips = sorted(packet_counts_per_ip.items(), key=lambda x: x[1], reverse=True)[:5]

        stats = {
            'port_scan_ips': port_scan_ips,
            'dos_ips': dos_ips,
            'icmp_count': icmp_count,
            'arp_count': arp_count,
            'icmp_suspicious': icmp_suspicious,
            'arp_suspicious': arp_suspicious,
            'pps': packets_per_sec,
            'bps': bytes_per_sec,
            'pps_alert': pps_alert,
            'bps_alert': bps_alert,
            'top_src_ips': top_src_ips,
        }

        return stats

    def analyze_packets(self, packets):
        from datetime import datetime

        stats = {
            'protocol_counts': {},
            'protocol_sizes': {},
            'src_ips': {},
            'dst_ips': {},
            'tcp_flags': {'SYN': 0, 'ACK': 0, 'FIN': 0, 'RST': 0},
            'total_size': 0,
            'timestamps': []
        }

        for pkt in packets:
            proto = pkt.get('proto', 'UNKNOWN')
            size = int(pkt.get('length', 0))
            ip_src = pkt.get('ip_src', 'N/A')
            ip_dst = pkt.get('ip_dst', 'N/A')

            # Conteos por protocolo
            stats['protocol_counts'][proto] = stats['protocol_counts'].get(proto, 0) + 1
            stats['protocol_sizes'][proto] = stats['protocol_sizes'].get(proto, 0) + size
            stats['src_ips'][ip_src] = stats['src_ips'].get(ip_src, 0) + 1
            stats['dst_ips'][ip_dst] = stats['dst_ips'].get(ip_dst, 0) + 1

            stats['total_size'] += size

            # Timestamps para duración
            try:
                ts = datetime.strptime(pkt['time'], '%H:%M:%S.%f')
                stats['timestamps'].append(ts)
            except Exception:
                pass

            # Contar flags TCP solo si es TCP
            if proto == 'TCP':
                flags_str = pkt.get('tcp_flags', '')
                # Los flags podrían venir separados por coma, espacio o sin separación
                # Ajusta según formato real
                flags = [f.strip().upper() for f in flags_str.replace(',', ' ').split()]
                for flag in ['SYN', 'ACK', 'FIN', 'RST']:
                    if flag in flags:
                        stats['tcp_flags'][flag] += 1

        # Calcular duración y tasa de paquetes por segundo
        if stats['timestamps']:
            duration = (max(stats['timestamps']) - min(stats['timestamps'])).total_seconds()
            stats['packets_per_second'] = len(stats['timestamps']) / duration if duration > 0 else len(stats['timestamps'])
        else:
            duration = 0
            stats['packets_per_second'] = 0
        stats['duration_seconds'] = duration

        # Tamaño promedio por protocolo
        avg_sizes = {}
        for proto in stats['protocol_counts']:
            count = stats['protocol_counts'][proto]
            total_size = stats['protocol_sizes'][proto]
            avg_sizes[proto] = total_size / count if count > 0 else 0
        stats['avg_sizes'] = avg_sizes

        # Top N IPs
        def top_n(d, n=5):
            return sorted(d.items(), key=lambda x: x[1], reverse=True)[:n]
        stats['top_src_ips'] = top_n(stats['src_ips'])
        stats['top_dst_ips'] = top_n(stats['dst_ips'])

        return stats


    def handle_input(self, key):
        if key in ('esc', 'ESC'):
            self.exit_program()
        elif key in ('r', 'R'):
            # Navegación según pantalla actual
            if self.current_screen in ('packets', 'analysis','security'):
                self.show_actions_screen()
            else:
                self.show_menu()

    def exit_program(self, *_):
        raise urwid.ExitMainLoop()


if __name__ == '__main__':
    PcapViewerApp()