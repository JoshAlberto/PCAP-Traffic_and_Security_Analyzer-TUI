import urwid
from widgets import SimpleButton


class TrafficAnalysisScreen:
    @staticmethod
    def get_widget(analysis_data, filename, on_back, on_exit):
        header = urwid.Text(f"Traffic Analisis - {filename}", align='center')
        header = urwid.AttrMap(urwid.LineBox(header), 'box')

        def boxed_section(title, lines):
            title_text = urwid.Text(('title', f'● {title}'), align='left')
            body = [title_text, urwid.Divider()] + [urwid.Text(line) for line in lines]
            pile = urwid.Pile(body)
            return urwid.AttrMap(urwid.LineBox(pile), 'box')

        sections = []

        # RESUMEN → lo ponemos primero
        resumen_lines = [
            f"Duración: {analysis_data.get('duration_seconds', 0):.3f} segundos",
            f"Total de paquetes: {sum(analysis_data.get('protocol_counts', {}).values())}",
            f"Promedio de paquetes por segundo: {analysis_data.get('packets_per_second', 0):.2f}",
            f"Tamaño total: {analysis_data.get('total_size', 0)} bytes"
        ]
        sections.append(boxed_section("Resumen", resumen_lines))

        # PROTOCOLOS
        proto_lines = [f"{proto}: {count} paquetes" for proto, count in analysis_data.get('protocol_counts', {}).items()]
        sections.append(boxed_section("Protocolos", proto_lines))

        # Tamaños promedios
        avg_lines = [f"{proto}: {size:.1f} bytes promedio" for proto, size in analysis_data.get('avg_sizes', {}).items()]
        sections.append(boxed_section("Tamaño Promedio por Protocolo", avg_lines))

        # IPs origen
        src_lines = [f"{ip}: {count} paquetes" for ip, count in analysis_data.get('top_src_ips', [])]
        sections.append(boxed_section("Top IPs Origen", src_lines))

        # IPs destino
        dst_lines = [f"{ip}: {count} paquetes" for ip, count in analysis_data.get('top_dst_ips', [])]
        sections.append(boxed_section("Top IPs Destino", dst_lines))

        # TCP FLAGS
        flag_lines = [f"{flag}: {count}" for flag, count in analysis_data.get('tcp_flags', {}).items()]
        sections.append(boxed_section("TCP Flags", flag_lines))

        # Scrollable layout
        list_box = urwid.ListBox(urwid.SimpleFocusListWalker(sections))

        # Footer
        back_btn = SimpleButton("← Return (R)", on_press=lambda _: on_back())
        exit_btn = SimpleButton("Exit (ESC)", on_press=lambda _: on_exit())
        footer = urwid.Columns([
            ('weight', 1, urwid.AttrMap(urwid.LineBox(back_btn), 'button_box')),
            ('weight', 1, urwid.AttrMap(urwid.LineBox(exit_btn), 'button_box')),
        ], dividechars=2)
        footer = urwid.Padding(footer, left=2, right=2)

        return urwid.Frame(body=list_box, header=header, footer=footer)


