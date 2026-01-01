import urwid
import pyfiglet
from widgets import SimpleButton


class PacketsScreen:
    @staticmethod
    def get_widget(packets, filename, on_back, on_exit):
        ascii_title = pyfiglet.figlet_format(f"Opened file: {filename}", font="digital")
        header_text = urwid.Text(('title', ascii_title), align='center')
        header_box = urwid.AttrMap(urwid.LineBox(header_text), 'box')
        header_padded = urwid.Padding(header_box, left=2, right=2)
        header = urwid.Pile([
            header_padded,
            urwid.AttrMap(urwid.Divider(top=1), 'divider')
        ])

        items = []
        for pkt in packets:
            proto_style = {
                'TCP': 'row tcp',
                'UDP': 'row udp',
                'ICMP': 'row icmp',
                'ARP': 'row arp',
                'DNS': 'row dns',
                'VRRP': 'row vrrp',
            }.get(pkt['proto'].upper(), 'row default')

            tcp_flags = pkt.get('tcp_flags', '')
            flags_text = f" | Flags TCP: {tcp_flags}" if tcp_flags and tcp_flags != "N/A" else ""

            text_line = (f"#{pkt['number']} | {pkt['time']} | {pkt['length']} bytes | "
                         f"{pkt['proto']} | Desde: {pkt['ip_src']} → Hacia: {pkt['ip_dst']}{flags_text}")
            
            row = urwid.AttrMap(urwid.Text(text_line), proto_style)
            divider = urwid.AttrMap(urwid.Divider('-'), 'divider')

            pile = urwid.Pile([row, divider])
            items.append(pile)

        listbox = urwid.ListBox(urwid.SimpleFocusListWalker(items))

        back_btn = SimpleButton("← Return (R)", on_press=on_back)
        back_btn_box = urwid.AttrMap(urwid.LineBox(back_btn), 'button_box')

        exit_btn = SimpleButton("Exit (ESC)", on_press=on_exit)
        exit_btn_box = urwid.AttrMap(urwid.LineBox(exit_btn), 'button_box')

        buttons = urwid.Columns([
            ('weight', 1, back_btn_box),
            ('weight', 1, exit_btn_box)
        ], dividechars=2)
        footer = urwid.Padding(buttons, left=2, right=2)

        frame = urwid.Frame(
            urwid.AttrMap(listbox, 'body'),
            header=header,
            footer=footer
        )
        return frame
