import os
import urwid
import pyfiglet
from widgets import SimpleButton


class MenuScreen:
    @staticmethod
    def get_widget(on_file_selected, on_exit):
        directory = os.path.join(os.getcwd(), 'logs')
        files = [f for f in os.listdir(directory) if f.endswith('.pcapng')]

        ascii_title = pyfiglet.figlet_format("LogsViewer TUI", font="slant")
        header_text = urwid.Text(('title', ascii_title), align='center')
        header_box = urwid.AttrMap(urwid.LineBox(header_text), 'box')
        header_padded = urwid.Padding(header_box, left=2, right=2)
        header = urwid.Pile([
            header_padded,
            urwid.AttrMap(urwid.Divider(top=1), 'divider')
        ])

        body = [
            urwid.AttrMap(urwid.Text("Select a file .pcapng:"), 'title'),
            urwid.Divider()
        ]

        for f in files:
            full_path = os.path.join(directory, f)
            btn = urwid.Button(f)
            urwid.connect_signal(btn, 'click', lambda button, path=full_path: on_file_selected(path))
            body.append(urwid.AttrMap(btn, 'button normal', focus_map='button focus'))

        if not files:
            body.append(urwid.Text("Files .pcapng werent found in the folder 'logs'."))

        listbox = urwid.ListBox(urwid.SimpleFocusListWalker(body))

        exit_btn = SimpleButton("Exit (ESC)", on_press=on_exit)
        exit_btn_box = urwid.AttrMap(urwid.LineBox(exit_btn), 'button_box')
        footer = urwid.Padding(exit_btn_box, left=2, right=2)

        frame = urwid.Frame(
            urwid.AttrMap(listbox, 'body'),
            header=header,
            footer=footer
        )
        return frame
