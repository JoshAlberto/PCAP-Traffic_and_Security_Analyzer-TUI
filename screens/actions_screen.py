import urwid
import pyfiglet
from widgets import SimpleButton

class ActionsScreen:
    @staticmethod
    def get_widget(on_back, on_exit, on_analisis, on_resume, on_security):
        ascii_title = pyfiglet.figlet_format("Actions", font="slant")
        header_text = urwid.Text(('title', ascii_title), align='center')
        header_box = urwid.AttrMap(urwid.LineBox(header_text), 'box')
        header = urwid.Pile([
            urwid.Padding(header_box, left=2, right=2),
            urwid.AttrMap(urwid.Divider(top=1), 'divider')
        ])

        def create_boxed_button(label, callback):
            button = SimpleButton(label, on_press=callback)
            return urwid.AttrMap(urwid.LineBox(button), 'button_box')

        button1 = create_boxed_button("Traffic Analysis", on_analisis)
        button2 = create_boxed_button("Packets Summary", on_resume)
        button3 = create_boxed_button("Security Check", on_security)

        buttons = urwid.Columns([
            ('weight', 1, button1),
            ('weight', 1, button2),
            ('weight', 1, button3)
        ], dividechars=4)

        body = urwid.Filler(buttons, valign='middle')
        body = urwid.AttrMap(body, 'body')

        back_btn = SimpleButton("← Return (R)", on_press=on_back)
        exit_btn = SimpleButton("Exit (ESC)", on_press=on_exit)
        footer = urwid.Columns([
            ('weight', 1, urwid.AttrMap(urwid.LineBox(back_btn), 'button_box')),
            ('weight', 1, urwid.AttrMap(urwid.LineBox(exit_btn), 'button_box')),
        ], dividechars=2)
        footer = urwid.Padding(footer, left=2, right=2)

        return urwid.Frame(body=body, header=header, footer=footer)

