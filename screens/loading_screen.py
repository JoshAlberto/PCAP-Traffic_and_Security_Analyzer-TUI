import urwid

class LoadingScreen:
    @staticmethod
    def get_widget(filename):
        # Header con LineBox y estilo 'box'
        header_text = urwid.Text(f"Loading File: {filename}", align='center')
        header = urwid.AttrMap(urwid.LineBox(header_text), 'box')

        # Spinner en el cuerpo, dentro de un Pile para añadir mensaje de carga
        spinner_text = urwid.Text('|', align='center')
        spinner = urwid.AttrMap(spinner_text, 'title')
        loading_message = urwid.Text(f"Loading '{filename}'...", align='center')
        pile = urwid.Pile([
            urwid.Divider(),
            urwid.Filler(loading_message, valign='middle', height='pack'),
            urwid.Divider(),
            urwid.Filler(spinner, valign='middle', height='pack'),
            urwid.Divider()
        ])
        body = urwid.Filler(pile, valign='middle')

        # Footer con instrucciones
        footer_text = urwid.Text("Press ESC to cancel", align='center')
        footer = urwid.Padding(footer_text, left=2, right=2)

        frame = urwid.Frame(body=body, header=header, footer=footer)
        frame.spinner = spinner_text  

        return frame
