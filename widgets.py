import urwid

class SimpleButton(urwid.WidgetWrap):
    def __init__(self, label, on_press=None):
        self.label = label
        self.on_press = on_press
        text_widget = urwid.Text(label, align='center')
        padded = urwid.Padding(text_widget, left=0, right=0)
        fill = urwid.Filler(padded, valign='middle', height='pack')
        attr = urwid.AttrMap(fill, 'button normal', 'button focus')
        super().__init__(attr)

    def selectable(self):
        return True

    def keypress(self, size, key):
        if key == 'enter' and self.on_press:
            self.on_press(self)
            return None
        return key

    def mouse_event(self, size, event, button, x, y, focus):
        if event == 'mouse press' and button == 1:
            if self.on_press:
                self.on_press(self)
            return True
        return False

class SimpleButtonBlue(urwid.WidgetWrap):
    def __init__(self, label, on_press=None):
        self.label = label
        self.on_press = on_press
        text_widget = urwid.Text(label, align='center')
        padded = urwid.Padding(text_widget, left=0, right=0)
        fill = urwid.Filler(padded, valign='middle', height='pack')
        attr = urwid.AttrMap(fill, 'button blue', 'button_focus_blue')
        super().__init__(attr)

    def selectable(self):
        return True

    def keypress(self, size, key):
        if key == 'enter' and self.on_press:
            self.on_press(self)
            return None
        return key

    def mouse_event(self, size, event, button, x, y, focus):
        if event == 'mouse press' and button == 1:
            if self.on_press:
                self.on_press(self)
            return True
        return False

class Collapsible(urwid.WidgetWrap):
    def __init__(self, title, content_widget, expanded=False):
        self.title = title
        self.content_widget = content_widget
        self.expanded = expanded

        self.button = urwid.Button(self._get_title_text())
        urwid.connect_signal(self.button, 'click', self.toggle)

        self._build_widget()
        super().__init__(self.widget)

    def _get_title_text(self):
        prefix = "▼ " if self.expanded else "▶ "
        return prefix + self.title

    def _build_widget(self):
        if self.expanded:
            pile = urwid.Pile([
                urwid.AttrMap(self.button, 'collapsible_title'),
                urwid.Divider(),
                self.content_widget
            ])
        else:
            pile = urwid.Pile([
                urwid.AttrMap(self.button, 'collapsible_title')
            ])
        self.widget = urwid.LineBox(pile)

    def toggle(self, button):
        self.expanded = not self.expanded
        self.button.set_label(self._get_title_text())
        self._build_widget()
        self._w = self.widget
