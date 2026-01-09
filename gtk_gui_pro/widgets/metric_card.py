import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GObject

class MetricCard(Gtk.Box):
    __gtype_name__ = "MetricCard"
    
    def __init__(self, label, value="0", change="", severity="low"):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        
        self.add_css_class("metric-card")
        self.set_size_request(220, 160)
        self.set_hexpand(True)
        self.set_vexpand(False)
        
        self.label_widget = Gtk.Label(label=label.upper())
        self.label_widget.add_css_class("metric-label")
        self.label_widget.set_halign(Gtk.Align.START)
        self.append(self.label_widget)
        
        value_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        value_box.set_margin_top(8)
        
        self.value_widget = Gtk.Label(label=value)
        self.value_widget.add_css_class("metric-value")
        self.value_widget.add_css_class(severity)
        self.value_widget.set_halign(Gtk.Align.START)
        value_box.append(self.value_widget)
        
        self.append(value_box)
        
        self.change_widget = Gtk.Label(label=change)
        self.change_widget.add_css_class("metric-change")
        self.change_widget.set_halign(Gtk.Align.START)
        self.change_widget.set_margin_top(6)
        self.append(self.change_widget)
        
        # mini sparkline chart
        self.sparkline = Gtk.DrawingArea()
        self.sparkline.set_size_request(-1, 40)
        self.sparkline.set_margin_top(12)
        self.sparkline.set_draw_func(self._draw_sparkline)
        self.append(self.sparkline)
        
        self._sparkline_data = []
    
    def update_value(self, value, severity=None):
        self.value_widget.set_label(value)
        if severity:
            # update severity styling
            for sev in ["critical", "high", "medium", "low"]:
                self.value_widget.remove_css_class(sev)
            self.value_widget.add_css_class(severity)
    
    def update_subtitle(self, text):
        if self.change_widget:
            self.change_widget.set_label(text)
    
    def update_sparkline(self, data):
        # keep last 20 data points
        self._sparkline_data = data[-20:] if len(data) > 20 else data
        self.sparkline.queue_draw()
    
    def _draw_sparkline(self, area, cr, width, height):
        # draw simple line chart
        if not self._sparkline_data or len(self._sparkline_data) < 2:
            return
        
        max_val = max(self._sparkline_data) if max(self._sparkline_data) > 0 else 1
        min_val = min(self._sparkline_data)
        
        cr.set_source_rgba(0.145, 0.388, 0.925, 0.6)  # Blue with transparency
        cr.set_line_width(2)
        
        step_x = width / (len(self._sparkline_data) - 1)
        for i, val in enumerate(self._sparkline_data):
            normalized = (val - min_val) / (max_val - min_val) if max_val > min_val else 0.5
            y = height - (normalized * height * 0.8) - (height * 0.1)
            x = i * step_x
            
            if i == 0:
                cr.move_to(x, y)
            else:
                cr.line_to(x, y)
        
        cr.stroke()
