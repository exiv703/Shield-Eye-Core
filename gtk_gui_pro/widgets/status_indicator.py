import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

class StatusIndicator(Gtk.Box):
    __gtype_name__ = "StatusIndicator"
    
    def __init__(self, label, status="idle"):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        
        self.dot = Gtk.DrawingArea()
        self.dot.set_size_request(12, 12)
        self.dot.set_draw_func(self._draw_dot)
        self.append(self.dot)
        
        self.label_widget = Gtk.Label(label=label)
        self.label_widget.set_halign(Gtk.Align.START)
        self.append(self.label_widget)
        
        self.status = status
    
    def set_status(self, status):
        self.status = status
        self.dot.queue_draw()
    
    def _draw_dot(self, area, cr, width, height):
        center_x = width / 2
        center_y = height / 2
        radius = 4
        
        # status colors
        colors = {
            "active": (0.063, 0.725, 0.506),   # Green
            "warning": (0.961, 0.620, 0.043),  # Orange
            "error": (0.937, 0.267, 0.267),    # Red
            "idle": (0.420, 0.447, 0.502),     # Gray
        }
        
        color = colors.get(self.status, colors["idle"])
        
        # add glow effect for active states
        if self.status in ["active", "warning", "error"]:
            import cairo
            gradient = cairo.RadialGradient(center_x, center_y, 0, center_x, center_y, radius * 2)
            gradient.add_color_stop_rgba(0, *color, 0.5)
            gradient.add_color_stop_rgba(1, *color, 0.0)
            cr.set_source(gradient)
            cr.arc(center_x, center_y, radius * 2, 0, 6.28)
            cr.fill()
        
        cr.set_source_rgba(*color, 1.0)
        cr.arc(center_x, center_y, radius, 0, 6.28)
        cr.fill()

class RiskBadge(Gtk.Label):
    __gtype_name__ = "RiskBadge"
    
    def __init__(self, level="LOW"):
        super().__init__(label=level.upper())
        self.add_css_class("risk-badge")
        self.set_risk_level(level)
    
    def set_risk_level(self, level):
        # update badge styling based on risk level
        for lv in ["critical", "high", "medium", "low"]:
            self.remove_css_class(lv)
        
        self.add_css_class(level.lower())
        self.set_label(level.upper())
