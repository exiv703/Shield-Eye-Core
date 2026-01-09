import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk
import math

class ChartPanel(Gtk.Box):
    __gtype_name__ = "ChartPanel"
    
    def __init__(self, title, chart_type="area"):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        
        self.add_css_class("chart-panel")
        self.chart_type = chart_type
        
        header = Gtk.Label(label=title)
        header.add_css_class("chart-header")
        header.set_halign(Gtk.Align.START)
        self.append(header)
        
        self.chart_area = Gtk.DrawingArea()
        if chart_type == "area":
            self.chart_area.set_size_request(800, 240)
        else:
            self.chart_area.set_size_request(350, 240)
        self.chart_area.set_hexpand(True)
        self.chart_area.set_vexpand(False)
        self.chart_area.set_draw_func(self._draw_chart)
        self.append(self.chart_area)
        
        self._data = []
        self._labels = []
        self._hover_index = None
        self._mouse_x = 0
        self._mouse_y = 0
        
        # add mouse tracking for area charts
        if chart_type == "area":
            motion_controller = Gtk.EventControllerMotion()
            motion_controller.connect("motion", self._on_mouse_motion)
            motion_controller.connect("leave", self._on_mouse_leave)
            self.chart_area.add_controller(motion_controller)
    
    def set_data(self, data, labels=None):
        self._data = data
        self._labels = labels if labels else [str(i) for i in range(len(data))]
        self.chart_area.queue_draw()
    
    def _on_mouse_motion(self, controller, x, y):
        if not self._data or len(self._data) < 2:
            return
        
        self._mouse_x = x
        self._mouse_y = y
        
        width = self.chart_area.get_width()
        height = self.chart_area.get_height()
        padding = 50
        chart_width = width - 2 * padding
        step_x = chart_width / (len(self._data) - 1)
        
        # find closest data point to cursor
        closest_index = None
        min_distance = float('inf')
        
        for i in range(len(self._data)):
            point_x = padding + i * step_x
            distance = abs(x - point_x)
            
            if distance < min_distance and distance < 20:
                min_distance = distance
                closest_index = i
        
        if closest_index != self._hover_index:
            self._hover_index = closest_index
            self.chart_area.queue_draw()
    
    def _on_mouse_leave(self, controller):
        if self._hover_index is not None:
            self._hover_index = None
            self.chart_area.queue_draw()
    
    def _draw_chart(self, area, cr, width, height):
        
        if not self._data:
            return
        
        if self.chart_type == "area":
            self._draw_area_chart(cr, width, height)
        elif self.chart_type == "donut":
            self._draw_donut_chart(cr, width, height)
        elif self.chart_type == "radial":
            self._draw_radial_gauge(cr, width, height)
        elif self.chart_type == "heatmap":
            self._draw_heatmap(cr, width, height)
    
    def _draw_area_chart(self, cr, width, height):
        
        if len(self._data) < 2:
            cr.set_source_rgba(0.420, 0.447, 0.502, 1.0)
            cr.select_font_face("Sans", 0, 0)
            cr.set_font_size(14)
            text = "No scan data available"
            extents = cr.text_extents(text)
            cr.move_to(width/2 - extents.width/2, height/2)
            cr.show_text(text)
            return
        
        padding = 50
        chart_width = width - 2 * padding
        chart_height = height - 2 * padding - 20
        
        max_val = max(self._data) if max(self._data) > 0 else 1
        step_x = chart_width / (len(self._data) - 1)
        
        cr.set_source_rgba(0.2, 0.25, 0.35, 0.3)
        cr.set_line_width(1)
        cr.select_font_face("Sans", 0, 0)
        cr.set_font_size(10)
        
        for i in range(5):
            y = padding + (i * chart_height / 4)
            cr.move_to(padding, y)
            cr.line_to(width - padding, y)
            cr.stroke()
            
            val = int(max_val * (1 - i / 4))
            cr.set_source_rgba(0.420, 0.447, 0.502, 0.8)
            cr.move_to(10, y + 4)
            cr.show_text(str(val))
            cr.set_source_rgba(0.2, 0.25, 0.35, 0.3)
        
        import cairo
        gradient = cairo.LinearGradient(0, padding, 0, height - padding)
        gradient.add_color_stop_rgba(0, 0.145, 0.388, 0.925, 0.4)
        gradient.add_color_stop_rgba(1, 0.145, 0.388, 0.925, 0.05)
        
        cr.move_to(padding, height - padding)
        for i, val in enumerate(self._data):
            x = padding + i * step_x
            y = height - padding - (val / max_val * chart_height)
            cr.line_to(x, y)
        cr.line_to(width - padding, height - padding)
        cr.close_path()
        cr.set_source(gradient)
        cr.fill()
        
        cr.set_source_rgba(0.145, 0.388, 0.925, 1.0)
        cr.set_line_width(2.5)
        for i, val in enumerate(self._data):
            x = padding + i * step_x
            y = height - padding - (val / max_val * chart_height)
            if i == 0:
                cr.move_to(x, y)
            else:
                cr.line_to(x, y)
        cr.stroke()
        
        cr.set_source_rgba(0.145, 0.388, 0.925, 1.0)
        for i, val in enumerate(self._data):
            x = padding + i * step_x
            y = height - padding - (val / max_val * chart_height)
            cr.arc(x, y, 4, 0, 2 * math.pi)
            cr.fill()
        
        cr.set_source_rgba(0.420, 0.447, 0.502, 0.8)
        cr.select_font_face("Sans", 0, 0)
        cr.set_font_size(10)
        
        label_step = max(1, len(self._labels) // 8)  # Show max 8 labels
        for i, label in enumerate(self._labels):
            if i % label_step == 0 or i == len(self._labels) - 1:
                x = padding + i * step_x
                extents = cr.text_extents(label)
                cr.move_to(x - extents.width / 2, height - padding + 20)
                cr.show_text(label)
        
        if self._hover_index is not None and 0 <= self._hover_index < len(self._data):
            val = self._data[self._hover_index]
            label = self._labels[self._hover_index]
            
            tooltip_width = 120
            tooltip_height = 60
            tooltip_x = self._mouse_x + 15
            tooltip_y = self._mouse_y - tooltip_height - 10
            
            if tooltip_x + tooltip_width > width - padding:
                tooltip_x = self._mouse_x - tooltip_width - 15
            if tooltip_y < padding:
                tooltip_y = self._mouse_y + 15
            
            cr.set_source_rgba(0.102, 0.122, 0.161, 0.95)
            cr.rectangle(tooltip_x, tooltip_y, tooltip_width, tooltip_height)
            cr.fill()
            
            cr.set_source_rgba(0.145, 0.388, 0.925, 0.3)
            cr.set_line_width(1)
            cr.rectangle(tooltip_x, tooltip_y, tooltip_width, tooltip_height)
            cr.stroke()
            
            cr.set_source_rgba(0.878, 0.902, 0.941, 1.0)
            cr.set_font_size(10)
            cr.move_to(tooltip_x + 10, tooltip_y + 20)
            cr.show_text(f"Date: {label}")
            cr.move_to(tooltip_x + 10, tooltip_y + 38)
            cr.show_text(f"Scans: {int(val)}")
            
            total = sum(self._data)
            avg = total / len(self._data)
            cr.move_to(tooltip_x + 10, tooltip_y + 52)
            cr.show_text(f"Avg: {avg:.1f}")
    
    def _draw_donut_chart(self, cr, width, height):
        
        if not self._data:
            cr.set_source_rgba(0.420, 0.447, 0.502, 1.0)
            cr.select_font_face("Sans", 0, 0)
            cr.set_font_size(14)
            text = "No risk data available"
            extents = cr.text_extents(text)
            cr.move_to(width/2 - extents.width/2, height/2)
            cr.show_text(text)
            return
        
        center_x = width / 2 - 40
        center_y = height / 2
        outer_radius = min(width, height) / 2 - 50
        inner_radius = outer_radius * 0.65
        
        total = sum(self._data)
        if total == 0:
            return
        
        colors = [
            (0.937, 0.267, 0.267),  # Critical - red
            (0.961, 0.620, 0.043),  # High - orange
            (0.231, 0.510, 0.965),  # Medium - blue
            (0.063, 0.725, 0.506),  # Low - green
        ]
        
        start_angle = -math.pi / 2
        
        for i, val in enumerate(self._data):
            if val == 0:
                continue
            
            angle = (val / total) * 2 * math.pi
            end_angle = start_angle + angle
            
            color = colors[i % len(colors)]
            cr.set_source_rgba(*color, 0.9)
            cr.arc(center_x, center_y, outer_radius, start_angle, end_angle)
            cr.arc_negative(center_x, center_y, inner_radius, end_angle, start_angle)
            cr.close_path()
            cr.fill()
            
            start_angle = end_angle
        
        cr.set_source_rgba(0.039, 0.055, 0.102, 1.0)
        cr.arc(center_x, center_y, inner_radius, 0, 2 * math.pi)
        cr.fill()
        
        cr.set_source_rgba(0.145, 0.388, 0.925, 0.1)
        cr.arc(center_x, center_y, inner_radius - 5, 0, 2 * math.pi)
        cr.fill()
        
        cr.set_source_rgba(0.878, 0.902, 0.941, 1.0)
        cr.select_font_face("Sans", 0, 1)
        cr.set_font_size(28)
        text = str(int(total))
        extents = cr.text_extents(text)
        cr.move_to(center_x - extents.width / 2, center_y + extents.height / 2 - 5)
        cr.show_text(text)
        
        cr.set_font_size(11)
        cr.set_source_rgba(0.420, 0.447, 0.502, 1.0)
        text2 = "Scans"
        extents2 = cr.text_extents(text2)
        cr.move_to(center_x - extents2.width / 2, center_y + 20)
        cr.show_text(text2)
        
        legend_x = center_x + outer_radius + 30
        legend_y = center_y - 60
        
        colors = [
            (0.937, 0.267, 0.267),  # Critical
            (0.961, 0.620, 0.043),  # High
            (0.231, 0.510, 0.965),  # Medium
            (0.063, 0.725, 0.506),  # Low
        ]
        
        cr.select_font_face("Sans", 0, 0)
        cr.set_font_size(11)
        
        for i, (val, label) in enumerate(zip(self._data, self._labels)):
            y = legend_y + i * 30
            
            cr.set_source_rgba(*colors[i], 0.9)
            cr.rectangle(legend_x, y - 8, 12, 12)
            cr.fill()
            
            cr.set_source_rgba(0.878, 0.902, 0.941, 1.0)
            cr.move_to(legend_x + 20, y + 3)
            percentage = (val / total * 100) if total > 0 else 0
            cr.show_text(f"{label}: {int(val)} ({percentage:.0f}%)")
    
    def _draw_radial_gauge(self, cr, width, height):
        
        if not self._data or len(self._data) == 0:
            return
        
        value = self._data[0] if isinstance(self._data[0], (int, float)) else 0
        max_value = 100
        
        center_x = width / 2
        center_y = height / 2
        radius = min(width, height) / 2 - 40
        
        cr.set_source_rgba(0.117, 0.161, 0.212, 1.0)
        cr.set_line_width(20)
        cr.arc(center_x, center_y, radius, -math.pi * 0.75, math.pi * 0.75)
        cr.stroke()
        
        if value <= 30:
            color = (0.063, 0.725, 0.506)  # Green
        elif value <= 60:
            color = (0.231, 0.510, 0.965)  # Blue
        elif value <= 80:
            color = (0.961, 0.620, 0.043)  # Orange
        else:
            color = (0.937, 0.267, 0.267)  # Red
        
        cr.set_source_rgba(*color, 1.0)
        cr.set_line_width(20)
        angle = -math.pi * 0.75 + (value / max_value) * (math.pi * 1.5)
        cr.arc(center_x, center_y, radius, -math.pi * 0.75, angle)
        cr.stroke()
        
        cr.set_source_rgba(0.878, 0.902, 0.941, 1.0)
        cr.select_font_face("Sans", 0, 1)
        cr.set_font_size(42)
        text = f"{int(value)}"
        extents = cr.text_extents(text)
        cr.move_to(center_x - extents.width / 2, center_y + extents.height / 2 - 15)
        cr.show_text(text)
        
        cr.set_font_size(20)
        cr.move_to(center_x - 15, center_y + 20)
        cr.show_text("/ 100")
        
        cr.select_font_face("Sans", 0, 0)
        cr.set_font_size(12)
        if value >= 80:
            status = "Excellent"
            cr.set_source_rgba(0.063, 0.725, 0.506, 1.0)
        elif value >= 60:
            status = "Good"
            cr.set_source_rgba(0.231, 0.510, 0.965, 1.0)
        elif value >= 40:
            status = "Fair"
            cr.set_source_rgba(0.961, 0.620, 0.043, 1.0)
        else:
            status = "Poor"
            cr.set_source_rgba(0.937, 0.267, 0.267, 1.0)
        
        extents = cr.text_extents(status)
        cr.move_to(center_x - extents.width / 2, center_y + 45)
        cr.show_text(status)
    
    def _draw_heatmap(self, cr, width, height):
        
        if not self._data:
            return
        
        if not isinstance(self._data[0], list):
            return
        
        rows = len(self._data)
        cols = len(self._data[0])
        
        padding = 30
        cell_width = (width - 2 * padding) / cols
        cell_height = (height - 2 * padding) / rows
        
        max_val = max(max(row) for row in self._data)
        if max_val == 0:
            max_val = 1
        
        for i, row in enumerate(self._data):
            for j, val in enumerate(row):
                x = padding + j * cell_width
                y = padding + i * cell_height
                
                intensity = val / max_val
                if intensity < 0.25:
                    cr.set_source_rgba(0.063, 0.725, 0.506, intensity)  # Green
                elif intensity < 0.5:
                    cr.set_source_rgba(0.231, 0.510, 0.965, intensity)  # Blue
                elif intensity < 0.75:
                    cr.set_source_rgba(0.961, 0.620, 0.043, intensity)  # Orange
                else:
                    cr.set_source_rgba(0.937, 0.267, 0.267, intensity)  # Red
                
                cr.rectangle(x, y, cell_width - 2, cell_height - 2)
                cr.fill()
