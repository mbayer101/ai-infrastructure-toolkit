import FreeCAD as App
import Part, math

R = 5.0       # Hexagon outer radius
wall = 1.0    # Wall thickness
rows = 5      # Number of rows
cols = 5      # Number of columns
height = 10.0 # Core height

doc = App.activeDocument() if App.activeDocument() else App.newDocument("HexCore")
hex_shapes = []
x_spacing = (R + wall) * math.sqrt(3)
y_spacing = (R + wall) * 1.5

for r in range(rows):
    for c in range(cols):
        x_offset = c * x_spacing + (x_spacing / 2.0 if r % 2 == 1 else 0.0)
        y_offset = r * y_spacing
        poly = Part.makePolygon(6, App.Vector(x_offset, y_offset, 0), App.Vector(0,0,1), R)
        face = Part.Face(poly)
        extrude = face.extrude(App.Vector(0, 0, height))
        hex_shapes.append(extrude)

compound = Part.makeCompound(hex_shapes)
Part.show(compound)
doc.recompute()

