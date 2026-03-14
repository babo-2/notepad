from PIL import Image, ImageDraw

values = {
    "red": (255, 0, 0),
    "green": (0, 255, 0),
    "blue": (0, 0, 255),
    "yellow": (255, 255, 0),
    "cyan": (0, 255, 255),
    "magenta": (255, 0, 255),
    "black": (0, 0, 0),
    "white": (255, 255, 255),
    "gray": (128, 128, 128),
    "orange": (255, 165, 0),
    "purple": (128, 0, 128),
    "pink": (255, 192, 203),
    "brown": (165, 42, 42),
    "lime": (0, 255, 0),
    "navy": (0, 0, 128),
    "gold": (255, 215, 0),
    "olive": (128, 128, 0),
    "maroon": (128, 0, 0),
    "teal": (0, 128, 128),
    "silver": (192, 192, 192)
}
for rgb in values:
    img = Image.new('RGB', (16, 16), values[rgb])
    
    img.save("images/"+rgb+".png")
