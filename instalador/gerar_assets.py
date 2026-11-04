"""Gera ícone e imagens do assistente de instalação (identidade Make Distribuidora)."""
import math
import os
import random

from PIL import Image, ImageDraw, ImageFont

AQUI = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(AQUI, "assets")
os.makedirs(OUT, exist_ok=True)

LIMA, MEDIO, ESCURO, BRANCO = (203, 245, 66), (50, 103, 58), (25, 36, 27), (255, 255, 255)
FONTS = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts")


def font(size, bold=True):
    for name in (("segoeuib.ttf", "arialbd.ttf") if bold else ("segoeui.ttf", "arial.ttf")):
        try:
            return ImageFont.truetype(os.path.join(FONTS, name), size)
        except OSError:
            pass
    return ImageFont.load_default()


def logo(size):
    """Quadrado arredondado verde-lima com um 'hub' de rede estilizado."""
    S = size * 4  # desenha em alta e reduz (antialias)
    im = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle([0, 0, S - 1, S - 1], radius=int(S * 0.24), fill=LIMA)
    c = S / 2
    r_out = S * 0.30
    pts = [(c + r_out * math.cos(a), c + r_out * math.sin(a)) for a in [(-90 + i * 72) * math.pi / 180 for i in range(5)]]
    lw = max(2, int(S * 0.045))
    for x, y in pts:
        d.line([(c, c), (x, y)], fill=ESCURO, width=lw)
    for x, y in pts:
        rr = S * 0.075
        d.ellipse([x - rr, y - rr, x + rr, y + rr], fill=ESCURO)
    rc = S * 0.13
    d.ellipse([c - rc, c - rc, c + rc, c + rc], fill=ESCURO)
    rc2 = S * 0.06
    d.ellipse([c - rc2, c - rc2, c + rc2, c + rc2], fill=LIMA)
    return im.resize((size, size), Image.LANCZOS)


def network_bg(w, h, seed=7, density=26):
    """Fundo verde-escuro com uma malha de nós (lembra o mapa da rede)."""
    im = Image.new("RGB", (w, h), ESCURO)
    d = ImageDraw.Draw(im)
    rnd = random.Random(seed)
    nodes = [(rnd.uniform(0, w), rnd.uniform(0, h)) for _ in range(density)]
    for i, (x, y) in enumerate(nodes):
        for x2, y2 in nodes[i + 1:]:
            if math.hypot(x - x2, y - y2) < w * 0.45:
                d.line([(x, y), (x2, y2)], fill=(40, 62, 44), width=max(1, w // 160))
    for x, y in nodes:
        r = rnd.choice([2, 3, 4]) * w / 164
        d.ellipse([x - r, y - r, x + r, y + r], fill=rnd.choice([MEDIO, (60, 90, 64), LIMA if rnd.random() < .2 else MEDIO]))
    return im


def wizard_large(scale):
    w, h = 164 * scale, 314 * scale
    im = network_bg(w, h, seed=3, density=22)
    d = ImageDraw.Draw(im)
    lg = logo(int(64 * scale))
    im.paste(lg, (int(20 * scale), int(26 * scale)), lg)
    d.text((20 * scale, 106 * scale), "Inventário", font=font(int(21 * scale)), fill=BRANCO)
    d.text((20 * scale, 131 * scale), "de Rede", font=font(int(21 * scale)), fill=BRANCO)
    d.rounded_rectangle([20 * scale, 162 * scale, 52 * scale, 165 * scale], radius=2 * scale, fill=LIMA)
    d.text((20 * scale, 174 * scale), "Identifica e mapeia\ntodos os dispositivos\nda rede.", font=font(int(10.5 * scale), False),
           fill=(200, 214, 198), spacing=int(3 * scale))
    d.text((20 * scale, h - 34 * scale), "MAKE DISTRIBUIDORA", font=font(int(8.5 * scale)), fill=LIMA)
    return im


def wizard_small(size):
    im = Image.new("RGB", (size, size), BRANCO)
    lg = logo(int(size * 0.86))
    o = (size - lg.width) // 2
    im.paste(lg, (o, o), lg)
    return im


if __name__ == "__main__":
    sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
    big = logo(256)
    # formato BMP em todos os tamanhos: o mais compatível com o Explorer do Windows
    big.save(os.path.join(OUT, "icone.ico"), sizes=[(s, s) for s in sizes], bitmap_format="bmp")
    big.save(os.path.join(OUT, "icone.png"))
    wizard_large(1).save(os.path.join(OUT, "wizard-164.bmp"))
    wizard_large(2).save(os.path.join(OUT, "wizard-328.bmp"))
    wizard_small(55).save(os.path.join(OUT, "wizard-small-55.bmp"))
    wizard_small(110).save(os.path.join(OUT, "wizard-small-110.bmp"))
    print("assets em", OUT, sorted(os.listdir(OUT)))
