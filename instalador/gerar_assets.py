"""Gera o ícone e as imagens do assistente de instalação do Scanner de Rede."""
import math
import os

from PIL import Image, ImageDraw, ImageFont

AQUI = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(AQUI, "assets")
os.makedirs(OUT, exist_ok=True)

AZUL, AZUL_ESCURO, AZUL_FUNDO = (37, 99, 235), (30, 58, 138), (23, 37, 84)
BRANCO, CINZA_CLARO = (255, 255, 255), (191, 207, 238)
FONTS = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts")


def font(size, bold=True):
    for name in (("segoeuisb.ttf", "segoeuib.ttf", "arialbd.ttf") if bold else ("segoeui.ttf", "arial.ttf")):
        try:
            return ImageFont.truetype(os.path.join(FONTS, name), size)
        except OSError:
            pass
    return ImageFont.load_default()


def radar(d, cx, cy, r, cor, lw, alfa_aneis=(120, 255)):
    """Dois anéis, o ponteiro e um alvo: a mesma marca do app.html."""
    for k, a in zip((1.0, 0.5), alfa_aneis):
        rr = r * k
        d.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], outline=cor + (a,), width=lw)
    ang = math.radians(-45)
    d.line([(cx, cy), (cx + r * math.cos(ang), cy + r * math.sin(ang))], fill=cor + (255,), width=lw)
    rc = lw * 1.1
    d.ellipse([cx - rc, cy - rc, cx + rc, cy + rc], fill=cor + (255,))
    a2 = math.radians(40)
    bx, by, rb = cx + r * 0.76 * math.cos(a2), cy + r * 0.76 * math.sin(a2), lw * 1.15
    d.ellipse([bx - rb, by - rb, bx + rb, by + rb], fill=cor + (255,))


def logo(size):
    """Quadrado arredondado azul com a marca de radar em branco."""
    S = size * 4  # desenha grande e reduz (antialias)
    im = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle([0, 0, S - 1, S - 1], radius=int(S * 0.24), fill=AZUL + (255,))
    radar(d, S / 2, S / 2, S * 0.30, BRANCO, max(2, int(S * 0.05)))
    return im.resize((size, size), Image.LANCZOS)


def fundo(w, h):
    """Degradê azul com anéis de radar bem discretos no canto."""
    im = Image.new("RGB", (w, h), AZUL_FUNDO)
    px = im.load()
    for y in range(h):
        t = y / max(1, h - 1)
        c = tuple(int(AZUL_ESCURO[i] * (1 - t) + AZUL_FUNDO[i] * t) for i in range(3))
        for x in range(w):
            px[x, y] = c
    ov = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(ov)
    cx, cy = w * 1.0, h * 0.86
    for k in range(1, 7):
        r = w * 0.22 * k
        d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=(255, 255, 255, 22), width=max(1, w // 150))
    return Image.alpha_composite(im.convert("RGBA"), ov).convert("RGB")


def wizard_large(scale):
    w, h = 164 * scale, 314 * scale
    im = fundo(w, h)
    d = ImageDraw.Draw(im)
    lg = logo(int(56 * scale))
    im.paste(lg, (int(20 * scale), int(28 * scale)), lg)
    d.text((20 * scale, 102 * scale), "Scanner", font=font(int(22 * scale)), fill=BRANCO)
    d.text((20 * scale, 128 * scale), "de Rede", font=font(int(22 * scale)), fill=BRANCO)
    d.text((20 * scale, 166 * scale), "Inventário, mapa e\ndiagnóstico da rede\nlocal.", font=font(int(10.5 * scale), False),
           fill=CINZA_CLARO, spacing=int(4 * scale))
    return im


def wizard_small(size):
    im = Image.new("RGB", (size, size), BRANCO)
    lg = logo(int(size * 0.84))
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
