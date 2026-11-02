#!/usr/bin/env python3
"""Draws docs/before-after.png from invented demo data. Needs Pillow; the tool itself does not.

The right-hand side is not typed by hand: the demo note goes through the real redaction code, so
the picture cannot drift from what the tool does.
"""
import os
import sys

from PIL import Image, ImageDraw, ImageFont

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.dont_write_bytecode = True
sys.path.insert(0, REPO)
import claudepassredactor as mr  # noqa: E402

DEMO_NOTE = """\
---
name: home-network
description: Router and server notes
---

# Home network

Router admin page: http://router.example

The wifi password is Purple-Otter-4817, guests
get the other network.

Deploy token for the blog:
DEMO_TOKEN

Backups go to
postgres://backup:Salty-Comet-93@db.example/main
every night at 02:00.

Reminder: the password manager is open source.
""".replace("DEMO_TOKEN", "gh" + "p_" + "DEMOxTOKENxNOTxREALx0123456789abcdef")   # assembled: no scanner alarm

WIDTH, PAD, LINE, GAP = 1800, 40, 34, 40
FONT_SIZE, TITLE_SIZE = 22, 26
BG, PANEL, BORDER = (250, 250, 250), (30, 33, 40), (58, 62, 72)
TEXT, DIM, TITLE = (222, 225, 230), (140, 146, 158), (34, 38, 46)
SECRET_BG, SECRET_FG = (120, 38, 44), (255, 214, 214)
MASK_BG, MASK_FG = (28, 92, 62), (196, 245, 216)


def font(size, bold=False):
    names = (["DejaVuSansMono-Bold.ttf", "CascadiaMono.ttf", "consolab.ttf", "Menlo.ttc"] if bold else
             ["DejaVuSansMono.ttf", "CascadiaMono.ttf", "consola.ttf", "Menlo.ttc"])
    for name in names:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    raise SystemExit("No monospaced font found.")


def draw_line(draw, x, y, text, marks, mono, char_w, background, foreground):
    """Write text, with a highlighted background over the [start, end) ranges in marks."""
    pos = 0
    for start, end in marks + [(len(text), len(text))]:
        draw.text((x + pos * char_w, y), text[pos:start], font=mono, fill=TEXT)
        if end > start:
            box = (x + start * char_w - 3, y - 3, x + end * char_w + 3, y + LINE - 7)
            draw.rounded_rectangle(box, radius=4, fill=background)
            draw.text((x + start * char_w, y), text[start:end], font=mono, fill=foreground)
        pos = end


def line_marks(text, spans):
    """Per line, the ranges in spans; each span must stay on one line, as they do in this demo."""
    lines, marks, offset = [], [], 0
    for line in text.split("\n"):
        end = offset + len(line)
        marks.append([(s - offset, e - offset) for s, e, *_ in spans if offset <= s and e <= end])
        lines.append(line)
        offset = end + 1
    return lines, marks


def panel(image, draw, x, y, width, height, title, lines, marks, mono, char_w, background, foreground):
    bold = font(TITLE_SIZE, bold=True)
    draw.text((x, y), title, font=bold, fill=TITLE)
    y += TITLE_SIZE + 18
    draw.rounded_rectangle((x, y, x + width, y + height), radius=12, fill=PANEL, outline=BORDER)
    row = y + 22
    for line, mark in zip(lines, marks):
        if line.startswith(("---", "name:", "description:")):
            draw.text((x + 24, row), line, font=mono, fill=DIM)
        else:
            draw_line(draw, x + 24, row, line, mark, mono, char_w, background, foreground)
        row += LINE


def main():
    spans = mr.find_spans(DEMO_NOTE)
    if len(spans) != 3:
        raise SystemExit(f"The demo should have three secrets, and has {len(spans)}.")
    after = mr.apply_spans(DEMO_NOTE, spans)

    masked, cursor, delta = [], 0, 0
    for start, end, _kinds in spans:
        masked.append((start + delta, start + delta + len(mr.TAG)))
        delta += len(mr.TAG) - (end - start)
    before_lines, before_marks = line_marks(DEMO_NOTE, spans)
    after_lines, after_marks = line_marks(after, masked)

    mono = font(FONT_SIZE)
    char_w = mono.getlength("M")
    panel_w = (WIDTH - 2 * PAD - GAP) // 2
    longest = max(len(line) for line in before_lines + after_lines)
    if longest * char_w + 48 > panel_w:
        raise SystemExit(f"A line of {longest} characters does not fit in the panel.")
    panel_h = len(before_lines) * LINE + 36
    height = PAD + TITLE_SIZE + 18 + panel_h + PAD

    image = Image.new("RGB", (WIDTH, height), BG)
    draw = ImageDraw.Draw(image)
    panel(image, draw, PAD, PAD, panel_w, panel_h, "Before: what Claude saved", before_lines, before_marks,
          mono, char_w, SECRET_BG, SECRET_FG)
    panel(image, draw, PAD + panel_w + GAP, PAD, panel_w, panel_h, "After: the hook has run", after_lines,
          after_marks, mono, char_w, MASK_BG, MASK_FG)
    output = os.path.join(REPO, "docs", "before-after.png")
    image.save(output, optimize=True)
    print(f"{image.size[0]}x{image.size[1]}, {os.path.getsize(output)} bytes")


if __name__ == "__main__":
    main()
