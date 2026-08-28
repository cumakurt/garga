#!/usr/bin/env python3
"""Render a captured terminal transcript into a dark-theme PNG screenshot."""

from __future__ import annotations

import argparse
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

BG = (13, 17, 23)
CHROME = (22, 27, 34)
BORDER = (48, 54, 61)
TITLE = (201, 209, 217)
PROMPT = (88, 166, 255)
BODY = (230, 237, 243)
MUTED = (139, 148, 158)
GREEN = (63, 185, 80)
RED = (248, 81, 73)
YELLOW = (210, 153, 34)

MAX_COLS = 108
MAX_ROWS = 56


def load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
        "/usr/share/fonts/truetype/lato/Lato-Medium.ttf",
    ]
    for path in candidates:
        if Path(path).is_file():
            return ImageFont.truetype(path, size=size)
    return ImageFont.load_default()


def color_for(line: str) -> tuple[int, int, int]:
    stripped = line.strip()
    lower = stripped.lower()
    if stripped.startswith("$ "):
        return PROMPT
    if (
        lower.startswith("ok")
        or " valid " in lower
        or "outcome=valid " in lower
        or "reason=success" in lower
        or lower.startswith("auth-check: valid")
    ):
        return GREEN
    if "critical" in lower or "invalid" in lower or lower.startswith("garga:"):
        if "pdf" in lower or "written" in lower:
            return GREEN
        if "invalid" in lower or "fail" in lower:
            return RED
    if "critical" in lower:
        return RED
    if "high" in lower or "warning" in lower:
        return YELLOW
    if stripped.startswith("#") or stripped.startswith("["):
        return MUTED
    return BODY


def wrap_lines(text: str, max_rows: int = MAX_ROWS) -> list[str]:
    rows: list[str] = []
    for raw in text.replace("\r", "").split("\n"):
        if raw == "":
            rows.append("")
            continue
        wrapped = textwrap.wrap(
            raw,
            width=MAX_COLS,
            replace_whitespace=False,
            drop_whitespace=False,
            break_long_words=True,
            break_on_hyphens=False,
        )
        rows.extend(wrapped or [""])
    if len(rows) > max_rows:
        head = rows[: max_rows - 1]
        head.append("… output truncated for screenshot …")
        return head
    if rows and rows[-1] == "":
        rows = rows[:-1]
    return rows or [""]


def render(title: str, command: str, body: str, destination: Path, max_rows: int = MAX_ROWS) -> None:
    font = load_font(15)
    title_font = load_font(14)
    transcript = "$ " + command
    if body.strip():
        transcript += "\n" + body.rstrip()
    else:
        transcript += "\n(no output)"
    lines = wrap_lines(transcript, max_rows=max_rows)

    pad_x = 22
    pad_y = 18
    line_h = 22
    chrome_h = 36
    width = pad_x * 2 + MAX_COLS * 9
    height = chrome_h + pad_y * 2 + line_h * len(lines)
    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, width, chrome_h), fill=CHROME)
    draw.ellipse((14, 12, 26, 24), fill=RED)
    draw.ellipse((34, 12, 46, 24), fill=YELLOW)
    draw.ellipse((54, 12, 66, 24), fill=GREEN)
    draw.text((88, 10), title, font=title_font, fill=TITLE)
    draw.rectangle((0, 0, width - 1, height - 1), outline=BORDER)

    y = chrome_h + pad_y
    for line in lines:
        draw.text((pad_x, y), line[:MAX_COLS], font=font, fill=color_for(line))
        y += line_h
    destination.parent.mkdir(parents=True, exist_ok=True)
    image.save(destination, "PNG", optimize=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--title", required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-rows", type=int, default=MAX_ROWS)
    args = parser.parse_args()
    body = Path(args.input).read_text(encoding="utf-8", errors="replace")
    render(args.title, args.command, body, Path(args.output), max_rows=args.max_rows)


if __name__ == "__main__":
    main()
