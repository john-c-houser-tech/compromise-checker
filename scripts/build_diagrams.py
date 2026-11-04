"""Draw the README's diagrams as SVG files, in light and dark, with Graphviz.

    python scripts/build_diagrams.py            # docs/diagrams/*.dot -> *-light.svg, *-dark.svg
    python scripts/build_diagrams.py --preview  # also PNGs, through rsvg-convert, to look at

Each .dot file is a Graphviz source with {text}, {fill} and the other colour names below as
placeholders, which the script fills in once per theme. The README shows the results with
<picture> tags, so GitHub picks the dark one under a dark theme. They are SVG files rather
than Mermaid blocks because GitHub lays a zoom panel over a Mermaid block's top-right corner,
on top of the diagram.
"""

import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent.parent / "docs" / "diagrams"

THEMES = {
    "light": {
        "text": "#1f2328",
        "edge": "#57606a",
        "fill": "#ddf4ff",
        "stroke": "#54aeff",
        "cfill": "#f6f8fa",
        "cstroke": "#d0d7de",
        "dfill": "#fff8c5",
        "dstroke": "#d4a72c",
    },
    "dark": {
        "text": "#e6edf3",
        "edge": "#8b949e",
        "fill": "#0c2d6b",
        "stroke": "#388bfd",
        "cfill": "#161b22",
        "cstroke": "#30363d",
        "dfill": "#3b2300",
        "dstroke": "#d29922",
    },
}

# Lines Graphviz adds that a plain SVG file doesn't need.
DROP = ("<?xml", "<!DOCTYPE", ' "http', "<!--", " -->")


def main() -> int:
    dot = shutil.which("dot")
    if dot is None:
        print("Graphviz's dot isn't installed", file=sys.stderr)
        return 1
    preview = "--preview" in sys.argv[1:]
    rsvg = shutil.which("rsvg-convert") if preview else None
    if preview and rsvg is None:
        print("rsvg-convert isn't installed, so no previews", file=sys.stderr)
        return 1
    for source in sorted(HERE.glob("*.dot")):
        template = source.read_text()
        for theme, colours in THEMES.items():
            out = HERE / f"{source.stem}-{theme}.svg"
            graph = template
            for key, colour in colours.items():
                graph = graph.replace("{" + key + "}", colour)
            svg = subprocess.run(  # noqa: S603 - our own dot, fixed arguments, the graph on stdin
                [dot, "-Tsvg"], input=graph, capture_output=True, text=True, check=True
            ).stdout
            lines = [line for line in svg.splitlines() if not line.startswith(DROP)]
            out.write_text("\n".join(lines) + "\n")
            print(out.relative_to(HERE.parent.parent), len(svg), "bytes")
            if rsvg is not None:
                background = "white" if theme == "light" else "#0d1117"
                png = out.with_suffix(".png")
                subprocess.run(  # noqa: S603 - our own rsvg-convert, fixed arguments
                    [rsvg, "-w", "1400", "-b", background, str(out), "-o", str(png)], check=True
                )
    return 0


if __name__ == "__main__":
    sys.exit(main())
