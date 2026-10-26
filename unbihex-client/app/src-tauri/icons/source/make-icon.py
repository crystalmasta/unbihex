"""Unbihex icons from logo.svg (the brand logo with the "unbihex" wordmark).

    python make-icon.py

writes, next to this script:
  icon.svg, icon-1024.png        the mark on a rounded dark square: master for `cargo tauri icon`
                                 (icon.svg is also copied to app/ui for the logo in the window)
  android-fg.svg, android-fg-N   the mark alone in the Android adaptive-icon safe zone, N = 108..432

App icons carry the mark only: at 16-32 px (tray, taskbar) the wordmark cannot be read.
PNGs are rendered by Microsoft Edge in headless mode, which ships with Windows.
"""

import pathlib
import re
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
EDGE = pathlib.Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
BACKGROUND = "#0B1736"
# Android foreground sizes per density (108 dp): mdpi, hdpi, xhdpi, xxhdpi, xxxhdpi.
ANDROID_SIZES = [108, 162, 216, 324, 432]


def build_svgs() -> None:
    logo = (HERE / "logo.svg").read_text(encoding="utf-8")
    defs, rest = logo.split("<defs>", 1)[1].split("</defs>", 1)
    rest = rest.rsplit("</svg>", 1)[0]
    # Drop the full-canvas background and the wordmark.
    rest, bg = re.subn(r'\s*<!--[^>]*-->\s*<rect width="1000" height="1000"[^>]*/>', "", rest, count=1)
    rest, word = re.subn(r'\s*<!-- Векторный текст "unbihex" -->\s*<g fill="none" stroke="#FFFFFF".*?</g>',
                         "", rest, count=1, flags=re.S)
    if bg != 1 or word != 1:
        raise SystemExit("logo.svg changed: background or wordmark not found")

    def svg(view: str, extra: str) -> str:
        return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view}" width="1024" height="1024">\n'
                f"  <defs>{defs}</defs>\n{extra}{rest}</svg>\n")

    # The mark spans x 270..734, y 228..634: centre (502, 431), 464 px wide.
    icon = svg("202 131 600 600",
               f'  <rect x="202" y="131" width="600" height="600" rx="132" fill="{BACKGROUND}" />\n')
    (HERE / "icon.svg").write_text(icon, encoding="utf-8")
    (HERE.parents[2] / "ui" / "icon.svg").write_text(icon, encoding="utf-8")
    # Android shows the central 66 of 108 dp, so the mark takes 61% of the canvas.
    (HERE / "android-fg.svg").write_text(svg("122 51 760 760", ""), encoding="utf-8")


def render(svg_name: str, out: pathlib.Path, size: int) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        page = pathlib.Path(tmp) / "page.html"
        page.write_text(
            f'<html><body style="margin:0;background:transparent">'
            f'<img src="{(HERE / svg_name).as_uri()}" width="{size}" height="{size}" style="display:block">'
            f"</body></html>", encoding="utf-8")
        subprocess.run(
            [str(EDGE), "--headless=new", "--disable-gpu", "--hide-scrollbars",
             "--force-device-scale-factor=1", f"--window-size={size},{size}",
             "--default-background-color=00000000", f"--user-data-dir={tmp}",
             f"--screenshot={out}", page.as_uri()],
            check=True, capture_output=True, timeout=120)


def main() -> None:
    build_svgs()
    render("icon.svg", HERE / "icon-1024.png", 1024)
    for n in ANDROID_SIZES:
        render("android-fg.svg", HERE / f"android-fg-{n}.png", n)
    print("ok")


if __name__ == "__main__":
    main()
