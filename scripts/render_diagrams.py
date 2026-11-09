"""Renderiza docs/diagramas/*.mmd em PNG (Mermaid no Chrome headless via Playwright)."""

from __future__ import annotations

import json
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "diagramas"
HTML = """<!doctype html><html><body style="margin:0;background:#fff">
<div id="d" class="mermaid"></div>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js"></script>
<script>
mermaid.initialize({startOnLoad:false, theme:'neutral', securityLevel:'loose',
  themeVariables:{fontFamily:'Helvetica, Arial, sans-serif', fontSize:'15px'}});
window.render = async (src) => { const {svg} = await mermaid.render('g', src);
  document.getElementById('d').innerHTML = svg; return true; };
</script></body></html>"""


def main() -> None:
    with sync_playwright() as p:
        b = p.chromium.launch(channel="chrome", headless=True)
        page = b.new_page(viewport={"width": 1800, "height": 1200}, device_scale_factor=2)
        page.set_content(HTML)
        page.wait_for_function("window.mermaid !== undefined")
        for f in sorted(SRC.glob("*.mmd")):
            page.evaluate(f"window.render({json.dumps(f.read_text())})")
            el = page.locator("#d svg")
            el.screenshot(path=SRC / f"{f.stem}.png")
            print("ok", f.stem)
        b.close()


if __name__ == "__main__":
    main()
