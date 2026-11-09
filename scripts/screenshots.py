"""Gera as capturas de tela usadas no relatório (docs/img/*.png).

Usa o Google Chrome instalado (Playwright, canal "chrome"). Requer a stack no ar
e o provisionamento feito. Uso: ``python -m scripts.screenshots``
"""

from __future__ import annotations

from pathlib import Path

from playwright.sync_api import sync_playwright

from vaultkit.config import load_env_file

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "img"
GW = "http://127.0.0.1:8800"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    creds = load_env_file(str(ROOT / ".lab" / "dashboard.env"), override=False)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        page = browser.new_page(viewport={"width": 1360, "height": 900}, device_scale_factor=2,
                                color_scheme="light")
        page.goto(GW)
        page.wait_for_selector(".svc .port")
        page.wait_for_timeout(600)
        page.screenshot(path=OUT / "01-painel-microservicos.png", full_page=True)

        page.fill("#role", creds["VAULTKIT_ROLE_ID"])
        page.fill("#sid", creds["VAULTKIT_SECRET_ID"])
        page.click("#btn-login")
        page.wait_for_selector("#login-out .msg")
        page.screenshot(path=OUT / "02-login-approle.png", full_page=True)

        page.fill("#path", "apps/")
        page.click("#btn-list")
        page.wait_for_selector(".keys a")
        page.click(".keys a >> text=env-injector/")
        page.wait_for_selector(".keys a >> text=config")
        page.click(".keys a >> text=config")
        page.wait_for_selector("table.kv")
        page.locator(".reveal").first.click()
        page.wait_for_timeout(300)
        page.screenshot(path=OUT / "03-leitura-segredo.png", full_page=True)

        page.click("#btn-read")  # segunda leitura: cache do secret-service
        page.wait_for_selector("text=cache do secret-service")
        page.fill("#path", "apps/db-checker/postgres")
        page.click("#btn-read")
        page.wait_for_timeout(500)
        page.wait_for_timeout(5200)  # atualização da auditoria
        page.screenshot(path=OUT / "04-auditoria-e-rastro.png", full_page=True)

        for name, port in [("api-gateway", 8800), ("auth-service", 8801), ("secret-service", 8802),
                           ("audit-service", 8803)]:
            doc = browser.new_page(viewport={"width": 1280, "height": 900}, device_scale_factor=2)
            doc.goto(f"http://127.0.0.1:{port}/docs")
            doc.wait_for_selector(".opblock")
            doc.wait_for_timeout(400)
            doc.screenshot(path=OUT / f"swagger-{name}.png", full_page=True)
            doc.close()
        browser.close()
    print("capturas em", OUT)


if __name__ == "__main__":
    main()
