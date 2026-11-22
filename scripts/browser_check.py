"""Exercise the running service and save portfolio screenshots from its synthetic demo."""
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


def main():
    destination = Path("docs/screenshots")
    destination.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 1080}, device_scale_factor=1)
        errors = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.goto("http://127.0.0.1:8000/")
        navigation = page.get_by_role("navigation", name="Main")
        expect(navigation.get_by_role("link")).to_have_text(["Workbench", "Capture library", "Detection rules"])
        expect(page.locator("#status")).to_contain_text("TShark", timeout=60000)
        expect(page.locator("#finding-list button")).to_have_count(3)
        expect(page.locator("#detail")).to_contain_text("12 frames")
        page.locator("#detail summary").click()
        expect(page.locator("#detail tbody tr")).to_have_count(10)
        page.screenshot(path=destination / "soc.png", full_page=True)
        page.get_by_role("button", name="GRC & audit").click()
        expect(page.locator(".matrix span")).to_have_count(25)
        expect(page.locator("#detail")).to_contain_text("A.8.20")
        expect(page.locator("#detail")).to_contain_text("72 hours")
        page.screenshot(path=destination / "grc.png", full_page=True)
        page.get_by_role("link", name="Change capture").click()
        expect(page.get_by_role("heading", name="Custom capture")).to_be_visible()
        page.get_by_role("link", name="Detection rules").click()
        sql_rule = page.locator("article").filter(has=page.get_by_role("heading", name="SQL injection indicators"))
        sql_rule.get_by_role("button", name="Inspect sample").click()
        expect(page.locator("#capture-title")).to_have_text("SQL injection", timeout=60000)
        expect(page.locator("#detail")).to_contain_text("A.8.28")
        page.get_by_role("link", name="Capture library").click()
        capture = Path(__file__).resolve().parents[1] / "sample_pcaps" / "03_ssh_burst.pcap"
        page.get_by_label("Choose a packet capture").set_input_files(capture)
        expect(page.locator("#capture-title")).to_have_text("Custom capture", timeout=60000)
        expect(page.locator("#capture-file")).to_have_text(capture.name)
        expect(page.locator("#detail")).to_contain_text("A.8.5")
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "Mobile page overflows"
        assert not errors, errors
        browser.close()


if __name__ == "__main__":
    main()
