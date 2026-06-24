#!/usr/bin/env python3
"""Capture MagikUp screenshots using Playwright (Python)."""
import os, sys, time
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE_URL  = os.environ.get("MAGIKUP_URL",  "http://localhost:8000")
SCDIR     = Path("./docs/screenshots")
USERNAME  = os.environ.get("MAGIKUP_USER", "admin")
PASSWORD  = os.environ.get("MAGIKUP_PASS")

if not PASSWORD:
    sys.exit("ERROR: MAGIKUP_PASS env var is required (see logs for INITIAL ADMIN PASSWORD)")

SCDIR.mkdir(parents=True, exist_ok=True)

def shot(page, name, full_page=False):
    path = str(SCDIR / f"{name}.png")
    time.sleep(0.8)
    page.screenshot(path=path, full_page=full_page)
    print(f"  \u2713 {name}.png")

def login(page):
    page.goto(f"{BASE_URL}/login")
    page.wait_for_selector('input[name="username"]')
    shot(page, "01_login")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_function("() => !window.location.pathname.includes('login')", timeout=15000)
    time.sleep(1)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(
        viewport={"width": 1440, "height": 900},
        device_scale_factor=2,
        color_scheme="light",
    )
    page = ctx.new_page()

    try:
        print("\U0001f4f8 Capturing screenshots...\n")

        print("[Login]")
        login(page)

        print("[Dashboard]")
        page.goto(f"{BASE_URL}/")
        page.wait_for_selector(".container-fluid")
        time.sleep(1.5)
        shot(page, "02_dashboard")
        tbl = page.query_selector(".table")
        if tbl:
            tbl.scroll_into_view_if_needed()
            time.sleep(0.5)
            shot(page, "03_dashboard_operations")

        print("[Backup]")
        page.goto(f"{BASE_URL}/backup")
        page.wait_for_selector(".container-fluid")
        time.sleep(1)
        shot(page, "04_backup")

        ep_sel = page.query_selector("select#endpoint")
        if ep_sel:
            opts = page.query_selector_all("select#endpoint option")
            if len(opts) > 1:
                ep_sel.select_option(index=1)
                time.sleep(2)
                shot(page, "05_backup_endpoint_selected")

        print("[Backup - Advanced Parameters]")
        adv = page.query_selector("#advancedParamsToggle")
        if adv:
            page.evaluate("document.getElementById('advancedParamsToggle').click()")
            time.sleep(0.8)
            shot(page, "05b_backup_advanced_params", full_page=True)

            exc = page.query_selector("#excludeTableToggle")
            if exc:
                page.evaluate("document.getElementById('excludeTableToggle').click()")
                time.sleep(0.5)
                shot(page, "05c_backup_advanced_exclusions", full_page=True)
                page.evaluate("document.getElementById('excludeTableToggle').click()")

            page.evaluate("document.getElementById('advancedParamsToggle').click()")
            time.sleep(0.5)

        print("[Restore]")
        page.goto(f"{BASE_URL}/restore")
        page.wait_for_selector(".container-fluid")
        time.sleep(1)
        shot(page, "06_restore")

        print("[Restore - Advanced Parameters]")
        radv = page.query_selector("#advancedParamsToggle")
        if radv:
            page.evaluate("document.getElementById('advancedParamsToggle').click()")
            time.sleep(0.8)
            shot(page, "06b_restore_advanced_params", full_page=True)
            page.evaluate("document.getElementById('advancedParamsToggle').click()")
            time.sleep(0.5)

        print("[Transfer]")
        page.goto(f"{BASE_URL}/transfer")
        page.wait_for_selector(".container-fluid")
        time.sleep(1)
        shot(page, "07_transfer")

        print("[Transfer - Backup Advanced Parameters]")
        page.evaluate("document.getElementById('bkAdvancedParamsToggle').click()")
        time.sleep(0.8)
        shot(page, "07b_transfer_backup_advanced_params", full_page=True)
        page.evaluate("document.getElementById('bkAdvancedParamsToggle').click()")
        time.sleep(0.5)

        print("[Transfer - Restore Advanced Parameters]")
        page.evaluate("document.getElementById('rsAdvancedParamsToggle').click()")
        time.sleep(0.8)
        shot(page, "07c_transfer_restore_advanced_params", full_page=True)
        page.evaluate("document.getElementById('rsAdvancedParamsToggle').click()")
        time.sleep(0.5)

        # ---- Query Editor ----
        print("[Query Editor]")
        page.goto(f"{BASE_URL}/query-editor")
        page.wait_for_selector(".container-fluid")
        time.sleep(1.5)
        shot(page, "08a_query_editor")

        # Select endpoint if available
        qe_ep = page.query_selector("select#qeEndpoint")
        if qe_ep:
            qe_opts = page.query_selector_all("select#qeEndpoint option")
            if len(qe_opts) > 1:
                qe_ep.select_option(index=1)
                time.sleep(3)
                shot(page, "08b_query_editor_connected")

        # Type a sample query in the Ace editor
        ace_editor = page.query_selector("#qeEditorContainer .ace_editor")
        if ace_editor:
            page.evaluate("""() => {
                if (window.qeEditor) {
                    window.qeEditor.setValue('SELECT datname, pg_size_pretty(pg_database_size(datname)) AS size\\nFROM pg_database\\nWHERE datistemplate = false\\nORDER BY pg_database_size(datname) DESC;', -1);
                }
            }""")
            time.sleep(0.5)
            shot(page, "08c_query_editor_with_query")

        print("[Files]")
        page.goto(f"{BASE_URL}/files")
        page.wait_for_selector(".container-fluid")
        time.sleep(1)
        shot(page, "09_files")

        print("[Admin]")
        page.goto(f"{BASE_URL}/admin")
        page.wait_for_selector(".container-fluid")
        time.sleep(1)
        shot(page, "10_admin_endpoints")

        edit_btn = page.query_selector('button.btn-warning[onclick^="editEndpoint"]')
        if edit_btn:
            edit_btn.click()
            time.sleep(1)
            shot(page, "10b_admin_edit_endpoint_modal")
            close_btn = page.query_selector("#addEndpointModal .btn-close")
            if close_btn:
                close_btn.click()
                time.sleep(0.5)

        page.click("#jumphosts-tab")
        time.sleep(0.8)
        shot(page, "11_admin_jumphosts")

        page.click("#aws-tab")
        time.sleep(0.8)
        shot(page, "12_admin_aws")

        page.click("#settings-tab")
        time.sleep(0.8)
        shot(page, "13_admin_settings", full_page=True)

        page.click("#importexport-tab")
        time.sleep(0.8)
        shot(page, "14_admin_importexport")

        page.click("#security-tab")
        time.sleep(0.8)
        shot(page, "15_admin_security")

        page.click("#users-tab")
        time.sleep(0.8)
        shot(page, "16_admin_users")

        add_user = page.query_selector('button[data-bs-target="#addUserModal"]')
        if add_user:
            add_user.click()
            time.sleep(0.8)
            shot(page, "17_admin_add_user_modal")
            page.click('#addUserModal .btn-close')
            time.sleep(0.5)

        audit = page.query_selector('button[onclick="loadAuditLog()"]')
        if audit:
            audit.scroll_into_view_if_needed()
            audit.click()
            time.sleep(1.5)
            shot(page, "18_admin_audit_log")

        print("[Info]")
        page.goto(f"{BASE_URL}/info")
        page.wait_for_selector(".container-fluid")
        time.sleep(1)
        shot(page, "19_info")

        print("[Change Password]")
        page.goto(f"{BASE_URL}/change-password")
        page.wait_for_selector(".container-fluid, .container")
        time.sleep(1)
        shot(page, "20_change_password")

        print("[Dark Mode]")
        page.goto(f"{BASE_URL}/")
        time.sleep(0.5)
        page.evaluate("() => { localStorage.setItem('theme','dark'); document.documentElement.setAttribute('data-bs-theme','dark'); }")
        time.sleep(1)
        shot(page, "21_dashboard_dark")

        page.goto(f"{BASE_URL}/query-editor")
        page.wait_for_selector(".container-fluid")
        time.sleep(0.5)
        page.evaluate("() => { localStorage.setItem('theme','dark'); document.documentElement.setAttribute('data-bs-theme','dark'); }")
        time.sleep(1)
        shot(page, "22_query_editor_dark")

        page.goto(f"{BASE_URL}/info")
        page.wait_for_selector(".container-fluid")
        time.sleep(0.5)
        page.evaluate("() => { localStorage.setItem('theme','dark'); document.documentElement.setAttribute('data-bs-theme','dark'); }")
        time.sleep(1)
        shot(page, "23_info_dark")

        page.goto(f"{BASE_URL}/login")
        time.sleep(0.5)
        page.evaluate("() => { localStorage.setItem('theme','dark'); document.documentElement.setAttribute('data-bs-theme','dark'); }")
        time.sleep(1)
        shot(page, "24_login_dark")

        page.evaluate("() => { localStorage.setItem('theme','light'); document.documentElement.setAttribute('data-bs-theme','light'); }")

        print("[Navbar]")
        login(page)
        time.sleep(0.5)
        dd = page.query_selector('.dropdown-toggle, #userDropdown, [data-bs-toggle="dropdown"]')
        if dd:
            dd.click()
            time.sleep(0.5)
            shot(page, "25_navbar_dropdown")

        print(f"\n\u2705 Done! Screenshots saved to {SCDIR}/")

    except Exception as e:
        print(f"\n\u274c Error: {e}")
        import traceback; traceback.print_exc()
        page.screenshot(path=str(SCDIR / "error_state.png"))
    finally:
        browser.close()
