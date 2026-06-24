import { chromium } from 'playwright';
import { mkdirSync } from 'fs';

const BASE_URL = process.env.MAGIKUP_URL || 'http://localhost:8000';
const SCREENSHOT_DIR = './docs/screenshots';
const USERNAME = process.env.MAGIKUP_USER || 'admin';
const PASSWORD = process.env.MAGIKUP_PASS || (() => { throw new Error('MAGIKUP_PASS env var is required (see logs for INITIAL ADMIN PASSWORD)'); })();

mkdirSync(SCREENSHOT_DIR, { recursive: true });

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  deviceScaleFactor: 2,
  colorScheme: 'light',
});

const page = await context.newPage();

async function screenshot(name, opts = {}) {
  const path = `${SCREENSHOT_DIR}/${name}.png`;
  await page.waitForTimeout(800);
  if (opts.fullPage) {
    await page.screenshot({ path, fullPage: true });
  } else {
    await page.screenshot({ path });
  }
  console.log(`  ✓ ${name}.png`);
}

async function login() {
  await page.goto(`${BASE_URL}/login`);
  await page.waitForSelector('input[name="username"]');
  await screenshot('01_login');

  await page.fill('input[name="username"]', USERNAME);
  await page.fill('input[name="password"]', PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL('**/');
  await page.waitForTimeout(1000);
}

try {
  // 1. Login page
  console.log('📸 Capturing screenshots...\n');
  console.log('[Login]');
  await login();

  // 2. Dashboard
  console.log('[Dashboard]');
  await page.goto(`${BASE_URL}/`);
  await page.waitForSelector('.container-fluid');
  await page.waitForTimeout(1500);
  await screenshot('02_dashboard');

  // Scroll to operations table
  const opsTable = await page.$('.table');
  if (opsTable) {
    await opsTable.scrollIntoViewIfNeeded();
    await page.waitForTimeout(500);
    await screenshot('03_dashboard_operations');
  }

  // 3. Backup page
  console.log('[Backup]');
  await page.goto(`${BASE_URL}/backup`);
  await page.waitForSelector('.container-fluid');
  await page.waitForTimeout(1000);
  await screenshot('04_backup');

  // Try selecting an endpoint to show schema mode
  const endpointSelect = await page.$('select#endpoint');
  if (endpointSelect) {
    const options = await endpointSelect.$$('option');
    if (options.length > 1) {
      await endpointSelect.selectOption({ index: 1 });
      await page.waitForTimeout(2000);
      await screenshot('05_backup_endpoint_selected');
    }
  }

  // Open Advanced Parameters panel
  console.log('[Backup - Advanced Parameters]');
  const advancedToggle = await page.$('#advancedParamsToggle');
  if (advancedToggle) {
    await advancedToggle.click();
    await page.waitForTimeout(800);
    await screenshot('05b_backup_advanced_params', { fullPage: true });

    // Enable exclude-table to show the pattern input
    const excludeTableToggle = await page.$('#excludeTableToggle');
    if (excludeTableToggle) {
      await excludeTableToggle.click();
      await page.waitForTimeout(500);
      await screenshot('05c_backup_advanced_exclusions', { fullPage: true });
      // Disable it back
      await excludeTableToggle.click();
    }

    // Close advanced params
    await advancedToggle.click();
    await page.waitForTimeout(500);
  }

  // 4. Restore page
  console.log('[Restore]');
  await page.goto(`${BASE_URL}/restore`);
  await page.waitForSelector('.container-fluid');
  await page.waitForTimeout(1000);
  await screenshot('06_restore');

  // Open Restore Advanced Parameters panel
  console.log('[Restore - Advanced Parameters]');
  const restoreAdvancedToggle = await page.$('#advancedParamsToggle');
  if (restoreAdvancedToggle) {
    await restoreAdvancedToggle.click();
    await page.waitForTimeout(800);
    await screenshot('06b_restore_advanced_params', { fullPage: true });

    // Close advanced params
    await restoreAdvancedToggle.click();
    await page.waitForTimeout(500);
  }

  // 5. Transfer page
  console.log('[Transfer]');
  await page.goto(`${BASE_URL}/transfer`);
  await page.waitForSelector('.container-fluid');
  await page.waitForTimeout(1000);
  await screenshot('07_transfer');

  // Transfer - Backup Advanced Parameters
  console.log('[Transfer - Backup Advanced Parameters]');
  await page.evaluate(() => document.getElementById('bkAdvancedParamsToggle').click());
  await page.waitForTimeout(800);
  await screenshot('07b_transfer_backup_advanced_params', { fullPage: true });
  await page.evaluate(() => document.getElementById('bkAdvancedParamsToggle').click());
  await page.waitForTimeout(500);

  // Transfer - Restore Advanced Parameters
  console.log('[Transfer - Restore Advanced Parameters]');
  await page.evaluate(() => document.getElementById('rsAdvancedParamsToggle').click());
  await page.waitForTimeout(800);
  await screenshot('07c_transfer_restore_advanced_params', { fullPage: true });
  await page.evaluate(() => document.getElementById('rsAdvancedParamsToggle').click());
  await page.waitForTimeout(500);

  // 6. Files page
  console.log('[Files]');
  await page.goto(`${BASE_URL}/files`);
  await page.waitForSelector('.container-fluid');
  await page.waitForTimeout(1000);
  await screenshot('08_files');

  // 7. Admin page - all tabs
  console.log('[Admin]');
  await page.goto(`${BASE_URL}/admin`);
  await page.waitForSelector('.container-fluid');
  await page.waitForTimeout(1000);
  await screenshot('09_admin_endpoints');

  // Try to open Edit Endpoint modal (click the first edit button if present)
  const editEndpointBtn = await page.$('button.btn-warning[onclick^="editEndpoint"]');
  if (editEndpointBtn) {
    await editEndpointBtn.click();
    await page.waitForTimeout(1000);
    await screenshot('09b_admin_edit_endpoint_modal');
    // Close modal
    const closeBtn = await page.$('#addEndpointModal .btn-close');
    if (closeBtn) {
      await closeBtn.click();
      await page.waitForTimeout(500);
    }
  }

  // Tab: Jump Hosts
  await page.click('#jumphosts-tab');
  await page.waitForTimeout(800);
  await screenshot('10_admin_jumphosts');

  // Tab: AWS
  await page.click('#aws-tab');
  await page.waitForTimeout(800);
  await screenshot('11_admin_aws');

  // Tab: Settings
  await page.click('#settings-tab');
  await page.waitForTimeout(800);
  await screenshot('12_admin_settings');

  // Tab: Import/Export
  await page.click('#importexport-tab');
  await page.waitForTimeout(800);
  await screenshot('13_admin_importexport');

  // Tab: Security
  await page.click('#security-tab');
  await page.waitForTimeout(800);
  await screenshot('14_admin_security');

  // Tab: Users
  await page.click('#users-tab');
  await page.waitForTimeout(800);
  await screenshot('15_admin_users');

  // Try to open Add User modal
  const addUserBtn = await page.$('button[data-bs-target="#addUserModal"]');
  if (addUserBtn) {
    await addUserBtn.click();
    await page.waitForTimeout(800);
    await screenshot('16_admin_add_user_modal');
    // Close modal
    await page.click('#addUserModal .btn-close');
    await page.waitForTimeout(500);
  }

  // Audit Log - scroll to it and click refresh
  const auditRefresh = await page.$('button[onclick="loadAuditLog()"]');
  if (auditRefresh) {
    await auditRefresh.scrollIntoViewIfNeeded();
    await auditRefresh.click();
    await page.waitForTimeout(1500);
    await screenshot('17_admin_audit_log');
  }

  // 8. Change Password page
  console.log('[Change Password]');
  await page.goto(`${BASE_URL}/change-password`);
  await page.waitForSelector('.container-fluid, .container');
  await page.waitForTimeout(1000);
  await screenshot('18_change_password');

  // 9. Dark mode variants — force dark theme via JS + localStorage
  console.log('[Dark Mode]');
  await page.goto(`${BASE_URL}/`);
  await page.waitForTimeout(500);
  await page.evaluate(() => {
    localStorage.setItem('theme', 'dark');
    document.documentElement.setAttribute('data-bs-theme', 'dark');
  });
  await page.waitForTimeout(1000);
  await screenshot('19_dashboard_dark');

  // Dark mode login
  await page.goto(`${BASE_URL}/login`);
  await page.waitForTimeout(500);
  await page.evaluate(() => {
    localStorage.setItem('theme', 'dark');
    document.documentElement.setAttribute('data-bs-theme', 'dark');
  });
  await page.waitForTimeout(1000);
  await screenshot('20_login_dark');

  // Restore light theme
  await page.evaluate(() => {
    localStorage.setItem('theme', 'light');
    document.documentElement.setAttribute('data-bs-theme', 'light');
  });

  // 10. Navbar / user dropdown
  console.log('[Navbar]');
  await login(); // re-login after visiting login page
  await page.waitForTimeout(500);

  const userDropdown = await page.$('.dropdown-toggle, #userDropdown, [data-bs-toggle="dropdown"]');
  if (userDropdown) {
    await userDropdown.click();
    await page.waitForTimeout(500);
    await screenshot('21_navbar_dropdown');
  }

  console.log(`\n✅ Done! Screenshots saved to ${SCREENSHOT_DIR}/`);

} catch (error) {
  console.error(`\n❌ Error: ${error.message}`);
  await page.screenshot({ path: `${SCREENSHOT_DIR}/error_state.png` });
} finally {
  await browser.close();
}
