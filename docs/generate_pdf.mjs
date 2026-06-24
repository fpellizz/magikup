import { chromium } from 'playwright';
import { resolve } from 'path';

const htmlPath = resolve('./docs/MagikUp_User_Manual.html');
const pdfPath = resolve('./docs/MagikUp_User_Manual.pdf');

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();

await page.goto(`file://${htmlPath}`, { waitUntil: 'networkidle' });
await page.waitForTimeout(2000);

await page.pdf({
  path: pdfPath,
  format: 'A4',
  margin: { top: '20mm', bottom: '20mm', left: '25mm', right: '25mm' },
  printBackground: true,
  displayHeaderFooter: true,
  headerTemplate: '<div></div>',
  footerTemplate: '<div style="font-size:8pt; color:#999; width:100%; text-align:center; padding:0 40px;"><span class="pageNumber"></span> / <span class="totalPages"></span></div>',
});

console.log(`PDF generated: ${pdfPath}`);
await browser.close();
