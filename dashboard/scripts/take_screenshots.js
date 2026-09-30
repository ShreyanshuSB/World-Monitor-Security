import puppeteer from 'puppeteer-core';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const EDGE_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const OUT_DIR = path.resolve(__dirname, '..', 'docs', 'screenshots');

if (!fs.existsSync(OUT_DIR)) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
}

async function capture() {
  console.log('Launching Edge via puppeteer-core...');
  const browser = await puppeteer.launch({
    executablePath: EDGE_PATH,
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu'],
  });

  const page = await browser.newPage();

  // Test viewports
  const viewports = [
    { name: '1440', width: 1440, height: 900 },
    { name: '1920', width: 1920, height: 1080 },
  ];

  const themes = ['dark', 'light'];

  for (const theme of themes) {
    for (const vp of viewports) {
      await page.setViewport({ width: vp.width, height: vp.height });
      await page.goto('http://127.0.0.1:5173', { waitUntil: 'networkidle0' });

      // Apply theme
      await page.evaluate((t) => {
        document.documentElement.setAttribute('data-theme', t);
        localStorage.setItem('wm_theme', t);
      }, theme);

      await new Promise((r) => setTimeout(r, 600));

      const clickNav = async (label) => {
        await page.evaluate((l) => {
          const btns = Array.from(document.querySelectorAll('aside button'));
          const btn = btns.find((b) => b.textContent?.toLowerCase().includes(l.toLowerCase()));
          if (btn) btn.click();
        }, label);
        await new Promise((r) => setTimeout(r, 450));
      };

      // 1. Overview Page
      await clickNav('Posture overview');
      const overviewFile = path.join(OUT_DIR, `overview_${theme}_${vp.name}.png`);
      await page.screenshot({ path: overviewFile, fullPage: false });
      console.log(`Saved: ${overviewFile}`);

      // 2. Run Assessment Page
      await clickNav('Run assessment');
      const runFile = path.join(OUT_DIR, `run_assessment_${theme}_${vp.name}.png`);
      await page.screenshot({ path: runFile, fullPage: false });
      console.log(`Saved: ${runFile}`);

      // 3. Findings Inventory
      await clickNav('Findings inventory');
      const findingsFile = path.join(OUT_DIR, `findings_${theme}_${vp.name}.png`);
      await page.screenshot({ path: findingsFile, fullPage: false });
      console.log(`Saved: ${findingsFile}`);

      // 4. Open Finding Detail Drawer (click first finding row)
      await page.evaluate(() => {
        const rows = document.querySelectorAll('tbody tr');
        if (rows.length > 0) rows[0].click();
      });
      await new Promise((r) => setTimeout(r, 400));
      const drawerFile = path.join(OUT_DIR, `finding_detail_${theme}_${vp.name}.png`);
      await page.screenshot({ path: drawerFile, fullPage: false });
      console.log(`Saved: ${drawerFile}`);

      // Close drawer
      await page.evaluate(() => {
        const closeBtn = document.querySelector('button[aria-label="Close drawer"]');
        if (closeBtn) closeBtn.click();
      });
      await new Promise((r) => setTimeout(r, 200));

      // 5. Remediation & Re-test
      await clickNav('Remediation & re-test');
      const remFile = path.join(OUT_DIR, `remediation_${theme}_${vp.name}.png`);
      await page.screenshot({ path: remFile, fullPage: false });
      console.log(`Saved: ${remFile}`);

      // 6. Attack Paths
      await clickNav('Attack paths');
      const attackFile = path.join(OUT_DIR, `attack_paths_${theme}_${vp.name}.png`);
      await page.screenshot({ path: attackFile, fullPage: false });
      console.log(`Saved: ${attackFile}`);

      // 7. OWASP & Domains (Coverage)
      await clickNav('OWASP & domains');
      const covFile = path.join(OUT_DIR, `coverage_${theme}_${vp.name}.png`);
      await page.screenshot({ path: covFile, fullPage: false });
      console.log(`Saved: ${covFile}`);

      // 8. Formal Report
      await clickNav('Formal report');
      const reportFile = path.join(OUT_DIR, `report_${theme}_${vp.name}.png`);
      await page.screenshot({ path: reportFile, fullPage: false });
      console.log(`Saved: ${reportFile}`);

      // 9. Audit Log Ledger
      await clickNav('Audit log ledger');
      const auditFile = path.join(OUT_DIR, `audit_log_${theme}_${vp.name}.png`);
      await page.screenshot({ path: auditFile, fullPage: false });
      console.log(`Saved: ${auditFile}`);

      // 10. Methodology & Scope
      await clickNav('Methodology & scope');
      const methodFile = path.join(OUT_DIR, `methodology_${theme}_${vp.name}.png`);
      await page.screenshot({ path: methodFile, fullPage: false });
      console.log(`Saved: ${methodFile}`);
    }
  }

  await browser.close();
  console.log('All screenshots completed successfully!');
}

capture().catch((err) => {
  console.error('Capture failed:', err);
  process.exit(1);
});
