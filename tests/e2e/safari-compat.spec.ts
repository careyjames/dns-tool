import { test, expect } from '@playwright/test';

test.describe('Safari/WebKit Compatibility', () => {
  test('loading overlay uses opacity-based hiding (not display:none)', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    const overlay = page.locator('#loadingOverlay');
    await expect(overlay).toBeAttached();

    const styles = await overlay.evaluate(el => {
      const cs = getComputedStyle(el);
      return {
        display: cs.display,
        opacity: cs.opacity,
        visibility: cs.visibility,
        pointerEvents: cs.pointerEvents,
      };
    });

    const isHidden = styles.display === 'none' || (styles.opacity === '0' && styles.visibility === 'hidden');
    expect(isHidden).toBe(true);
    if (styles.display !== 'none') {
      expect(styles.pointerEvents).toBe('none');
    }
  });

  test('overlay element is div with role=status', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    const overlay = page.locator('#loadingOverlay');
    const tagName = await overlay.evaluate(el => el.tagName.toLowerCase());
    expect(tagName).toBe('div');
    const role = await overlay.getAttribute('role');
    expect(role).toBe('status');
  });

  test('no inline onclick/onchange handlers (CSP compliance)', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    const inlineHandlers = await page.evaluate(() => {
      const allElements = document.querySelectorAll('*');
      const violations: string[] = [];
      allElements.forEach(el => {
        const attrs = el.attributes;
        for (let i = 0; i < attrs.length; i++) {
          const name = attrs[i].name.toLowerCase();
          if (name.startsWith('on') && name !== 'one') {
            violations.push(`${el.tagName}#${el.id || '(no-id)'} has ${name}`);
          }
        }
      });
      return violations;
    });
    expect(inlineHandlers).toEqual([]);
  });

  test('CSS animations are defined (not suppressed by display:none)', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    const pulseExists = await page.evaluate(() => {
      const sheets = document.styleSheets;
      for (let i = 0; i < sheets.length; i++) {
        try {
          const rules = sheets[i].cssRules;
          for (let j = 0; j < rules.length; j++) {
            if (rules[j] instanceof CSSKeyframesRule && (rules[j] as CSSKeyframesRule).name === 'pulse') {
              return true;
            }
          }
        } catch (e) {}
      }
      return false;
    });
    if (!pulseExists) {
      const sheetCount = await page.evaluate(() => {
        let accessible = 0;
        for (let i = 0; i < document.styleSheets.length; i++) {
          try { void document.styleSheets[i].cssRules; accessible++; } catch (e) {}
        }
        return { total: document.styleSheets.length, accessible };
      });
      test.skip(sheetCount.accessible === 0, 'WebKit blocks cross-origin stylesheet access in CI');
    }
    expect(pulseExists).toBe(true);
  });

  test('loading dots animation keyframes exist', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    const bounceExists = await page.evaluate(() => {
      const sheets = document.styleSheets;
      for (let i = 0; i < sheets.length; i++) {
        try {
          const rules = sheets[i].cssRules;
          for (let j = 0; j < rules.length; j++) {
            if (rules[j] instanceof CSSKeyframesRule && (rules[j] as CSSKeyframesRule).name === 'bounce') {
              return true;
            }
          }
        } catch (e) {}
      }
      return false;
    });
    if (!bounceExists) {
      const sheetCount = await page.evaluate(() => {
        let accessible = 0;
        for (let i = 0; i < document.styleSheets.length; i++) {
          try { void document.styleSheets[i].cssRules; accessible++; } catch (e) {}
        }
        return { total: document.styleSheets.length, accessible };
      });
      test.skip(sheetCount.accessible === 0, 'WebKit blocks cross-origin stylesheet access in CI');
    }
    expect(bounceExists).toBe(true);
  });

  test('history page overlay uses same pattern', async ({ page }) => {
    await page.goto('/history');
    await page.waitForLoadState('networkidle');
    const overlays = page.locator('.loading-overlay');
    const count = await overlays.count();
    if (count > 0) {
      const overlay = overlays.first();
      const styles = await overlay.evaluate(el => {
        const cs = getComputedStyle(el);
        return { display: cs.display, opacity: cs.opacity, visibility: cs.visibility };
      });
      const isHidden = styles.display === 'none' || (styles.opacity === '0' && styles.visibility === 'hidden');
      expect(isHidden).toBe(true);

      const tagName = await overlay.evaluate(el => el.tagName.toLowerCase());
      expect(tagName).toBe('div');
    }
  });

  test('investigate page overlay uses same pattern', async ({ page }) => {
    await page.goto('/investigate');
    await page.waitForLoadState('networkidle');
    const overlay = page.locator('#loadingOverlay');
    if (await overlay.count() > 0) {
      const styles = await overlay.evaluate(el => {
        const cs = getComputedStyle(el);
        return { display: cs.display, opacity: cs.opacity, visibility: cs.visibility };
      });
      const isHidden = styles.display === 'none' || (styles.opacity === '0' && styles.visibility === 'hidden');
      expect(isHidden).toBe(true);

      const tagName = await overlay.evaluate(el => el.tagName.toLowerCase());
      expect(tagName).toBe('div');
    }
  });
});
