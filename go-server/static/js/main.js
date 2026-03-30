(function() {
    if (document.documentElement.classList.contains('covert-mode')) {
        document.body.classList.add('covert-mode');
        try {
            const env = localStorage.getItem('covertEnv') ?? 'tactical';
            document.body.classList.add('covert-' + env);
        } catch(_e) { /* localStorage unavailable — fall back to tactical */ // NOSONAR
            document.body.classList.add('covert-tactical');
        }
    }
    if (!document.getElementById('covertFilterOverlay')) {
        const overlay = document.createElement('div');
        overlay.id = 'covertFilterOverlay';
        overlay.className = 'covert-filter-overlay';
        document.body.appendChild(overlay);
    }
})();

(function() {
'use strict';

function parseIcon(html) {
    if (!html) return document.createTextNode('');
    const doc = new DOMParser().parseFromString(html, 'text/html');
    return doc.body.firstElementChild ?? document.createTextNode('');
}

function setIconAndText(el, iconHtml, text) {
    el.textContent = '';
    if (iconHtml) el.appendChild(parseIcon(iconHtml));
    if (text) el.appendChild(document.createTextNode(text));
}

function stripDots(s) {
    let d = s;
    while (d.charAt(0) === '.') d = d.slice(1);
    while (d.charAt(d.length - 1) === '.') d = d.slice(0, -1);
    return d;
}

function isValidLabel(label) {
    if (label.length === 0 || label.length > 63) return false;
    return !(label.startsWith('-') || label.endsWith('-'));
}

if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(function() { /* intentionally empty — SW optional */ }); // NOSONAR
}

function clearOverlayTimers(overlay) {
    overlay.classList.remove('is-active');
    if (overlay.dataset.timerId) {
        clearInterval(Number(overlay.dataset.timerId));
        delete overlay.dataset.timerId;
    }
    if (overlay.dataset.pollId) {
        clearInterval(Number(overlay.dataset.pollId));
        delete overlay.dataset.pollId;
    }
}

function resetAnalyzeButtons() {
    const reanalyzeBtn = document.getElementById('reanalyzeBtn');
    if (reanalyzeBtn && !reanalyzeBtn.classList.contains('disabled')) {
        reanalyzeBtn.textContent = ' Re-analyze';
        if (globalThis._icons) { reanalyzeBtn.insertBefore(parseIcon(globalThis._icons.sync), reanalyzeBtn.firstChild); }
    }
    const analyzeBtn = document.getElementById('analyzeBtn');
    if (analyzeBtn) {
        setIconAndText(analyzeBtn, globalThis._icons?.search ?? null, ' Analyze');
        analyzeBtn.disabled = false;
    }
    for (const b of document.querySelectorAll('.history-view-btn,.history-reanalyze-btn')) {
        b.classList.remove('disabled');
        b.removeAttribute('aria-disabled');
    }
}

globalThis.addEventListener('pageshow', function(e) {
    if (e.persisted) {
        for (const overlay of document.querySelectorAll('.loading-overlay')) {
            clearOverlayTimers(overlay);
        }
        resetTopologyNodes();
        document.body.classList.remove('loading');
        resetAnalyzeButtons();
    }
});

/*
 * Safari/WebKit Scan Overlay — Two Bugs, Two Fixes
 *
 * BUG 1 — Animation restart: WebKit does not restart CSS animations
 * when an element transitions from display:none to visible. The
 * double-rAF below forces a reflow so spinners/dots animate.
 *
 * BUG 2 — Timer freeze on navigation: Using location.href to start
 * a scan triggers a full-page navigation. WebKit kills all running
 * JS timers during navigation, so the overlay timer freezes at 0s.
 *
 * REQUIRED PATTERN for any scan action that shows an overlay:
 *   1. Call showOverlay(overlay) — activates overlay + fixes animations
 *   2. Call startStatusCycle(overlay) — starts timer + phase rotation
 *   3. Use fetch(url) to submit the scan (keeps JS alive)
 *   4. On response: parse with DOMParser and replace document element
 *   5. Update URL: history.replaceState(null, '', resp.url)
 *   6. Fallback: .catch → location.href (graceful degradation)
 *
 * NEVER use location.href or globalThis.location to start a scan that
 * depends on an active overlay timer. See index.html and history.html
 * for reference implementations.
 */
function showOverlay(overlay) {
    if (!overlay) return;
    overlay.classList.add('is-active');
    requestAnimationFrame(function() {
        requestAnimationFrame(function() {
            const els = overlay.querySelectorAll('.loading-spinner, .loading-spinner i, .loading-dots span');
            const animated = [];
            for (const el of els) {
                const anim = getComputedStyle(el).animationName;
                if (anim && anim !== 'none') animated.push(el);
            }
            for (const el of animated) el.classList.add('anim-restart');
            if (animated.length) void animated[0].offsetWidth; // NOSONAR — single reflow to restart all animations (Safari)
            for (const el of animated) el.classList.remove('anim-restart');
        });
    });
}

function startStatusCycle(overlayEl) {
    const timerEl = document.getElementById('loadingTimer') ?? overlayEl.querySelector('.loading-elapsed span');
    const noteEl = document.getElementById('loadingNote');
    const startTime = Date.now();

    if (timerEl) {
        timerEl.textContent = '0s';
        const timerId = setInterval(function() {
            const elapsed = Math.floor((Date.now() - startTime) / 1000);
            timerEl.textContent = elapsed + 's';
        }, 1000);
        overlayEl.dataset.timerId = timerId;
    }
    if (noteEl) {
        setTimeout(function() {
            noteEl.classList.add('u-opacity-visible');
        }, 6000);
    }

    const topoEl = document.getElementById('scanTopology');
    if (topoEl) {
        topoEl.setAttribute('aria-hidden', 'false');
    }
}

const PHASE_DONE_CLASSES = ['phase-done-dns','phase-done-email','phase-done-dnssec','phase-done-ct','phase-done-smtp','phase-done-policy','phase-done-registrar','phase-done-engine','phase-done-web3'];
const PHASE_RUNNING_CLASSES = ['phase-running-dns','phase-running-email','phase-running-dnssec','phase-running-ct','phase-running-smtp','phase-running-policy','phase-running-registrar','phase-running-engine','phase-running-web3'];
const SUB_RUNNING_CLASSES = ['sub-running-dns','sub-running-email','sub-running-dnssec','sub-running-ct','sub-running-smtp','sub-running-policy','sub-running-registrar','sub-running-engine','sub-running-web3'];
const CONN_DONE_CLASSES = ['conn-done-dns','conn-done-email','conn-done-dnssec','conn-done-ct','conn-done-smtp','conn-done-policy','conn-done-registrar','conn-done-engine','conn-done-web3'];
const CONN_ACTIVE_CLASSES = ['conn-active-dns','conn-active-email','conn-active-dnssec','conn-active-ct','conn-active-smtp','conn-active-policy','conn-active-registrar','conn-active-engine','conn-active-web3'];
const RESOLVER_KEYS = ['cf','g','q9','od','eu'];
const RES_DONE_CLASSES = ['res-done-cf','res-done-g','res-done-q9','res-done-od','res-done-eu'];

function removeClasses(el, classes) {
    for (const c of classes) el.classList.remove(c);
}

function resetResolverElements(els) {
    for (const el of els) {
        el.classList.remove('res-running');
        removeClasses(el, RES_DONE_CLASSES);
    }
}

function applyResolverStatus(dots, lines, labels, rk, dnsStatus) {
    if (dnsStatus === 'running') {
        for (const d of dots) d.classList.add('res-running');
        for (const l of lines) l.classList.add('res-running');
    } else if (dnsStatus === 'done') {
        for (const d of dots) d.classList.add('res-done-' + rk);
        for (const l of lines) l.classList.add('res-done-' + rk);
        for (const lb of labels) lb.classList.add('res-label-done');
    }
}

function updateResolverDots(topoEl, dnsStatus) {
    for (const rk of RESOLVER_KEYS) {
        const dots = topoEl.querySelectorAll('.topo-res-dot[data-resolver="' + rk + '"]');
        const lines = topoEl.querySelectorAll('.topo-res-line[data-resolver="' + rk + '"]');
        const labels = topoEl.querySelectorAll('.topo-res-label[data-resolver="' + rk + '"]');
        resetResolverElements(dots);
        resetResolverElements(lines);
        for (const lb of labels) lb.classList.remove('res-label-done');
        applyResolverStatus(dots, lines, labels, rk, dnsStatus);
    }
}

function resetPhaseNode(node, taskEl, info) {
    node.classList.remove('phase-running', 'phase-done');
    removeClasses(node, PHASE_DONE_CLASSES);
    removeClasses(node, PHASE_RUNNING_CLASSES);
    if (taskEl) {
        taskEl.classList.remove('sub-done');
        removeClasses(taskEl, SUB_RUNNING_CLASSES);
        if (info.tasks_total > 0) {
            taskEl.textContent = (info.tasks_done ?? 0) + '/' + info.tasks_total;
        }
    }
}

function applyPhaseConnectors(topoEl, group, pkey, isDone) {
    for (const line of topoEl.querySelectorAll('.topo-connector')) {
        if (line.dataset.from !== group) continue;
        if (isDone) {
            line.classList.remove('active');
            removeClasses(line, CONN_ACTIVE_CLASSES);
            line.classList.add('complete', 'conn-done-' + pkey);
        } else {
            line.classList.add('active', 'conn-active-' + pkey);
        }
    }
}

function updatePhaseNode(topoEl, node, info, pkey, taskEl, durEl, group) {
    resetPhaseNode(node, taskEl, info);
    if (info.status === 'done') {
        node.classList.add('phase-done', 'phase-done-' + pkey);
        if (taskEl) taskEl.classList.add('sub-done');
        if (durEl && info.duration_ms > 0) {
            durEl.textContent = (info.duration_ms / 1000).toFixed(1) + 's';
            durEl.classList.add('visible');
        }
        applyPhaseConnectors(topoEl, group, pkey, true);
    } else if (info.status === 'running') {
        node.classList.add('phase-running', 'phase-running-' + pkey);
        if (taskEl) taskEl.classList.add('sub-running-' + pkey);
        applyPhaseConnectors(topoEl, group, pkey, false);
    }
}

function updateTopologyFromProgress(data) {
    const topoEl = document.getElementById('scanTopology');
    if (!topoEl || !data?.phases) return;
    const phases = data.phases;
    const dnsPhase = phases['dns_records'];
    if (dnsPhase) {
        updateResolverDots(topoEl, dnsPhase.status);
    }
    for (const group of Object.keys(phases)) {
        const info = phases[group];
        const node = topoEl.querySelector('[data-phase="' + group + '"]');
        const durEl = topoEl.querySelector('[data-dur="' + group + '"]');
        const taskEl = topoEl.querySelector('[data-tasks="' + group + '"]');
        if (!node) continue;
        const pkey = node.dataset.pkey ?? 'dns';
        updatePhaseNode(topoEl, node, info, pkey, taskEl, durEl, group);
    }
}

function followRedirect(url, overlay, analyzeBtn) {
    fetch(url, {
        headers: { 'X-Requested-With': 'fetch' },
        redirect: 'follow'
    }).then(function(resp) {
        return resp.text().then(function(html) { hideOverlayAndReset(overlay, analyzeBtn); applyFetchedPage(html, resp.url); });
    }).catch(function() {
        hideOverlayAndReset(overlay, analyzeBtn);
        globalThis.location.href = url;
    });
}

function handlePollData(data, ctx) {
    if (!data) {
        if (ctx.failures >= 3) { clearInterval(ctx.pollId); hideOverlayAndReset(ctx.overlay, ctx.btn); }
        return;
    }
    updateTopologyFromProgress(data);
    if (data.status === 'failed') {
        clearInterval(ctx.pollId);
        hideOverlayAndReset(ctx.overlay, ctx.btn);
        showFlashAlert(data.error || 'Analysis failed. Please try again.', ctx.overlay ? ctx.overlay.parentNode : document.body);
        return;
    }
    if (data.status === 'complete' && data.redirect_url) {
        clearInterval(ctx.pollId);
        followRedirect(data.redirect_url, ctx.overlay, ctx.btn);
    } else if (data.status === 'complete') {
        clearInterval(ctx.pollId);
        hideOverlayAndReset(ctx.overlay, ctx.btn);
    }
    if (ctx.failures >= 3) { clearInterval(ctx.pollId); hideOverlayAndReset(ctx.overlay, ctx.btn); }
}

function startProgressPolling(token, overlay, analyzeBtn) {
    const ctx = { failures: 0, pollId: 0, overlay: overlay, btn: analyzeBtn };
    ctx.pollId = setInterval(function() {
        fetch('/api/scan/progress/' + token).then(function(resp) {
            if (!resp.ok) { ctx.failures++; return null; }
            ctx.failures = 0;
            return resp.json();
        }).then(function(data) {
            handlePollData(data, ctx);
        }).catch(function() {
            ctx.failures++;
            if (ctx.failures >= 3) { clearInterval(ctx.pollId); hideOverlayAndReset(overlay, analyzeBtn); }
        });
    }, 500);
    if (overlay) {
        overlay.dataset.pollId = ctx.pollId;
    }
    return ctx.pollId;
}

function hideOverlayAndReset(overlay, btn) {
    if (overlay) {
        overlay.classList.remove('is-active');
        if (overlay.dataset.timerId) {
            clearInterval(Number(overlay.dataset.timerId));
            delete overlay.dataset.timerId;
        }
        if (overlay.dataset.pollId) {
            clearInterval(Number(overlay.dataset.pollId));
            delete overlay.dataset.pollId;
        }
    }
    resetTopologyNodes();
    document.body.classList.remove('loading');
    if (btn) {
        setIconAndText(btn, globalThis._icons?.search ?? null, ' Analyze');
        btn.disabled = false;
    }
}

function showFlashAlert(message, container) {
    const flash = document.createElement('div');
    flash.className = 'alert alert-warning alert-dismissible fade show mt-3';
    flash.role = 'alert';
    flash.textContent = message;
    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'btn-close';
    closeBtn.dataset.bsDismiss = 'alert';
    flash.appendChild(closeBtn);
    const target = container ?? document.body;
    const form = target.querySelector('#domainForm');
    if (form?.parentNode) {
        form.parentNode.insertBefore(flash, form);
    } else {
        target.insertBefore(flash, target.firstChild);
    }
}

function resetTopologyNodes() {
    const topoEl = document.getElementById('scanTopology');
    if (!topoEl) return;
    topoEl.setAttribute('aria-hidden', 'true');
    for (const n of topoEl.querySelectorAll('.topo-node')) {
        n.classList.remove('phase-running', 'phase-done');
        removeClasses(n, PHASE_DONE_CLASSES);
        removeClasses(n, PHASE_RUNNING_CLASSES);
    }
    for (const d of topoEl.querySelectorAll('.topo-dur')) {
        d.textContent = '';
        d.classList.remove('visible');
    }
    for (const t of topoEl.querySelectorAll('.topo-sub[data-tasks]')) {
        t.classList.remove('sub-done');
        removeClasses(t, SUB_RUNNING_CLASSES);
    }
    for (const c of topoEl.querySelectorAll('.topo-connector')) {
        c.classList.remove('active', 'complete');
        removeClasses(c, CONN_DONE_CLASSES);
        removeClasses(c, CONN_ACTIVE_CLASSES);
    }
    for (const d of topoEl.querySelectorAll('.topo-res-dot')) {
        d.classList.remove('res-running');
        removeClasses(d, RES_DONE_CLASSES);
    }
    for (const l of topoEl.querySelectorAll('.topo-res-line')) {
        l.classList.remove('res-running');
        removeClasses(l, RES_DONE_CLASSES);
    }
    for (const lb of topoEl.querySelectorAll('.topo-res-label')) {
        lb.classList.remove('res-label-done');
    }
}

function isBareTopLevelDomain(domain) {
    if (!domain) return false;
    let d = domain.toLowerCase();
    while (d.charAt(0) === '.') d = d.slice(1);
    while (d.charAt(d.length - 1) === '.') d = d.slice(0, -1);
    if (!d || d.length > 63) return false;
    const labels = d.split('.');
    return labels.length === 1 && (/^[a-zA-Z]{2,}$/.test(labels[0]) || labels[0].startsWith('xn--'));
}

function swapToTLDScanPhases(overlay) {
    const checklist = overlay.querySelector('#scanChecklist');
    if (!checklist) return;
    const isCovert = document.body.classList.contains('covert-mode');
    const phases = [
        { delay: 0, normal: 'DNS records \u2014 Cloudflare, Google, Quad9, OpenDNS, DNS4EU', covert: 'Enumerating DNS across 5 resolvers\u2026' },
        { delay: 1200, normal: 'DNSSEC chain of trust \u2014 DS/DNSKEY validation', covert: 'Testing DNS poison resistance \u2014 DNSSEC, DANE' },
        { delay: 2500, normal: 'Nameserver fleet \u2014 reachability, ASN diversity, SOA sync', covert: 'Probing NS fleet \u2014 reachability, ASN, SOA serial' },
        { delay: 3500, normal: 'Delegation consistency \u2014 glue, TTL, DS alignment', covert: 'Auditing delegation chain \u2014 glue, DS, TTL drift' },
        { delay: 5000, normal: 'DNS server security \u2014 Nmap probes', covert: 'Nmap fingerprinting nameservers\u2026' },
        { delay: 7000, normal: 'SOA compliance \u2014 timers, zone health', covert: 'Checking SOA timers against RFC 1912' },
        { delay: 9000, normal: 'Registrar \u0026 RDAP analysis', covert: 'Mapping registrar \u0026 RDAP footprint' },
        { delay: 12000, normal: 'Classifying \u0026 Interpreting Intelligence', covert: 'Correlating attack surface\u2026' }
    ];
    checklist.textContent = '';
    for (const p of phases) {
        const div = document.createElement('div');
        div.className = 'scan-phase';
        div.dataset.delay = p.delay;
        const iconWrap = document.createElement('span');
        iconWrap.className = 'scan-icon scan-pending';
        iconWrap.appendChild(parseIcon(globalThis._icons?.spinner ?? ''));
        iconWrap.setAttribute('aria-hidden', 'true');
        const span = document.createElement('span');
        span.className = isCovert ? 'covert-show' : 'covert-hide';
        span.textContent = isCovert ? p.covert : p.normal;
        div.appendChild(iconWrap);
        div.appendChild(span);
        checklist.appendChild(div);
    }
}

function showCovertTLDToast(domain, callback) {
    const existing = document.getElementById('tldReconToast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.id = 'tldReconToast';
    toast.role = 'alert';
    toast.ariaLive = 'assertive';
    toast.className = 'tld-recon-toast';
    const toastTitle = document.createElement('div');
    toastTitle.className = 'tld-recon-toast-title';
    toastTitle.appendChild(parseIcon(globalThis._icons.globe));
    toastTitle.appendChild(document.createTextNode('Planning to hack the planet, Zero Cool?'));
    const toastBody = document.createElement('div');
    toastBody.className = 'tld-recon-toast-body';
    toastBody.textContent = 'Bare\u2011TLD recon maps registry infrastructure only \u2014 DNSSEC, NS delegation, CAA, registrar, Nmap, SVCB. No SPF/DKIM/DMARC at zone scope.';
    const toastFooter = document.createElement('div');
    toastFooter.className = 'tld-recon-toast-footer';
    toastFooter.appendChild(parseIcon(globalThis._icons.satellite));
    toast.appendChild(toastTitle);
    toast.appendChild(toastBody);
    toast.appendChild(toastFooter);
    toastFooter.appendChild(document.createTextNode('Scanning .' + domain.toUpperCase() + ' \u2014 infrastructure vectors only'));

    document.body.appendChild(toast);

    toast.addEventListener('click', function() {
        toast.remove();
    });

    setTimeout(function() {
        toast.classList.add('tld-recon-toast-dismissing');
        setTimeout(function() {
            toast.remove();
            if (callback) callback();
        }, 300);
    }, 4000);
}

function isValidDomain(domain) {
    if (!domain) return false;
    const d = stripDots(domain);
    if (d.length > 253 || d.length === 0) return false;
    const labels = d.split('.');
    if (labels.length === 1) {
        return /^[a-zA-Z]{2,}$/.test(labels[0]) || labels[0].startsWith('xn--');
    }
    for (const label of labels) {
        if (!isValidLabel(label)) return false;
    }
    const lastLabel = labels[labels.length - 1];
    if (/^\d+$/.test(lastLabel)) return false;
    if (!/[^\u0020-\u007F]/.test(d)) {
        for (const label of labels) {
            if (!/^[a-zA-Z0-9-]+$/.test(label)) return false;
        }
    }
    return true;
}

function fetchAndApplyPage(url, options, overlay, btn) {
    return fetch(url, options).then(function(resp) {
        return resp.text().then(function(html) { hideOverlayAndReset(overlay, btn); applyFetchedPage(html, resp.url); });
    });
}

function applyFetchedPage(html, respUrl) {
    const parsed = new DOMParser().parseFromString(html, 'text/html');
    document.documentElement.replaceWith(parsed.documentElement);
    globalThis.scrollTo(0, 0);
    const modeMeta = document.querySelector('meta[name="x-report-mode"]');
    const idEl = document.querySelector('[data-analysis-id]');
    const mode = modeMeta ? modeMeta.getAttribute('content') : '';
    const aid = idEl ? idEl.dataset.analysisId : '';
    if (aid && mode) {
        globalThis.history.replaceState(null, '', '/analysis/' + aid + '/view/' + mode);
    } else if (respUrl && respUrl !== globalThis.location.href) {
        globalThis.history.replaceState(null, '', respUrl);
    }
}

function resetCopyBtn(btn) {
    btn.textContent = '';
    btn.appendChild(parseIcon(globalThis._icons.copy));
    btn.classList.remove('copied');
}

function handleCopyResult(btn, success) {
    btn.textContent = '';
    btn.appendChild(parseIcon(success ? globalThis._icons.check : globalThis._icons.times));
    if (success) btn.classList.add('copied');
    setTimeout(function() { resetCopyBtn(btn); }, 1500);
}

function createCopyHandler(codeBlock, btn) {
    return function(e) {
        e.stopPropagation();
        let copyText = '';
        for (const node of codeBlock.childNodes) {
            if (node !== btn && !node.classList?.contains('copy-btn')) {
                copyText += node.textContent;
            }
        }
        copyText = copyText.trim();

        navigator.clipboard.writeText(copyText).then(
            function() { handleCopyResult(btn, true); }
        ).catch(
            function() { handleCopyResult(btn, false); }
        );
    };
}

const covertEnvClasses = ['covert-submarine', 'covert-tactical', 'covert-basement'];

function clearCovertEnv() {
    for (const c of covertEnvClasses) document.body.classList.remove(c);
}

function getCovertEnv() {
    try { return localStorage.getItem('covertEnv') ?? 'tactical'; } catch(_e) { return 'tactical'; } // NOSONAR
}

function hasAcceptedROE() {
    try { return localStorage.getItem('roeAccepted') === '1'; } catch(_e) { return false; } // NOSONAR
}

function markROEAccepted() {
    try { localStorage.setItem('roeAccepted', '1'); } catch(_e) { /* storage unavailable */ } // NOSONAR
}

let _morseAudio = null;
function _ensureMorseAudio() {
    if (!_morseAudio) {
        try {
            _morseAudio = new Audio('/static/audio/morse-hack-the-planet.m4a');
            _morseAudio.volume = 0.4;
            _morseAudio.preload = 'auto';
        } catch(_e) { /* Audio API unavailable */ } // NOSONAR
    }
    return _morseAudio;
}
function playMorseEasterEgg() {
    try {
        const a = _ensureMorseAudio();
        if (a) {
            a.currentTime = 0;
            a.play().catch(function(err) {
                console.warn('Morse audio blocked by autoplay policy:', err.message);
            });
        }
    } catch(_e) { /* intentionally empty — Audio API unavailable in some contexts */ } // NOSONAR
}

function updateEnvButtons(env) {
    for (const b of document.querySelectorAll('.covert-env-btn')) {
        b.classList.toggle('active', b.dataset.env === env);
    }
}

const covertThemeColors = { submarine: '#0a0404', tactical: '#1a0808', basement: '#140606' };
const defaultThemeColors = [];

function updateThemeColor(env) {
    const metas = document.querySelectorAll('meta[name="theme-color"]');
    if (!defaultThemeColors.length && metas.length) {
        for (const m of metas) defaultThemeColors.push(m.getAttribute('content') ?? '#0d1117');
    }
    const color = covertThemeColors[env] ?? covertThemeColors.tactical;
    for (const m of metas) m.setAttribute('content', color);
}

function restoreThemeColor() {
    const metas = document.querySelectorAll('meta[name="theme-color"]');
    let i = 0;
    for (const m of metas) { m.setAttribute('content', defaultThemeColors[i] ?? '#0d1117'); i++; }
}

function setCovertEnv(env) {
    clearCovertEnv();
    if (env && covertEnvClasses.includes('covert-' + env)) {
        document.body.classList.add('covert-' + env);
    } else {
        document.body.classList.add('covert-tactical');
        env = 'tactical';
    }
    try { localStorage.setItem('covertEnv', env); } catch(_e) { /* storage unavailable */ } // NOSONAR
    updateEnvButtons(env);
    if (document.body.classList.contains('covert-mode')) { updateThemeColor(env); }
}

function exitFullscreenSafe() {
    const activeFs = document.fullscreenElement || document.webkitFullscreenElement;
    if (!activeFs) return;
    try { if (document.exitFullscreen) { document.exitFullscreen(); } else if (document.webkitExitFullscreen) { document.webkitExitFullscreen(); } } catch(_e) { /* intentional */ } // NOSONAR
}

function setCovertMode(active) {
    if (active) {
        document.body.classList.add('covert-mode');
        setCovertEnv(getCovertEnv());
    } else {
        document.body.classList.remove('covert-mode');
        clearCovertEnv();
        restoreThemeColor();
        exitFullscreenSafe();
    }
    const toggle = document.getElementById('covertToggle');
    if (toggle) { toggle.setAttribute('aria-pressed', active ? 'true' : 'false'); }
    try { localStorage.setItem('covertMode', active ? '1' : '0'); } catch(_e) { /* storage unavailable */ } // NOSONAR
}

function saveScrollPosition() {
    try { sessionStorage.setItem('covert_scroll_y', String(globalThis.scrollY)); } catch(_e) { /* storage unavailable */ } // NOSONAR
}

function activateCovertOrSwitch() {
    const idEl = document.querySelector('[data-analysis-id]');
    const modeMeta = document.querySelector('meta[name="x-report-mode"]');
    if (idEl && modeMeta) {
        const aid = idEl.dataset.analysisId;
        const cur = (modeMeta.getAttribute('content') ?? 'E').toUpperCase();
        if (aid && (cur === 'E' || cur === 'C')) {
            const target = cur === 'E' ? 'C' : 'E';
            saveScrollPosition();
            globalThis.location.href = '/analysis/' + aid + '/view/' + target;
            return;
        }
    }
    setCovertMode(!document.body.classList.contains('covert-mode'));
}

function handleAnalyzeLinkClick(e) {
    e.preventDefault();
    const link = e.currentTarget;
    const overlay = document.getElementById('loadingOverlay');
    const loadingDomain = document.getElementById('loadingDomain');
    const url = new URL(link.href, globalThis.location.origin);
    const domain = url.searchParams.get('domain') ?? '';
    if (overlay) {
        if (loadingDomain) loadingDomain.textContent = domain;
        showOverlay(overlay);
        startStatusCycle(overlay);
    }
    document.body.classList.add('loading');
    fetchAndApplyPage(link.href, {
        headers: { 'X-Requested-With': 'fetch' },
        redirect: 'follow'
    }, overlay, null).catch(function() {
        hideOverlayAndReset(overlay, null);
        globalThis.location.href = link.href;
    });
}

function privacyWasDismissed() {
    try { if (localStorage.getItem('privacyAck') === '1') return true; } catch(_e) { /* storage unavailable */ } // NOSONAR
    try { if (document.cookie.indexOf('privacyAck=1') !== -1) return true; } catch(_e) { /* cookie unavailable */ } // NOSONAR
    return false;
}
function persistPrivacyDismiss() {
    try { localStorage.setItem('privacyAck', '1'); } catch(_e) { /* storage unavailable */ } // NOSONAR
    try { document.cookie = 'privacyAck=1;path=/;max-age=31536000;SameSite=Lax'; } catch(_e) { /* cookie unavailable */ } // NOSONAR
}
function initPrivacyBanner() {
    const banner = document.getElementById('privacyBanner');
    if (!banner) { return; }
    if (privacyWasDismissed()) { banner.remove(); return; }
    function dismissBanner(e) {
        if (e) { e.preventDefault(); e.stopPropagation(); }
        persistPrivacyDismiss();
        banner.classList.add('d-none');
        if (banner.parentNode) { banner.remove(); }
    }
    const acceptBtn = document.getElementById('privacyAccept');
    if (acceptBtn) {
        acceptBtn.onclick = dismissBanner;
    }
    banner.addEventListener('click', function(e) {
        if (e.target.closest?.('#privacyAccept')) {
            dismissBanner(e);
        }
    });
}

function initPrivacyToggle() {
    const privToggle = document.getElementById('privacyToggle');
    const privDetail = document.getElementById('privacyDetail');
    if (privToggle && privDetail) {
        function togglePrivacy() { privDetail.classList.toggle('d-none'); }
        privToggle.addEventListener('click', togglePrivacy);
        privToggle.addEventListener('keydown', function(e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); togglePrivacy(); } });
    }
}

function initGlobeMotion() {
    const rmq = globalThis.matchMedia('(prefers-reduced-motion: reduce)');
    function globeMotion() {
        const at = document.querySelector('.globe-meridians animateTransform');
        if (at) { at.setAttribute('repeatCount', rmq.matches ? '0' : 'indefinite'); }
    }
    globeMotion();
    rmq.addEventListener('change', globeMotion);
}

function initVideoFallback() {
    const csvEl = document.getElementById('caseStudyVideo');
    if (!csvEl) return;
    csvEl.addEventListener('error', function() {
        const w = csvEl.closest('.approach-video-wrapper');
        if (w) {
            const msg = document.createElement('div');
            msg.style.cssText = 'text-align:center;padding:1.5rem;color:rgba(170,178,188,0.7);font-size:0.85rem';
            msg.innerHTML = 'Video could not load. <a href="/video/forgotten-domain" style="color:rgba(88,166,255,0.85)">Watch on dedicated page</a> or <a href="/static/video/forgotten-domain.mp4" download style="color:rgba(88,166,255,0.85)">download directly</a>.';
            csvEl.replaceWith(msg);
        }
    }, true);
    const src = csvEl.querySelector('source');
    if (src) {
        src.addEventListener('error', function() {
            csvEl.dispatchEvent(new Event('error'));
        });
    }
}

function initROEModal() {
    const roeModalEl = document.getElementById('roeModal');
    let roeModal = null;
    if (roeModalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal) {
        roeModal = new bootstrap.Modal(roeModalEl);
        roeModalEl.addEventListener('show.bs.modal', function() { roeModalEl.removeAttribute('inert'); roeModalEl.removeAttribute('aria-hidden'); });
        roeModalEl.addEventListener('shown.bs.modal', function() { roeModalEl.removeAttribute('inert'); });
        roeModalEl.addEventListener('hidden.bs.modal', function() { roeModalEl.setAttribute('inert', ''); roeModalEl.setAttribute('aria-hidden', 'true'); });
    }
    let roeHandled = false;
    function handleRoeAccept(e) {
        if (roeHandled) return;
        roeHandled = true;
        setTimeout(function() { roeHandled = false; }, 400);
        if (e) { e.preventDefault(); }
        markROEAccepted();
        playMorseEasterEgg();
        if (roeModal) { roeModal.hide(); }
        activateCovertOrSwitch();
    }
    function handleRoeDecline(e) {
        if (roeHandled) return;
        roeHandled = true;
        setTimeout(function() { roeHandled = false; }, 400);
        if (e) { e.preventDefault(); }
        if (roeModal) { roeModal.hide(); }
        globalThis.location.href = 'https://youtu.be/7zUJ-dx2xXw?si=PBI0AoTgfPAellVW';
    }
    const roeAcceptBtn = document.getElementById('roeAccept');
    if (roeAcceptBtn) {
        roeAcceptBtn.addEventListener('click', handleRoeAccept);
        roeAcceptBtn.addEventListener('touchend', handleRoeAccept);
    }
    const roeDeclineBtn = document.getElementById('roeDecline');
    if (roeDeclineBtn) {
        roeDeclineBtn.addEventListener('click', handleRoeDecline);
        roeDeclineBtn.addEventListener('touchend', handleRoeDecline);
    }
    return roeModal;
}

function initCovertControls(roeModal) {
    const covertBtn = document.getElementById('covertToggle');
    if (covertBtn) {
        covertBtn.addEventListener('click', function() {
            if (document.body.classList.contains('covert-mode')) {
                const idEl = document.querySelector('[data-analysis-id]');
                if (idEl?.dataset.analysisId) {
                    const aid = idEl.dataset.analysisId;
                    setCovertMode(false);
                    const psMeta = document.querySelector('meta[name="x-public-suffix"]');
                    const exitView = (psMeta?.getAttribute('content') === '1') ? 'Z' : 'E';
                    saveScrollPosition();
                    globalThis.location.href = '/analysis/' + aid + '/view/' + exitView;
                    return;
                }
                setCovertMode(false);
                return;
            }
            if (!hasAcceptedROE() && roeModal) {
                roeModal.show();
                return;
            }
            playMorseEasterEgg();
            activateCovertOrSwitch();
        });
    }
    const covertExitHome = document.getElementById('covertExitHome');
    if (covertExitHome) {
        covertExitHome.addEventListener('click', function() {
            setCovertMode(false);
        });
    }
    initFullscreenControls();
    if (document.body.classList.contains('covert-mode')) {
        setCovertEnv(getCovertEnv());
        const initToggle = document.getElementById('covertToggle');
        if (initToggle) { initToggle.setAttribute('aria-pressed', 'true'); }
    }
}

function initFullscreenControls() {
    document.addEventListener('click', function(e) {
        const envBtn = e.target.closest('.covert-env-btn');
        if (envBtn?.dataset?.env) {
            setCovertEnv(envBtn.dataset.env);
        }
        const fsBtn = e.target.closest('.covert-fullscreen-btn');
        if (fsBtn) {
            const fsEl = document.fullscreenElement || document.webkitFullscreenElement;
            if (fsEl) {
                if (document.exitFullscreen) { document.exitFullscreen(); }
                else if (document.webkitExitFullscreen) { document.webkitExitFullscreen(); }
            } else {
                const de = document.documentElement;
                if (de.requestFullscreen) { de.requestFullscreen({ navigationUI: 'hide' }); }
                else if (de.webkitRequestFullscreen) { de.webkitRequestFullscreen(); }
            }
        }
    });
    function handleFullscreenChange() {
        const fsEl = document.fullscreenElement || document.webkitFullscreenElement;
        for (const b of document.querySelectorAll('.covert-fullscreen-btn')) {
            const ic = b.querySelector('.icon');
            if (fsEl) {
                if (ic && globalThis._icons) { ic.replaceWith(parseIcon(globalThis._icons.compress)); }
                b.setAttribute('title', 'Exit Focus Mode (Esc)');
            } else {
                if (ic && globalThis._icons) { ic.replaceWith(parseIcon(globalThis._icons.expand)); }
                b.setAttribute('title', 'Focus Mode — hide browser chrome for full scotopic immersion');
            }
        }
    }
    document.addEventListener('fullscreenchange', handleFullscreenChange);
    document.addEventListener('webkitfullscreenchange', handleFullscreenChange);
    const fsSupported = document.fullscreenEnabled || document.webkitFullscreenEnabled || false;
    if (!fsSupported) {
        for (const b of document.querySelectorAll('.covert-fullscreen-btn')) {
            b.classList.add('d-none');
        }
    }
}

function restoreScrollPosition() {
    try {
        const savedY = sessionStorage.getItem('covert_scroll_y');
        if (savedY !== null) {
            sessionStorage.removeItem('covert_scroll_y');
            const y = Number.parseInt(savedY, 10);
            if (!Number.isNaN(y) && y > 0) { globalThis.scrollTo(0, y); }
        }
    } catch(_e) { /* storage unavailable */ } // NOSONAR
}

function initSmoothScroll() {
    for (const anchor of document.querySelectorAll('a[href^="#"]')) {
        anchor.addEventListener('click', function(e) {
            if (('bsToggle' in this.dataset)) return;
            e.preventDefault();
            const href = this.getAttribute('href');
            if (!href || href === '#') return;
            try {
                const target = document.querySelector(href);
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            } catch(_e) { /* invalid selector */ } // NOSONAR
        });
    }
}

function initAlertDismissal() {
    for (const alert of document.querySelectorAll('.alert-dismissible:not(.alert-persistent)')) {
        setTimeout(function() {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            bsAlert.close();
        }, 5000);
    }

    for (const btn of document.querySelectorAll('.alert-dismissible .btn-close')) {
        btn.addEventListener('click', function() {
            const alertEl = btn.closest('.alert');
            if (alertEl) {
                try {
                    const bsAlert = bootstrap.Alert.getOrCreateInstance(alertEl);
                    bsAlert.close();
                } catch (e) {
                    console.warn('Bootstrap alert fallback:', e.message);
                    alertEl.classList.remove('show');
                    alertEl.addEventListener('transitionend', function() { alertEl.remove(); });
                    setTimeout(function() { alertEl.remove(); }, 300);
                }
            }
        });
    }
}

function initCodeBlocks() {
    for (const codeBlock of document.querySelectorAll('.code-block')) {
        codeBlock.classList.add('u-pointer');
        codeBlock.title = 'Click to copy';

        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'copy-btn';
        btn.ariaLabel = 'Copy to clipboard';
        btn.appendChild(parseIcon(globalThis._icons.copy));
        codeBlock.appendChild(btn);

        const doCopy = createCopyHandler(codeBlock, btn);
        btn.addEventListener('click', doCopy);
        codeBlock.addEventListener('click', doCopy);
    }
}

function initDomainForm() {
    const domainForm = document.getElementById('domainForm');
    const domainInput = document.getElementById('domain');
    const analyzeBtn = document.getElementById('analyzeBtn');

    if (!domainForm || !domainInput || !analyzeBtn) return;

    domainInput.addEventListener('input', function() {
        const domain = this.value.trim();
        const isValid = domain === '' || isValidDomain(domain);

        if (domain && !isValid) {
            this.classList.add('is-invalid');
            analyzeBtn.disabled = true;
        } else {
            this.classList.remove('is-invalid');
            analyzeBtn.disabled = false;
        }
    });

    if (globalThis.innerWidth >= 768 && !('ontouchstart' in globalThis)) {
        domainInput.focus();
    }

    let analysisSubmitted = false;
    domainForm.addEventListener('submit', function(e) {
        if (analysisSubmitted) return;
        e.preventDefault();
        const covertField = document.getElementById('covertField');
        if (covertField) {
            const isCovert = document.body.classList.contains('covert-mode') ? '1' : '0';
            covertField.value = isCovert;
        }
        const domain = domainInput.value.trim().toLowerCase().replace(/^\./, '');
        domainInput.value = domain;

        if (!domain) {
            domainInput.classList.add('is-invalid');
            return;
        }

        if (!isValidDomain(domain)) {
            domainInput.classList.add('is-invalid');
            return;
        }

        if (!domainForm.checkValidity()) {
            domainForm.reportValidity();
            return;
        }

        if (document.body.classList.contains('covert-mode') && isBareTopLevelDomain(domain)) {
            showCovertTLDToast(domain);
        }

        const overlay = document.getElementById('loadingOverlay');
        const loadingDomain = document.getElementById('loadingDomain');
        if (overlay) {
            if (loadingDomain) {
                loadingDomain.textContent = domain;
            }
            if (isBareTopLevelDomain(domain)) {
                swapToTLDScanPhases(overlay);
            }
            showOverlay(overlay);
            startStatusCycle(overlay);
        }
        setIconAndText(analyzeBtn, globalThis._icons?.spinner ?? null, ' Analyzing...');
        analyzeBtn.disabled = true;
        document.body.classList.add('loading');
        analysisSubmitted = true;
        const formData = new FormData(domainForm);
        fetch(domainForm.action, {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'fetch', 'Accept': 'application/json' },
            redirect: 'follow'
        }).then(function(resp) {
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            return resp.json();
        }).then(function(data) {
            if (data.token) {
                startProgressPolling(data.token, overlay, analyzeBtn);
            }
        }).catch(function() {
            hideOverlayAndReset(overlay, analyzeBtn);
            analysisSubmitted = false;
            const flash = document.createElement('div');
            flash.className = 'alert alert-danger alert-dismissible fade show mt-3';
            flash.role = 'alert';
            flash.textContent = 'Network error \u2014 please check your connection and try again.';
            const closeBtn = document.createElement('button');
            closeBtn.type = 'button';
            closeBtn.className = 'btn-close';
            closeBtn.dataset.bsDismiss = 'alert';
            flash.appendChild(closeBtn);
            domainForm.parentNode.insertBefore(flash, domainForm);
        });
    });

    domainInput.addEventListener('focus', function() {
        this.classList.remove('is-invalid');
    });
}

document.addEventListener('DOMContentLoaded', function() {
    restoreScrollPosition();
    document.addEventListener('click', function() { _ensureMorseAudio(); }, { once: true });
    initGlobeMotion();
    initVideoFallback();
    initPrivacyToggle();
    const roeModal = initROEModal();
    initCovertControls(roeModal);
    initPrivacyBanner();
    initDomainForm();

    for (const link of document.querySelectorAll('a[href^="/analyze?domain="]')) {
        if (link.id === 'reanalyzeBtn') continue;
        if (link.classList.contains('history-reanalyze-btn')) continue;
        link.addEventListener('click', handleAnalyzeLinkClick);
    }

    initAlertDismissal();
    initSmoothScroll();
    initCodeBlocks();
});

const allFixesCollapse = document.getElementById('allFixesCollapse');
if (allFixesCollapse) {
    const toggleBtn = document.querySelector('[data-bs-target="#allFixesCollapse"]');
    if (toggleBtn) {
        const originalNodes = Array.from(toggleBtn.childNodes).map(function(node) {
            return node.cloneNode(true);
        });
        allFixesCollapse.addEventListener('shown.bs.collapse', function() {
            setIconAndText(toggleBtn, globalThis._icons?.chevronUp ?? null, ' Show fewer');
        });
        allFixesCollapse.addEventListener('hidden.bs.collapse', function() {
            toggleBtn.textContent = '';
            for (const node of originalNodes) {
                toggleBtn.appendChild(node.cloneNode(true));
            }
        });
    }
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function createHistoryRow(ch) {
    let typeColor = 'secondary';
    if (ch.record_type === 'A' || ch.record_type === 'AAAA') {
        typeColor = 'primary';
    } else if (ch.record_type === 'MX') {
        typeColor = 'success';
    } else if (ch.record_type === 'NS') {
        typeColor = 'info';
    }
    const tr = document.createElement('tr');

    const tdDate = document.createElement('td');
    const codeDate = document.createElement('code');
    codeDate.className = 'text-muted u-fs-080em';
    codeDate.textContent = ch.date || '';
    tdDate.appendChild(codeDate);

    const tdType = document.createElement('td');
    const badgeType = document.createElement('span');
    badgeType.className = 'badge bg-' + typeColor;
    badgeType.textContent = ch.record_type || '';
    tdType.appendChild(badgeType);

    const tdAction = document.createElement('td');
    const actionSpan = document.createElement('span');
    if (ch.action === 'added') {
        actionSpan.className = 'text-success';
        setIconAndText(actionSpan, globalThis._icons?.plusCircle ?? null, ' Added');
    } else {
        actionSpan.className = 'text-danger';
        setIconAndText(actionSpan, globalThis._icons?.minusCircle ?? null, ' Removed');
    }
    tdAction.appendChild(actionSpan);

    const tdValue = document.createElement('td');
    const codeValue = document.createElement('code');
    codeValue.className = 'u-fs-085em';
    codeValue.textContent = ch.value || '';
    tdValue.appendChild(codeValue);

    const tdOrg = document.createElement('td');
    const spanOrg = document.createElement('span');
    spanOrg.className = 'text-muted';
    spanOrg.textContent = ch.org || '\u2014';
    tdOrg.appendChild(spanOrg);

    const tdDesc = document.createElement('td');
    const spanDesc = document.createElement('span');
    spanDesc.className = 'text-muted u-fs-085em';
    spanDesc.textContent = ch.description || '';
    tdDesc.appendChild(spanDesc);

    tr.appendChild(tdDate);
    tr.appendChild(tdType);
    tr.appendChild(tdAction);
    tr.appendChild(tdValue);
    tr.appendChild(tdOrg);
    tr.appendChild(tdDesc);
    return tr;
}

function loadDNSHistory(domain) {
    const btn = document.getElementById('dns-history-btn');
    if (!btn) return;
    btn.disabled = true;
    setIconAndText(btn, globalThis._icons?.spinner ?? null, ' Loading history\u2026');

    fetch('/api/dns-history?domain=' + encodeURIComponent(domain))
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (!data || data.status === 'unavailable' || data.status === 'error' || !data.available) {
                btn.closest('.dns-history-load-wrapper').classList.add('d-none');
                return;
            }
            const section = document.getElementById('dns-history-section');
            const body = document.getElementById('dns-history-body');
            const source = document.getElementById('dns-history-source');
            if (!section || !body) return;

            source.textContent = 'Source: ' + (data.source || 'SecurityTrails');

            const changes = data.changes || [];
            body.textContent = '';
            if (changes.length === 0) {
                const p = document.createElement('p');
                p.className = 'text-muted mb-0';
                setIconAndText(p, globalThis._icons?.checkCircle ?? null, ' No DNS record changes detected in available history. A, AAAA, MX, and NS records for this domain have remained stable.');
                body.appendChild(p);
            } else {
                const wrap = document.createElement('div');
                wrap.className = 'table-responsive';
                const table = document.createElement('table');
                table.className = 'table table-sm table-striped mb-0';
                const thead = document.createElement('thead');
                const headRow = document.createElement('tr');
                const headers = [
                    {text: 'Date', cls: 'u-w-80px'}, {text: 'Type', cls: 'u-w-60px'},
                    {text: 'Action', cls: 'u-w-70px'}, {text: 'Value'}, {text: 'Organization'}, {text: 'Timeline'}
                ];
                for (const h of headers) {
                    const th = document.createElement('th');
                    if (h.cls) th.className = h.cls;
                    th.textContent = h.text;
                    headRow.appendChild(th);
                }
                thead.appendChild(headRow);
                table.appendChild(thead);
                const tbody = document.createElement('tbody');
                for (const ch of changes) {
                    tbody.appendChild(createHistoryRow(ch));
                }
                table.appendChild(tbody);
                wrap.appendChild(table);
                body.appendChild(wrap);
            }

            btn.closest('.dns-history-load-wrapper').classList.add('d-none');
            section.classList.remove('d-none');
        })
        .catch(function() {
            btn.closest('.dns-history-load-wrapper').classList.add('d-none');
        });
}

globalThis.showOverlay = showOverlay;
globalThis.startStatusCycle = startStatusCycle;
globalThis.escapeHtml = escapeHtml;
globalThis.loadDNSHistory = loadDNSHistory;

})();
