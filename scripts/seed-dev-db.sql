-- seed-dev-db.sql — Populates the development database with realistic test data.
-- Safe to run multiple times (idempotent via ON CONFLICT / WHERE NOT EXISTS).
-- Contains NO production data, NO PII, NO secrets.
-- All domains use real public domains or RFC 2606 reserved names.
--
-- Usage:  psql "$DATABASE_URL" -f scripts/seed-dev-db.sql

BEGIN;

-- ============================================================
-- domain_analyses — 12 representative scans
-- ============================================================
INSERT INTO domain_analyses (
    id, domain, ascii_domain, spf_status, dmarc_status, dmarc_policy, dkim_status,
    analysis_success, analysis_duration, created_at, updated_at,
    full_results, posture_hash, private, has_user_selectors, scan_flag, scan_source
)
VALUES
-- NOTE: All posture_hash values are identical because the seed full_results JSON
-- uses simplified keys (spf, dmarc, dkim) rather than the analysis-section keys
-- (spf_analysis, dmarc_analysis, dkim_analysis) that CanonicalPostureHash extracts.
-- The hash is the real SHA-3-512 of empty canonical fields — honest, not fake.
-- Real scans produce full_results with proper analysis sections and unique hashes.

-- 1. Strong posture — all pass
(1, 'cloudflare.com', 'cloudflare.com', 'pass', 'pass', 'reject', 'pass',
 true, 42.3, NOW() - INTERVAL '6 hours', NOW() - INTERVAL '6 hours',
 '{"_tool_version":"26.28.50","domain":"cloudflare.com","spf":{"status":"pass","record":"v=spf1 include:_spf.google.com include:spf1.mcsv.net include:spf.mandrillapp.com ~all","lookup_count":4},"dmarc":{"status":"pass","policy":"reject","pct":100,"has_rua":true},"dkim":{"status":"pass","selectors_found":["google","mandrill"]},"dnssec":{"signed":true,"valid":true},"mta_sts":{"mode":"enforce"},"caa":{"present":true}}'::json,
 '21e860988de57da068fee0a690bad2c613250b738cca5c3230d93a9dd882d20d5663765d26c2becc21d251fc7ed0a77db491a9b1bd03fe59dcc5dfff88fb5910', false, false, false, 'web'),

-- 2. Weak posture — SPF fail, no DMARC
(2, 'evilhacker.com', 'evilhacker.com', 'fail', 'fail', 'none', 'pass',
 true, 60.0, NOW() - INTERVAL '5 hours', NOW() - INTERVAL '5 hours',
 '{"_tool_version":"26.28.50","domain":"evilhacker.com","spf":{"status":"fail","record":"","lookup_count":0},"dmarc":{"status":"fail","policy":"none","pct":0,"has_rua":false},"dkim":{"status":"pass","selectors_found":["default"]},"dnssec":{"signed":false,"valid":false},"mta_sts":{"mode":"none"},"caa":{"present":false}}'::json,
 '21e860988de57da068fee0a690bad2c613250b738cca5c3230d93a9dd882d20d5663765d26c2becc21d251fc7ed0a77db491a9b1bd03fe59dcc5dfff88fb5910', false, false, false, 'web'),

-- 3. Mixed posture — SPF pass, DMARC quarantine
(3, 'github.com', 'github.com', 'pass', 'pass', 'quarantine', 'pass',
 true, 38.7, NOW() - INTERVAL '4 hours', NOW() - INTERVAL '4 hours',
 '{"_tool_version":"26.28.50","domain":"github.com","spf":{"status":"pass","record":"v=spf1 ip4:192.30.252.0/22 include:_netblocks.google.com include:servers.mcsv.net ~all","lookup_count":5},"dmarc":{"status":"pass","policy":"quarantine","pct":100,"has_rua":true},"dkim":{"status":"pass","selectors_found":["google","pf2014"]},"dnssec":{"signed":false,"valid":false},"mta_sts":{"mode":"enforce"},"caa":{"present":true}}'::json,
 '21e860988de57da068fee0a690bad2c613250b738cca5c3230d93a9dd882d20d5663765d26c2becc21d251fc7ed0a77db491a9b1bd03fe59dcc5dfff88fb5910', false, false, false, 'web'),

-- 4. International domain (IDN)
(4, 'kisa.org.cy', 'kisa.org.cy', 'pass', 'fail', 'none', 'pass',
 true, 54.3, NOW() - INTERVAL '3 hours 30 minutes', NOW() - INTERVAL '3 hours 30 minutes',
 '{"_tool_version":"26.28.50","domain":"kisa.org.cy","spf":{"status":"pass","record":"v=spf1 include:_spf.google.com ~all","lookup_count":2},"dmarc":{"status":"fail","policy":"none","pct":0,"has_rua":false},"dkim":{"status":"pass","selectors_found":["google"]},"dnssec":{"signed":false,"valid":false},"mta_sts":{"mode":"none"},"caa":{"present":false}}'::json,
 '21e860988de57da068fee0a690bad2c613250b738cca5c3230d93a9dd882d20d5663765d26c2becc21d251fc7ed0a77db491a9b1bd03fe59dcc5dfff88fb5910', false, false, false, 'web'),

-- 5. Strong enterprise
(5, 'google.com', 'google.com', 'pass', 'pass', 'reject', 'pass',
 true, 31.2, NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 hours',
 '{"_tool_version":"26.28.50","domain":"google.com","spf":{"status":"pass","record":"v=spf1 include:_spf.google.com ~all","lookup_count":3},"dmarc":{"status":"pass","policy":"reject","pct":100,"has_rua":true},"dkim":{"status":"pass","selectors_found":["20230601"]},"dnssec":{"signed":false,"valid":false},"mta_sts":{"mode":"enforce"},"caa":{"present":true}}'::json,
 '21e860988de57da068fee0a690bad2c613250b738cca5c3230d93a9dd882d20d5663765d26c2becc21d251fc7ed0a77db491a9b1bd03fe59dcc5dfff88fb5910', false, false, false, 'web'),

-- 6. No-mail domain
(6, 'parked-domain.example', 'parked-domain.example', 'pass', 'pass', 'reject', 'none',
 true, 12.8, NOW() - INTERVAL '2 hours 30 minutes', NOW() - INTERVAL '2 hours 30 minutes',
 '{"_tool_version":"26.28.50","domain":"parked-domain.example","spf":{"status":"pass","record":"v=spf1 -all","lookup_count":0},"dmarc":{"status":"pass","policy":"reject","pct":100,"has_rua":false},"dkim":{"status":"none","selectors_found":[]},"dnssec":{"signed":false,"valid":false},"mta_sts":{"mode":"none"},"caa":{"present":false},"null_mx":true}'::json,
 '21e860988de57da068fee0a690bad2c613250b738cca5c3230d93a9dd882d20d5663765d26c2becc21d251fc7ed0a77db491a9b1bd03fe59dcc5dfff88fb5910', false, false, false, 'web'),

-- 7. SPF too many lookups
(7, 'markphd.me', 'markphd.me', 'fail', 'fail', 'none', 'pass',
 true, 60.0, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '2 hours',
 '{"_tool_version":"26.28.50","domain":"markphd.me","spf":{"status":"fail","record":"v=spf1 include:_spf.google.com include:spf.protection.outlook.com include:sendgrid.net include:mail.zendesk.com include:spf.freshdesk.com include:servers.mcsv.net ~all","lookup_count":12},"dmarc":{"status":"fail","policy":"none","pct":0,"has_rua":false},"dkim":{"status":"pass","selectors_found":["google"]},"dnssec":{"signed":false,"valid":false},"mta_sts":{"mode":"none"},"caa":{"present":false}}'::json,
 '21e860988de57da068fee0a690bad2c613250b738cca5c3230d93a9dd882d20d5663765d26c2becc21d251fc7ed0a77db491a9b1bd03fe59dcc5dfff88fb5910', false, false, false, 'web'),

-- 8. Government domain — strong
(8, 'cisa.gov', 'cisa.gov', 'pass', 'pass', 'reject', 'pass',
 true, 44.1, NOW() - INTERVAL '1 hour 30 minutes', NOW() - INTERVAL '1 hour 30 minutes',
 '{"_tool_version":"26.28.50","domain":"cisa.gov","spf":{"status":"pass","record":"v=spf1 include:_spf.google.com include:amazonses.com ~all","lookup_count":4},"dmarc":{"status":"pass","policy":"reject","pct":100,"has_rua":true},"dkim":{"status":"pass","selectors_found":["google","selector1"]},"dnssec":{"signed":true,"valid":true},"mta_sts":{"mode":"enforce"},"caa":{"present":true}}'::json,
 '21e860988de57da068fee0a690bad2c613250b738cca5c3230d93a9dd882d20d5663765d26c2becc21d251fc7ed0a77db491a9b1bd03fe59dcc5dfff88fb5910', false, false, false, 'web'),

-- 9. Weak — all fail
(9, 'purpleflock.com', 'purpleflock.com', 'fail', 'fail', 'none', 'fail',
 true, 58.5, NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 hour',
 '{"_tool_version":"26.28.50","domain":"purpleflock.com","spf":{"status":"fail","record":"","lookup_count":0},"dmarc":{"status":"fail","policy":"none","pct":0,"has_rua":false},"dkim":{"status":"fail","selectors_found":[]},"dnssec":{"signed":false,"valid":false},"mta_sts":{"mode":"none"},"caa":{"present":false}}'::json,
 '21e860988de57da068fee0a690bad2c613250b738cca5c3230d93a9dd882d20d5663765d26c2becc21d251fc7ed0a77db491a9b1bd03fe59dcc5dfff88fb5910', false, false, false, 'web'),

-- 10. Microsoft-hosted
(10, 'microsoft.com', 'microsoft.com', 'pass', 'pass', 'reject', 'pass',
 true, 35.9, NOW() - INTERVAL '45 minutes', NOW() - INTERVAL '45 minutes',
 '{"_tool_version":"26.28.50","domain":"microsoft.com","spf":{"status":"pass","record":"v=spf1 include:_spf-a.microsoft.com include:_spf-b.microsoft.com include:_spf-c.microsoft.com ~all","lookup_count":6},"dmarc":{"status":"pass","policy":"reject","pct":100,"has_rua":true},"dkim":{"status":"pass","selectors_found":["selector1","selector2"]},"dnssec":{"signed":false,"valid":false},"mta_sts":{"mode":"enforce"},"caa":{"present":true}}'::json,
 '21e860988de57da068fee0a690bad2c613250b738cca5c3230d93a9dd882d20d5663765d26c2becc21d251fc7ed0a77db491a9b1bd03fe59dcc5dfff88fb5910', false, false, false, 'web'),

-- 11. Long domain name (layout stress test)
(11, 'subdomain.really-long-organization-name.co.uk', 'subdomain.really-long-organization-name.co.uk', 'pass', 'pass', 'quarantine', 'none',
 true, 47.2, NOW() - INTERVAL '30 minutes', NOW() - INTERVAL '30 minutes',
 '{"_tool_version":"26.28.50","domain":"subdomain.really-long-organization-name.co.uk","spf":{"status":"pass","record":"v=spf1 include:_spf.google.com ~all","lookup_count":2},"dmarc":{"status":"pass","policy":"quarantine","pct":50,"has_rua":true},"dkim":{"status":"none","selectors_found":[]},"dnssec":{"signed":false,"valid":false},"mta_sts":{"mode":"testing"},"caa":{"present":false}}'::json,
 '21e860988de57da068fee0a690bad2c613250b738cca5c3230d93a9dd882d20d5663765d26c2becc21d251fc7ed0a77db491a9b1bd03fe59dcc5dfff88fb5910', false, false, false, 'web'),

-- 12. Recent scan — DMARC p=none with pct
(12, 'stanford.edu', 'stanford.edu', 'pass', 'pass', 'none', 'pass',
 true, 39.4, NOW() - INTERVAL '10 minutes', NOW() - INTERVAL '10 minutes',
 '{"_tool_version":"26.28.50","domain":"stanford.edu","spf":{"status":"pass","record":"v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all","lookup_count":5},"dmarc":{"status":"pass","policy":"none","pct":100,"has_rua":true},"dkim":{"status":"pass","selectors_found":["google"]},"dnssec":{"signed":false,"valid":false},"mta_sts":{"mode":"none"},"caa":{"present":true}}'::json,
 '21e860988de57da068fee0a690bad2c613250b738cca5c3230d93a9dd882d20d5663765d26c2becc21d251fc7ed0a77db491a9b1bd03fe59dcc5dfff88fb5910', false, false, false, 'web')

ON CONFLICT (id) DO NOTHING;

SELECT setval('domain_analyses_id_seq', GREATEST((SELECT MAX(id) FROM domain_analyses), 12));

-- ============================================================
-- analysis_stats — 7 days of realistic stats
-- ============================================================
INSERT INTO analysis_stats (date, total_analyses, successful_analyses, failed_analyses, unique_domains, avg_analysis_time, created_at, updated_at)
VALUES
    (CURRENT_DATE - 6, 18, 16, 2, 14, 41.2, NOW(), NOW()),
    (CURRENT_DATE - 5, 24, 22, 2, 19, 38.7, NOW(), NOW()),
    (CURRENT_DATE - 4, 31, 29, 2, 25, 44.1, NOW(), NOW()),
    (CURRENT_DATE - 3, 15, 14, 1, 12, 36.9, NOW(), NOW()),
    (CURRENT_DATE - 2, 22, 20, 2, 17, 42.5, NOW(), NOW()),
    (CURRENT_DATE - 1, 27, 25, 2, 21, 39.8, NOW(), NOW()),
    (CURRENT_DATE,     12, 12, 0, 10, 43.1, NOW(), NOW())
ON CONFLICT (date) DO NOTHING;

-- ============================================================
-- site_analytics — 7 days of page view data
-- ============================================================
INSERT INTO site_analytics (date, pageviews, unique_visitors, analyses_run, unique_domains_analyzed, referrer_sources, top_pages, created_at, updated_at)
VALUES
    (CURRENT_DATE - 6, 142, 68, 18, 14, '{"direct":45,"google":18,"github":5}', '{"/":60,"/history":30,"/sources":15}', NOW(), NOW()),
    (CURRENT_DATE - 5, 198, 91, 24, 19, '{"direct":52,"google":28,"twitter":11}', '{"/":85,"/history":42,"/stats":20}', NOW(), NOW()),
    (CURRENT_DATE - 4, 231, 112, 31, 25, '{"direct":61,"google":35,"linkedin":8}', '{"/":95,"/history":55,"/approach":18}', NOW(), NOW()),
    (CURRENT_DATE - 3, 105, 48, 15, 12, '{"direct":30,"google":12,"github":6}', '{"/":42,"/history":25,"/sources":12}', NOW(), NOW()),
    (CURRENT_DATE - 2, 176, 82, 22, 17, '{"direct":48,"google":22,"twitter":12}', '{"/":72,"/history":38,"/stats":16}', NOW(), NOW()),
    (CURRENT_DATE - 1, 210, 97, 27, 21, '{"direct":55,"google":30,"github":12}', '{"/":88,"/history":48,"/approach":22}', NOW(), NOW()),
    (CURRENT_DATE,     89, 41, 12, 10, '{"direct":25,"google":10,"linkedin":6}', '{"/":38,"/history":20,"/sources":9}', NOW(), NOW())
ON CONFLICT (date) DO NOTHING;

-- ============================================================
-- ice_test_runs + ice_results — one representative ICE run
-- ============================================================
INSERT INTO ice_test_runs (id, app_version, git_commit, run_type, total_cases, total_passed, total_failed, duration_ms, created_at)
VALUES (1, '26.28.50', 'dev', 'ci', 186, 184, 2, 4200, NOW() - INTERVAL '1 hour')
ON CONFLICT (id) DO NOTHING;

SELECT setval('ice_test_runs_id_seq', GREATEST((SELECT MAX(id) FROM ice_test_runs), 1));

INSERT INTO ice_results (run_id, protocol, layer, case_id, case_name, passed, expected, actual, rfc_section, created_at)
SELECT 1, v.protocol, v.layer, v.case_id, v.case_name, v.passed, v.expected, v.actual, v.rfc_section, NOW() - INTERVAL '1 hour'
FROM (VALUES
    ('SPF',    'collection', 'spf_collect_01', 'SPF TXT lookup',            true,  'v=spf1 record found', 'v=spf1 record found', 'RFC 7208 §4.4'),
    ('SPF',    'analysis',   'spf_analyze_01', 'SPF lookup count ≤10',      true,  '≤10 lookups',         '4 lookups',           'RFC 7208 §4.6.4'),
    ('SPF',    'analysis',   'spf_analyze_02', 'SPF permissiveness check',  true,  '-all or ~all',        '~all',                'RFC 7208 §5'),
    ('DMARC',  'collection', 'dmarc_collect_01','DMARC TXT lookup',         true,  'v=DMARC1 found',      'v=DMARC1 found',      'RFC 7489 §6.1'),
    ('DMARC',  'analysis',   'dmarc_analyze_01','DMARC policy strength',    true,  'reject or quarantine', 'reject',              'RFC 7489 §6.3'),
    ('DKIM',   'collection', 'dkim_collect_01', 'DKIM selector discovery',  true,  '≥1 selector found',   '2 selectors found',   'RFC 6376 §3.6.1'),
    ('DKIM',   'analysis',   'dkim_analyze_01', 'DKIM key length ≥2048',    true,  '≥2048-bit key',       '2048-bit key',        'RFC 8301 §3'),
    ('DNSSEC', 'collection', 'dnssec_collect_01','DNSSEC DS record lookup', true,  'DS record present',   'DS record present',   'RFC 4035 §5'),
    ('DANE',   'collection', 'dane_collect_01', 'TLSA record lookup',       true,  'TLSA record present', 'TLSA record present', 'RFC 6698 §2.1'),
    ('MTA-STS','collection', 'mtasts_collect_01','MTA-STS TXT lookup',      true,  'v=STSv1 found',       'v=STSv1 found',       'RFC 8461 §3.1'),
    ('BIMI',   'collection', 'bimi_collect_01', 'BIMI TXT lookup',          false, 'v=BIMI1 found',       'No BIMI record',      'RFC 9495 §3.2'),
    ('CAA',    'collection', 'caa_collect_01',  'CAA record lookup',        true,  'CAA record present',  'CAA record present',  'RFC 8659 §4')
) AS v(protocol, layer, case_id, case_name, passed, expected, actual, rfc_section)
WHERE NOT EXISTS (SELECT 1 FROM ice_results WHERE run_id = 1 AND case_id = v.case_id);

-- ============================================================
-- ice_maturity — protocol maturity levels
-- Starts at development with zero runs. Real maturity data
-- accumulates organically as the ICAE test suite runs during
-- domain analyses. Do NOT seed fake maturity progression.
-- ============================================================
INSERT INTO ice_maturity (protocol, layer, maturity, total_runs, consecutive_passes, last_evaluated_at, updated_at)
VALUES
    ('SPF',     'collection', 'development', 0, 0, NOW(), NOW()),
    ('SPF',     'analysis',   'development', 0, 0, NOW(), NOW()),
    ('DMARC',   'collection', 'development', 0, 0, NOW(), NOW()),
    ('DMARC',   'analysis',   'development', 0, 0, NOW(), NOW()),
    ('DKIM',    'collection', 'development', 0, 0, NOW(), NOW()),
    ('DKIM',    'analysis',   'development', 0, 0, NOW(), NOW()),
    ('DNSSEC',  'collection', 'development', 0, 0, NOW(), NOW()),
    ('DNSSEC',  'analysis',   'development', 0, 0, NOW(), NOW()),
    ('DANE',    'collection', 'development', 0, 0, NOW(), NOW()),
    ('DANE',    'analysis',   'development', 0, 0, NOW(), NOW()),
    ('MTA-STS', 'collection', 'development', 0, 0, NOW(), NOW()),
    ('MTA-STS', 'analysis',   'development', 0, 0, NOW(), NOW()),
    ('BIMI',    'collection', 'development', 0, 0, NOW(), NOW()),
    ('BIMI',    'analysis',   'development', 0, 0, NOW(), NOW()),
    ('CAA',     'collection', 'development', 0, 0, NOW(), NOW()),
    ('CAA',     'analysis',   'development', 0, 0, NOW(), NOW()),
    ('TLS-RPT', 'collection', 'development', 0, 0, NOW(), NOW()),
    ('TLS-RPT', 'analysis',   'development', 0, 0, NOW(), NOW())
ON CONFLICT (protocol, layer) DO NOTHING;

COMMIT;
