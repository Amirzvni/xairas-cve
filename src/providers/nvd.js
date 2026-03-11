import { loadConfig } from '../lib/config.js';

const NVD_CVE_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const NVD_CPE_API = 'https://services.nvd.nist.gov/rest/json/cpes/2.0';

let lastRequestTime = 0;

function getRateDelay() {
    const config = loadConfig();
    return config.nvd?.apiKey ? 600 : 6000;
}

async function rateLimitedFetch(url, headers = {}) {
    const delay = getRateDelay();
    const now = Date.now();
    const elapsed = now - lastRequestTime;

    if (elapsed < delay) {
        await new Promise((resolve) => setTimeout(resolve, delay - elapsed));
    }

    lastRequestTime = Date.now();

    const config = loadConfig();
    if (config.nvd?.apiKey) {
        headers['apiKey'] = config.nvd.apiKey;
    }

    const response = await fetch(url, { headers });

    if (response.status === 403) {
        throw new Error('NVD API rate limit exceeded. Consider adding an API key via: xairas-cve config set --nvd-api-key <key>');
    }

    if (!response.ok) {
        throw new Error(`NVD API error: ${response.status} ${response.statusText}`);
    }

    return response.json();
}

/**
 * Search CPE dictionary to discover vendor:product for a technology.
 * Returns unique vendor:product pairs.
 */
export async function searchCPE(keyword) {
    const params = new URLSearchParams({
        keywordSearch: keyword,
        resultsPerPage: '50',
    });

    const data = await rateLimitedFetch(`${NVD_CPE_API}?${params}`);

    // Extract unique vendor:product pairs
    const seen = new Map();

    for (const p of data.products || []) {
        const parts = p.cpe.cpeName.split(':');
        const vendor = parts[3];
        const product = parts[4];
        const key = `${vendor}:${product}`;

        if (!seen.has(key)) {
            seen.set(key, {
                vendor,
                product,
                title: p.cpe.titles?.[0]?.title || key,
            });
        }
    }

    return Array.from(seen.values());
}

/**
 * Query CVEs using exact CPE vendor:product match.
 */
export async function queryNVD(tech) {
    const { name, version, cpeVendor, cpeProduct } = tech;

    if (!cpeVendor || !cpeProduct) {
        throw new Error(`No CPE mapping for "${name}". Re-add with: xairas-cve stack add --name ${name} --category ${tech.category}`);
    }

    // Build CPE match string: any version of this vendor:product
    const params = new URLSearchParams({
        keywordSearch: `${cpeVendor} ${cpeProduct}`,
        keywordExactMatch: '',
        resultsPerPage: '100',
    });

    const data = await rateLimitedFetch(`${NVD_CVE_API}?${params}`);

    const vulns = [];

    for (const item of data.vulnerabilities || []) {
        const cve = item.cve;

        // Filter: only include CVEs that affect our version
        if (!isVersionAffected(cve, cpeVendor, cpeProduct, version)) continue;

        const severity = extractCvssSeverity(cve);

        vulns.push({
            id: cve.id,
            aliases: [],
            summary: extractDescription(cve),
            details: '',
            severity,
            published: cve.published || null,
            modified: cve.lastModified || null,
            references: (cve.references || []).map((r) => r.url),
            source: 'nvd',
            tech: `${name}@${version}`,
            category: tech.category,
        });
    }

    return vulns;
}

function isVersionAffected(cve, cpeVendor, cpeProduct, techVersion) {
    const configs = cve.configurations || [];

    for (const config of configs) {
        const nodes = config.nodes || [];
        for (const node of nodes) {
            const matches = node.cpeMatch || [];
            for (const match of matches) {
                if (!match.vulnerable) continue;

                const cpe = match.criteria?.toLowerCase() || '';
                const parts = cpe.split(':');
                const matchVendor = parts[3];
                const matchProduct = parts[4];

                // Only look at our exact vendor:product
                if (matchVendor !== cpeVendor.toLowerCase()) continue;
                if (matchProduct !== cpeProduct.toLowerCase()) continue;

                const versionStart = match.versionStartIncluding || match.versionStartExcluding;
                const versionEnd = match.versionEndIncluding || match.versionEndExcluding;

                if (!versionStart && !versionEnd) {
                    const cpeVersion = parts[5] || '*';
                    if (cpeVersion === '*' || cpeVersion === '-') return true;
                    if (cpeVersion === techVersion.toLowerCase()) return true;
                    continue;
                }

                if (isInVersionRange(techVersion, match)) return true;
            }
        }
    }

    return false;
}

function isInVersionRange(version, match) {
    const v = normalizeVersion(version);

    if (match.versionStartIncluding) {
        if (compareVersions(v, normalizeVersion(match.versionStartIncluding)) < 0) return false;
    }
    if (match.versionStartExcluding) {
        if (compareVersions(v, normalizeVersion(match.versionStartExcluding)) <= 0) return false;
    }
    if (match.versionEndIncluding) {
        if (compareVersions(v, normalizeVersion(match.versionEndIncluding)) > 0) return false;
    }
    if (match.versionEndExcluding) {
        if (compareVersions(v, normalizeVersion(match.versionEndExcluding)) >= 0) return false;
    }

    return true;
}

function normalizeVersion(v) {
    return v.split('.').map((part) => {
        const num = parseInt(part, 10);
        return isNaN(num) ? part : num;
    });
}

function compareVersions(a, b) {
    const len = Math.max(a.length, b.length);
    for (let i = 0; i < len; i++) {
        const av = a[i] ?? 0;
        const bv = b[i] ?? 0;

        if (typeof av === 'number' && typeof bv === 'number') {
            if (av < bv) return -1;
            if (av > bv) return 1;
        } else {
            const sa = String(av);
            const sb = String(bv);
            if (sa < sb) return -1;
            if (sa > sb) return 1;
        }
    }
    return 0;
}

function extractCvssSeverity(cve) {
    const metrics = cve.metrics || {};

    const v31 = metrics.cvssMetricV31?.[0]?.cvssData;
    if (v31) return { label: v31.baseSeverity, score: v31.baseScore };

    const v30 = metrics.cvssMetricV30?.[0]?.cvssData;
    if (v30) return { label: v30.baseSeverity, score: v30.baseScore };

    const v2 = metrics.cvssMetricV2?.[0]?.cvssData;
    if (v2) return { label: v2.baseSeverity || 'UNKNOWN', score: v2.baseScore };

    return { label: 'UNKNOWN', score: null };
}

function extractDescription(cve) {
    const descriptions = cve.descriptions || [];
    const en = descriptions.find((d) => d.lang === 'en');
    return en?.value || descriptions[0]?.value || '';
}

export async function batchQueryNVD(techs) {
    const results = [];

    for (const tech of techs) {
        if (tech.source !== 'nvd') continue;

        try {
            const vulns = await queryNVD(tech);
            results.push({ tech, vulns, error: null });
        } catch (err) {
            results.push({ tech, vulns: [], error: err.message });
        }
    }

    return results;
}