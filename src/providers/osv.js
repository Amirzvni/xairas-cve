import chalk from 'chalk';

const OSV_API = 'https://api.osv.dev/v1';

export async function queryOSV(tech) {
    const { name, version, ecosystem } = tech;

    const body = {
        package: {
            name,
            ecosystem,
        },
    };

    // Only include version if provided — omitting it returns ALL vulns for the package
    if (version) {
        body.version = version;
    }

    const response = await fetch(`${OSV_API}/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });

    if (!response.ok) {
        throw new Error(`OSV API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    const vulns = data.vulns || [];

    return vulns.map((vuln) => ({
        id: vuln.id,
        aliases: vuln.aliases || [],
        summary: vuln.summary || '',
        details: vuln.details || '',
        severity: extractSeverity(vuln),
        published: vuln.published || null,
        modified: vuln.modified || null,
        references: (vuln.references || []).map((r) => r.url),
        source: 'osv',
        tech: `${name}@${version}`,
        category: tech.category,
    }));
}

function extractSeverity(vuln) {
    // Try database_specific severity first
    if (vuln.database_specific?.severity) {
        return { label: vuln.database_specific.severity, score: null };
    }

    // Try CVSS from severity array
    if (vuln.severity && vuln.severity.length > 0) {
        for (const s of vuln.severity) {
            if (s.type === 'CVSS_V3') {
                const score = parseCvssScore(s.score);
                return { label: cvssLabel(score), score };
            }
        }
    }

    return { label: 'UNKNOWN', score: null };
}

function parseCvssScore(vector) {
    if (!vector) return null;
    // CVSS vector format: CVSS:3.1/AV:N/AC:L/... — we need to compute the score
    // But some sources include the score directly in the vector or as a separate field
    // For now, return null and let the display handle it
    // The NVD enrichment will provide the actual numeric score
    return null;
}

function cvssLabel(score) {
    if (score === null) return 'UNKNOWN';
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score > 0) return 'LOW';
    return 'NONE';
}

export async function batchQueryOSV(techs) {
    const results = [];

    for (const tech of techs) {
        if (tech.source !== 'osv') continue;

        try {
            const vulns = await queryOSV(tech);
            results.push({ tech, vulns, error: null });
        } catch (err) {
            results.push({ tech, vulns: [], error: err.message });
        }
    }

    return results;
}