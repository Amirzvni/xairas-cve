import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { loadConfig } from '../lib/config.js';
import { isAlreadyNotified, markBatchNotified, recordScan } from '../lib/db.js';
import { queryOSV } from '../providers/osv.js';
import { queryNVD } from '../providers/nvd.js';
import { sendTelegramAlert } from '../notifiers/telegram.js';

export async function runScan(options = {}) {
    const { silent = false } = options;
    const config = loadConfig();

    if (config.stack.length === 0) {
        if (!silent) console.log(chalk.yellow('\n  ⚠ No technologies in stack. Use xairas-cve stack add first.\n'));
        return { total: 0, newVulns: [] };
    }

    const allVulns = [];
    const errors = [];

    for (const tech of config.stack) {
        const label = `${tech.name}@${tech.version}`;
        const spinner = silent ? null : ora(`  Scanning ${label} [${tech.source}]`).start();

        try {
            let vulns;
            if (tech.source === 'osv') {
                vulns = await queryOSV(tech);
            } else if (tech.source === 'nvd') {
                vulns = await queryNVD(tech);
            } else {
                if (spinner) spinner.warn(`  ${label} — unknown source "${tech.source}"`);
                continue;
            }

            if (spinner) spinner.succeed(`  ${label} — ${vulns.length} vulnerabilit${vulns.length === 1 ? 'y' : 'ies'}`);
            allVulns.push(...vulns);
        } catch (err) {
            if (spinner) spinner.fail(`  ${label} — ${err.message}`);
            errors.push({ tech: label, error: err.message });
        }
    }

    // Filter by minimum CVSS
    const minCvss = config.severity?.minCvss || 0;
    const filtered = allVulns.filter((v) => {
        if (minCvss === 0) return true;
        if (v.severity.score === null) return true; // include unknowns
        return v.severity.score >= minCvss;
    });

    // Separate new vs already-seen
    const newVulns = [];
    const knownVulns = [];

    for (const vuln of filtered) {
        if (isAlreadyNotified(vuln.id, vuln.tech)) {
            knownVulns.push(vuln);
        } else {
            newVulns.push(vuln);
        }
    }

    // Mark new vulns as notified
    if (newVulns.length > 0) {
        markBatchNotified(newVulns);

        // Send Telegram notifications
        if (!options.skipNotify) {
            await sendTelegramAlert(newVulns);
        }
    }



    // Record scan
    recordScan(config.stack.length, filtered.length, newVulns.length);

    // Print summary
    if (!silent) {
        console.log('');
        console.log(chalk.bold('  Scan Summary'));
        console.log(`    Technologies   ${config.stack.length}`);
        console.log(`    Total CVEs     ${filtered.length}`);
        console.log(`    New CVEs       ${newVulns.length > 0 ? chalk.red.bold(newVulns.length) : chalk.green(0)}`);
        console.log(`    Known CVEs     ${knownVulns.length}`);

        if (errors.length > 0) {
            console.log(`    Errors         ${chalk.red(errors.length)}`);
        }

        if (newVulns.length > 0) {
            console.log('');
            console.log(chalk.bold('  New Vulnerabilities'));
            console.log('');

            // Sort by severity score descending
            const sorted = newVulns.sort((a, b) => (b.severity.score || 0) - (a.severity.score || 0));

            for (const vuln of sorted) {
                const severityColor = getSeverityColor(vuln.severity.label);
                const score = vuln.severity.score !== null ? vuln.severity.score : '?';
                const badge = severityColor(`  ${vuln.severity.label} ${score}`);

                console.log(`    ${chalk.bold(vuln.id)} ${badge}  ${chalk.dim(vuln.tech)}`);
                console.log(`    ${vuln.summary.slice(0, 120)}`);
                if (vuln.references.length > 0) {
                    console.log(`    ${chalk.dim(vuln.references[0])}`);
                }
                console.log('');
            }
        } else if (filtered.length > 0) {
            console.log(chalk.green('\n  ✓ No new vulnerabilities since last scan.\n'));
        } else {
            console.log(chalk.green('\n  ✓ No known vulnerabilities found.\n'));
        }
    }

    return { total: filtered.length, newVulns };
}

function getSeverityColor(label) {
    switch (label?.toUpperCase()) {
        case 'CRITICAL': return chalk.bgRed.white.bold;
        case 'HIGH': return chalk.red.bold;
        case 'MEDIUM': return chalk.yellow;
        case 'LOW': return chalk.dim;
        default: return chalk.dim;
    }
}

const scanCommand = new Command('scan')
    .description('Scan your stack for known vulnerabilities (one-shot)')
    .action(async () => {
        console.log('');
        await runScan();
    });

export default scanCommand;