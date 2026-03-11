import { Command } from 'commander';
import chalk from 'chalk';
import { getHistory, getNotifiedCves } from '../lib/db.js';

const historyCommand = new Command('history')
    .description('View past scan results and notified CVEs');

historyCommand
    .command('scans')
    .description('Show recent scan history')
    .option('--limit <n>', 'Number of scans to show', '10')
    .action((options) => {
        const scans = getHistory(parseInt(options.limit, 10));

        if (scans.length === 0) {
            console.log(chalk.dim('\n  No scan history yet.\n'));
            return;
        }

        console.log('');
        console.log(chalk.bold('  Recent Scans'));
        console.log('');

        for (const scan of scans) {
            const newLabel = scan.new_vulns > 0
                ? chalk.red.bold(`${scan.new_vulns} new`)
                : chalk.green('0 new');

            console.log(`    ${chalk.dim(scan.scanned_at)}  ${scan.tech_count} techs  ${scan.total_vulns} total  ${newLabel}`);
        }
        console.log('');
    });

historyCommand
    .command('cves')
    .description('Show previously notified CVEs')
    .option('--limit <n>', 'Number of CVEs to show', '20')
    .action((options) => {
        const cves = getNotifiedCves(parseInt(options.limit, 10));

        if (cves.length === 0) {
            console.log(chalk.dim('\n  No CVEs recorded yet.\n'));
            return;
        }

        console.log('');
        console.log(chalk.bold('  Notified CVEs'));
        console.log('');

        for (const cve of cves) {
            const score = cve.severity_score !== null ? cve.severity_score : '?';
            const color = getSeverityColor(cve.severity_label);
            console.log(`    ${chalk.bold(cve.id)}  ${color(`${cve.severity_label} ${score}`)}  ${chalk.dim(cve.tech)}  ${chalk.dim(cve.notified_at)}`);
        }
        console.log('');
    });

function getSeverityColor(label) {
    switch (label?.toUpperCase()) {
        case 'CRITICAL': return chalk.bgRed.white.bold;
        case 'HIGH': return chalk.red.bold;
        case 'MEDIUM': return chalk.yellow;
        case 'LOW': return chalk.dim;
        case 'MODERATE': return chalk.yellow;
        default: return chalk.dim;
    }
}

export default historyCommand;