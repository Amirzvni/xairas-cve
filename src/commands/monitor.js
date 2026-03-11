import { Command } from 'commander';
import chalk from 'chalk';
import { loadConfig } from '../lib/config.js';
import { runScan } from './scan.js';

function parseInterval(str) {
    const match = str.match(/^(\d+)(m|h|d)$/);
    if (!match) return null;

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
        case 'm': return value * 60 * 1000;
        case 'h': return value * 60 * 60 * 1000;
        case 'd': return value * 24 * 60 * 60 * 1000;
        default: return null;
    }
}

const monitorCommand = new Command('monitor')
    .description('Continuously monitor for new CVEs')
    .option('--interval <interval>', 'Override scan interval (e.g. 30m, 6h, 1d)')
    .action(async (options) => {
        const config = loadConfig();

        if (!config.telegram.botToken || !config.telegram.chatId) {
            console.log(chalk.red('\n  ✗ Telegram not configured. Run: xairas-cve config set --bot-token <token> --chat-id <id>\n'));
            return;
        }

        if (config.stack.length === 0) {
            console.log(chalk.yellow('\n  ⚠ No technologies in stack. Use xairas-cve stack add first.\n'));
            return;
        }

        const intervalStr = options.interval || config.scanInterval || '6h';
        const intervalMs = parseInterval(intervalStr);

        if (!intervalMs) {
            console.log(chalk.red(`\n  ✗ Invalid interval "${intervalStr}". Use format: 30m, 6h, 1d\n`));
            return;
        }

        const intervalMin = Math.round(intervalMs / 60000);

        console.log('');
        console.log(chalk.bold.cyan('  xairas-cve monitor'));
        console.log(chalk.dim(`  Scanning ${config.stack.length} technologies every ${intervalStr}`));
        console.log(chalk.dim('  Press Ctrl+C to stop'));
        console.log('');

        // Initial scan
        console.log(chalk.dim(`  [${timestamp()}] Running initial scan...`));
        await runScan({ silent: false });

        // Schedule recurring scans
        const timer = setInterval(async () => {
            console.log(chalk.dim(`\n  [${timestamp()}] Scanning...`));
            try {
                await runScan({ silent: false });
            } catch (err) {
                console.log(chalk.red(`  ✗ Scan failed: ${err.message}`));
            }
        }, intervalMs);

        // Handle graceful shutdown
        process.on('SIGINT', () => {
            clearInterval(timer);
            console.log(chalk.dim(`\n  [${timestamp()}] Monitor stopped.`));
            process.exit(0);
        });

        process.on('SIGTERM', () => {
            clearInterval(timer);
            process.exit(0);
        });
    });

function timestamp() {
    return new Date().toISOString().slice(11, 19);
}

export default monitorCommand;