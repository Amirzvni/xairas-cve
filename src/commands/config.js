import { Command } from 'commander';
import chalk from 'chalk';
import { loadConfig, saveConfig, getConfigPath } from '../lib/config.js';

const configCommand = new Command('config')
    .description('Manage xairas-cve configuration');

configCommand
    .command('set')
    .description('Set Telegram and scanning configuration')
    .option('--bot-token <token>', 'Telegram bot token')
    .option('--chat-id <id>', 'Telegram chat ID')
    .option('--api-url <url>', 'Telegram API URL (default: https://api.telegram.org)')
    .option('--nvd-api-key <key>', 'NVD API key (optional, increases rate limit)')
    .option('--scan-interval <interval>', 'Scan interval (e.g. 1h, 6h, 24h)')
    .option('--min-cvss <score>', 'Minimum CVSS score to notify (0-10)')
    .option('--thread-id <id>', 'Telegram topic/thread ID (for forum groups)')
    .action((options) => {
        const config = loadConfig();

        if (options.botToken) config.telegram.botToken = options.botToken;
        if (options.chatId) config.telegram.chatId = options.chatId;
        if (options.apiUrl) config.telegram.apiUrl = options.apiUrl;
        if (options.nvdApiKey) config.nvd.apiKey = options.nvdApiKey;
        if (options.scanInterval) config.scanInterval = options.scanInterval;
        if (options.minCvss) config.severity.minCvss = parseFloat(options.minCvss);
        if (options.threadId) config.telegram.threadId = options.threadId;

        saveConfig(config);
        console.log(chalk.green('✓ Configuration updated.'));
    });

configCommand
    .command('show')
    .description('Show current configuration')
    .action(() => {
        const config = loadConfig();

        // Mask the bot token for security
        let maskedToken = chalk.dim('not set');
        if (config.telegram.botToken) {
            const token = config.telegram.botToken;
            maskedToken = token.slice(0, 4) + chalk.dim('••••') + token.slice(-4);
        }

        let maskedNvdKey = chalk.dim('not set (using public rate limit)');
        if (config.nvd?.apiKey) {
            const key = config.nvd.apiKey;
            maskedNvdKey = key.slice(0, 4) + chalk.dim('••••') + key.slice(-4);
        }

        const chatId = config.telegram.chatId || chalk.dim('not set');
        const apiUrl = config.telegram.apiUrl || 'https://api.telegram.org';
        const stackCount = config.stack.length;
        const threadId = config.telegram.threadId || chalk.dim('not set (sends to main chat)');
        console.log('');
        console.log(chalk.bold.cyan('  xairas-cve') + chalk.dim(` — ${getConfigPath()}`));
        console.log('');
        console.log(chalk.bold('  Telegram'));
        console.log(`    Bot Token      ${maskedToken}`);
        console.log(`    Chat ID        ${chatId}`);
        console.log(`    Thread ID      ${threadId}`);
        console.log(`    API URL        ${apiUrl}`);
        console.log('');
        console.log(chalk.bold('  NVD'));
        console.log(`    API Key        ${maskedNvdKey}`);
        console.log('');
        console.log(chalk.bold('  Scanning'));
        console.log(`    Interval       ${config.scanInterval}`);
        console.log(`    Min CVSS       ${config.severity.minCvss}`);
        console.log('');
        console.log(chalk.bold('  Stack'));
        console.log(`    Technologies   ${stackCount === 0 ? chalk.dim('none added yet') : stackCount}`);
        console.log('');
    });

export default configCommand;