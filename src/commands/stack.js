import { Command } from 'commander';
import { createInterface } from 'node:readline';
import chalk from 'chalk';
import ora from 'ora';
import { loadConfig, saveConfig } from '../lib/config.js';
import { searchCPE } from '../providers/nvd.js';

const KNOWN_CATEGORIES = {
    'npm': { ecosystem: 'npm', source: 'osv' },
    'pypi': { ecosystem: 'PyPI', source: 'osv' },
    'go': { ecosystem: 'Go', source: 'osv' },
    'maven': { ecosystem: 'Maven', source: 'osv' },
    'ubuntu-pkg': { ecosystem: 'Ubuntu', source: 'osv' },
    'debian-pkg': { ecosystem: 'Debian', source: 'osv' },
    'infrastructure': { ecosystem: null, source: 'nvd' },
    'hardware': { ecosystem: null, source: 'nvd' },
};

const VALID_OSV_ECOSYSTEMS = [
    'npm', 'PyPI', 'Go', 'Maven', 'NuGet', 'crates.io',
    'Packagist', 'RubyGems', 'Pub', 'Hex', 'SwiftURL',
    'Ubuntu', 'Debian', 'Alpine', 'AlmaLinux', 'Rocky Linux',
    'Linux', 'Android', 'GitHub Actions',
];

function resolveEcosystem(category, ecosystemFlag) {
    const known = KNOWN_CATEGORIES[category];

    if (known) {
        return {
            ecosystem: known.ecosystem,
            source: known.source,
        };
    }

    if (!ecosystemFlag) {
        return { error: true };
    }

    if (ecosystemFlag === 'nvd') {
        return { ecosystem: null, source: 'nvd' };
    }

    const match = VALID_OSV_ECOSYSTEMS.find(
        (e) => e.toLowerCase() === ecosystemFlag.toLowerCase()
    );

    return { ecosystem: match || ecosystemFlag, source: 'osv' };
}

function prompt(question) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => {
        rl.question(question, (answer) => {
            rl.close();
            resolve(answer.trim());
        });
    });
}

const stackCommand = new Command('stack')
    .description('Manage your technology stack');

stackCommand
    .command('add')
    .description('Add a technology to monitor')
    .requiredOption('--name <name>', 'Technology name (e.g. nginx, express, openssl)')
    .requiredOption('--version <version>', 'Version you are running')
    .requiredOption('--category <category>', 'Category (npm, pypi, go, maven, ubuntu-pkg, debian-pkg, infrastructure, hardware, or custom)')
    .option('--ecosystem <ecosystem>', 'OSV ecosystem or "nvd" (required for custom categories)')
    .option('--cpe <vendor:product>', 'Skip CPE discovery and use exact CPE vendor:product')
    .action(async (options) => {
        const config = loadConfig();
        const { name, version, category, ecosystem: ecosystemFlag, cpe } = options;

        const exists = config.stack.find(
            (t) => t.name.toLowerCase() === name.toLowerCase() && t.category === category
        );
        if (exists) {
            console.log(chalk.yellow(`\n  ⚠ "${name}" already exists in category "${category}". Use ${chalk.bold('stack update')} to change version.\n`));
            return;
        }

        const resolved = resolveEcosystem(category, ecosystemFlag);

        if (resolved.error) {
            const ecosystems = VALID_OSV_ECOSYSTEMS.join(', ');
            console.log(chalk.red(`\n  ✗ Custom category "${category}" requires --ecosystem flag.`));
            console.log(chalk.dim(`    OSV ecosystems: ${ecosystems}`));
            console.log(chalk.dim(`    Or use --ecosystem nvd for NVD/CPE lookup.\n`));
            return;
        }

        const entry = {
            name,
            version,
            category,
            ecosystem: resolved.ecosystem,
            source: resolved.source,
        };

        // NVD items need CPE mapping
        if (resolved.source === 'nvd') {
            // If user provided --cpe flag, use it directly
            if (cpe) {
                const [vendor, product] = cpe.split(':');
                if (!vendor || !product) {
                    console.log(chalk.red('\n  ✗ --cpe must be in format vendor:product (e.g. mikrotik:routeros)\n'));
                    return;
                }
                entry.cpeVendor = vendor;
                entry.cpeProduct = product;
            } else {
                // Interactive CPE discovery
                const spinner = ora(`  Searching NVD for "${name}"...`).start();

                let cpeResults;
                try {
                    cpeResults = await searchCPE(name);
                } catch (err) {
                    spinner.fail(`  NVD search failed: ${err.message}`);
                    return;
                }

                if (cpeResults.length === 0) {
                    spinner.fail(`  No CPE entries found for "${name}". Try a different search term or use --cpe vendor:product.`);
                    return;
                }

                spinner.stop();

                console.log(chalk.bold(`\n  Found ${cpeResults.length} product(s) matching "${name}":\n`));

                const display = cpeResults.slice(0, 15);
                for (let i = 0; i < display.length; i++) {
                    const r = display[i];
                    console.log(`    ${chalk.cyan(i + 1)}) ${r.vendor}:${r.product}  ${chalk.dim('—')}  ${r.title}`);
                }

                if (cpeResults.length > 15) {
                    console.log(chalk.dim(`\n    ... and ${cpeResults.length - 15} more. Refine your search if needed.`));
                }

                const answer = await prompt(chalk.bold('\n  Select number (or 0 to cancel): '));
                const choice = parseInt(answer, 10);

                if (!choice || choice < 1 || choice > display.length) {
                    console.log(chalk.dim('\n  Cancelled.\n'));
                    return;
                }

                const selected = display[choice - 1];
                entry.cpeVendor = selected.vendor;
                entry.cpeProduct = selected.product;
            }
        }

        config.stack.push(entry);
        saveConfig(config);

        let sourceLabel = resolved.source.toUpperCase();
        if (resolved.ecosystem) sourceLabel += `:${resolved.ecosystem}`;
        if (entry.cpeVendor) sourceLabel += `:${entry.cpeVendor}:${entry.cpeProduct}`;

        console.log(chalk.green(`\n  ✓ Added ${chalk.bold(name)}@${version} [${category}] → ${sourceLabel}\n`));
    });

stackCommand
    .command('list')
    .description('List all monitored technologies')
    .action(() => {
        const config = loadConfig();

        if (config.stack.length === 0) {
            console.log(chalk.dim('\n  No technologies added yet. Use xairas-cve stack add to get started.\n'));
            return;
        }

        const grouped = {};
        for (const tech of config.stack) {
            if (!grouped[tech.category]) grouped[tech.category] = [];
            grouped[tech.category].push(tech);
        }

        console.log('');
        for (const [category, techs] of Object.entries(grouped)) {
            console.log(chalk.bold.cyan(`  ${category}`));
            for (const tech of techs) {
                let source = chalk.dim(`${tech.source}`);
                if (tech.ecosystem) source += chalk.dim(`:${tech.ecosystem}`);
                if (tech.cpeVendor) source += chalk.dim(` cpe=${tech.cpeVendor}:${tech.cpeProduct}`);
                console.log(`    ${tech.name}@${chalk.yellow(tech.version)}  ${source}`);
            }
            console.log('');
        }
    });

stackCommand
    .command('remove')
    .description('Remove a technology from monitoring')
    .requiredOption('--name <name>', 'Technology name to remove')
    .option('--category <category>', 'Category (if name exists in multiple categories)')
    .action((options) => {
        const config = loadConfig();
        const { name, category } = options;

        const beforeCount = config.stack.length;

        config.stack = config.stack.filter((t) => {
            const nameMatch = t.name.toLowerCase() === name.toLowerCase();
            if (category) return !(nameMatch && t.category === category);
            return !nameMatch;
        });

        const removed = beforeCount - config.stack.length;

        if (removed === 0) {
            console.log(chalk.yellow(`\n  ⚠ "${name}" not found in stack.\n`));
            return;
        }

        saveConfig(config);
        console.log(chalk.green(`\n  ✓ Removed ${removed} entr${removed === 1 ? 'y' : 'ies'} for "${name}".\n`));
    });

stackCommand
    .command('update')
    .description('Update version of an existing technology')
    .requiredOption('--name <name>', 'Technology name')
    .requiredOption('--version <version>', 'New version')
    .option('--category <category>', 'Category (if name exists in multiple categories)')
    .action((options) => {
        const config = loadConfig();
        const { name, version, category } = options;

        let updated = 0;
        for (const tech of config.stack) {
            const nameMatch = tech.name.toLowerCase() === name.toLowerCase();
            const categoryMatch = category ? tech.category === category : true;
            if (nameMatch && categoryMatch) {
                tech.version = version;
                updated++;
            }
        }

        if (updated === 0) {
            console.log(chalk.yellow(`\n  ⚠ "${name}" not found in stack.\n`));
            return;
        }

        saveConfig(config);
        console.log(chalk.green(`\n  ✓ Updated ${chalk.bold(name)} to version ${chalk.yellow(version)}.\n`));
    });

export default stackCommand;