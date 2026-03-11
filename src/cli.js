#!/usr/bin/env node

import { Command } from 'commander';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import configCommand from './commands/config.js';
import stackCommand from './commands/stack.js';
import scanCommand from './commands/scan.js';
import monitorCommand from './commands/monitor.js';
import historyCommand from './commands/history.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf-8'));

const program = new Command();

program
    .name('xairas-cve')
    .description(pkg.description)
    .version(pkg.version, '-V', 'output the version number');

program.addCommand(configCommand);
program.addCommand(stackCommand);
program.addCommand(scanCommand);
program.addCommand(monitorCommand);
program.addCommand(historyCommand);

program.parse();