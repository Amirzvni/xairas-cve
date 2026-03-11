import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const CONFIG_DIR = join(homedir(), '.xairas-cve');
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');

const DEFAULT_CONFIG = {
    telegram: {
        botToken: '',
        chatId: '',
        threadId: '',
        apiUrl: 'https://api.telegram.org',
    },
    nvd: {
        apiKey: '',
    },
    scanInterval: '6h',
    severity: {
        minCvss: 0,
    },
    stack: [],
};

function ensureConfigDir() {
    if (!existsSync(CONFIG_DIR)) {
        mkdirSync(CONFIG_DIR, { recursive: true });
    }
}

export function getConfigPath() {
    return CONFIG_FILE;
}

export function loadConfig() {
    ensureConfigDir();

    if (!existsSync(CONFIG_FILE)) {
        writeFileSync(CONFIG_FILE, JSON.stringify(DEFAULT_CONFIG, null, 2));
        return structuredClone(DEFAULT_CONFIG);
    }

    const raw = readFileSync(CONFIG_FILE, 'utf-8');
    return JSON.parse(raw);
}

export function saveConfig(config) {
    ensureConfigDir();
    writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}