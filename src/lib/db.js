import Database from 'better-sqlite3';
import { existsSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const CONFIG_DIR = join(homedir(), '.xairas-cve');
const DB_FILE = join(CONFIG_DIR, 'data.db');

let db = null;

export function getDb() {
    if (db) return db;

    if (!existsSync(CONFIG_DIR)) {
        mkdirSync(CONFIG_DIR, { recursive: true });
    }

    db = new Database(DB_FILE);
    db.pragma('journal_mode = WAL');

    db.exec(`
    CREATE TABLE IF NOT EXISTS notified_cves (
      id TEXT NOT NULL,
      tech TEXT NOT NULL,
      category TEXT NOT NULL,
      severity_label TEXT,
      severity_score REAL,
      summary TEXT,
      source TEXT NOT NULL,
      notified_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (id, tech)
    );

    CREATE TABLE IF NOT EXISTS scan_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scanned_at TEXT NOT NULL DEFAULT (datetime('now')),
      tech_count INTEGER NOT NULL,
      total_vulns INTEGER NOT NULL,
      new_vulns INTEGER NOT NULL
    );
  `);

    return db;
}

export function isAlreadyNotified(cveId, tech) {
    const db = getDb();
    const row = db.prepare('SELECT 1 FROM notified_cves WHERE id = ? AND tech = ?').get(cveId, tech);
    return !!row;
}

export function markNotified(vuln) {
    const db = getDb();
    db.prepare(`
    INSERT OR IGNORE INTO notified_cves (id, tech, category, severity_label, severity_score, summary, source)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
        vuln.id,
        vuln.tech,
        vuln.category,
        vuln.severity.label,
        vuln.severity.score,
        vuln.summary,
        vuln.source
    );
}

export function markBatchNotified(vulns) {
    const db = getDb();
    const insert = db.prepare(`
    INSERT OR IGNORE INTO notified_cves (id, tech, category, severity_label, severity_score, summary, source)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

    const transaction = db.transaction((items) => {
        for (const v of items) {
            insert.run(v.id, v.tech, v.category, v.severity.label, v.severity.score, v.summary, v.source);
        }
    });

    transaction(vulns);
}

export function recordScan(techCount, totalVulns, newVulns) {
    const db = getDb();
    db.prepare(`
    INSERT INTO scan_history (tech_count, total_vulns, new_vulns)
    VALUES (?, ?, ?)
  `).run(techCount, totalVulns, newVulns);
}

export function getHistory(limit = 20) {
    const db = getDb();
    return db.prepare(`
    SELECT * FROM scan_history ORDER BY scanned_at DESC LIMIT ?
  `).all(limit);
}

export function getNotifiedCves(limit = 50) {
    const db = getDb();
    return db.prepare(`
    SELECT * FROM notified_cves ORDER BY notified_at DESC LIMIT ?
  `).all(limit);
}