import chalk from 'chalk';
import { loadConfig } from '../lib/config.js';

export async function sendTelegramAlert(vulns) {
    const config = loadConfig();
    const { botToken, chatId, threadId, apiUrl } = config.telegram;

    if (!botToken || !chatId) {
        console.log(chalk.yellow('  ⚠ Telegram not configured. Skipping notifications.'));
        return;
    }

    const baseUrl = (apiUrl || 'https://api.telegram.org').replace(/\/$/, '');

    // Group vulns by tech for cleaner messages
    const grouped = {};
    for (const vuln of vulns) {
        if (!grouped[vuln.tech]) grouped[vuln.tech] = [];
        grouped[vuln.tech].push(vuln);
    }

    for (const [tech, techVulns] of Object.entries(grouped)) {
        const lines = [];
        lines.push(`🚨 <b>${techVulns.length} new CVE${techVulns.length > 1 ? 's' : ''} for ${escapeHtml(tech)}</b>`);
        lines.push('');

        for (const vuln of techVulns) {
            const score = vuln.severity.score !== null ? vuln.severity.score : '?';
            const emoji = getSeverityEmoji(vuln.severity.label);
            const link = vuln.references[0] ? `<a href="${escapeHtml(vuln.references[0])}">${escapeHtml(vuln.id)}</a>` : escapeHtml(vuln.id);

            lines.push(`${emoji} ${link}  <b>${escapeHtml(vuln.severity.label)} ${score}</b>`);
            lines.push(`${escapeHtml(truncate(vuln.summary, 150))}`);
            lines.push('');
        }

        lines.push(`<i>xairas-cve • ${new Date().toISOString().slice(0, 16)}</i>`);

        const text = lines.join('\n');

        const body = {
            chat_id: chatId,
            text,
            parse_mode: 'HTML',
            disable_web_page_preview: true,
        };

        if (threadId) {
            body.message_thread_id = parseInt(threadId, 10);
        }

        try {
            const response = await fetch(`${baseUrl}/bot${botToken}/sendMessage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });

            const data = await response.json();

            if (!data.ok) {
                console.log(chalk.red(`  ✗ Telegram error for ${tech}: ${data.description}`));
            }
        } catch (err) {
            console.log(chalk.red(`  ✗ Telegram send failed for ${tech}: ${err.message}`));
        }
    }
}

function escapeHtml(text) {
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function truncate(str, max) {
    if (str.length <= max) return str;
    return str.slice(0, max - 3) + '...';
}

function getSeverityEmoji(label) {
    switch (label?.toUpperCase()) {
        case 'CRITICAL': return '🔴';
        case 'HIGH': return '🟠';
        case 'MEDIUM': return '🟡';
        case 'LOW': return '🟢';
        case 'MODERATE': return '🟡';
        default: return '⚪';
    }
}