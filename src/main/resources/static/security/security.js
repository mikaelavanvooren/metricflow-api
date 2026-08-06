'use strict';

const API = '/api/v1/security';
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

const el = (id) => document.getElementById(id);

/**
 * Advisory summaries and dependency names originate from a third-party database, so nothing is
 * ever interpolated into markup unescaped.
 */
function escapeHtml(value) {
    if (value === null || value === undefined) {
        return '';
    }
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatTimestamp(iso) {
    if (!iso) {
        return 'unknown time';
    }
    const parsed = new Date(iso);
    return isNaN(parsed.getTime()) ? iso : parsed.toLocaleString();
}

async function getJson(path) {
    const response = await fetch(path, { headers: { Accept: 'application/json' } });
    let body = null;
    try {
        body = await response.json();
    } catch (e) {
        body = null;
    }
    if (!response.ok) {
        const message = body && body.message ? body.message : `${response.status} ${response.statusText}`;
        throw new Error(message);
    }
    return body;
}

function showAlert(message) {
    const alert = el('alert');
    alert.textContent = message;
    alert.hidden = false;
}

function clearAlert() {
    el('alert').hidden = true;
}

function severityBadge(severity) {
    const name = severity || 'UNKNOWN';
    return `<span class="badge sev-${escapeHtml(name)}">${escapeHtml(name)}</span>`;
}

function renderCards(report) {
    const counts = report.countsBySeverity || {};
    const cards = [
        { label: 'Total findings', value: report.totalFindings },
        { label: 'Critical', value: counts.CRITICAL || 0 },
        { label: 'High', value: counts.HIGH || 0 },
        { label: 'Vulnerable deps', value: `${report.vulnerableDependencies}/${report.dependenciesScanned}` },
        { label: 'Failing checks', value: report.failingConfigChecks }
    ];
    el('cards').innerHTML = cards.map((card) => `
        <div class="card">
            <div class="value">${escapeHtml(card.value)}</div>
            <div class="label">${escapeHtml(card.label)}</div>
        </div>`).join('');
}

function renderSeverityChart(counts) {
    const values = SEVERITIES.map((name) => counts[name] || 0);
    const max = Math.max.apply(null, values.concat([1]));
    el('severity-chart').innerHTML = SEVERITIES.map((name, index) => {
        const value = values[index];
        const width = value === 0 ? 0 : Math.max((value / max) * 100, 2);
        return `
            <div class="bar-row">
                <span class="bar-label">${escapeHtml(name)}</span>
                <div class="bar-track"><div class="bar-fill sev-${escapeHtml(name)}" style="width:${width}%"></div></div>
                <span class="bar-value">${escapeHtml(value)}</span>
            </div>`;
    }).join('');
}

function renderConfigChecks(findings) {
    const list = el('config-list');
    if (!findings || findings.length === 0) {
        list.innerHTML = '<li class="empty">No configuration checks ran.</li>';
        return;
    }
    list.innerHTML = findings.map((finding) => {
        const status = finding.passing
            ? '<span class="status-pass">PASS</span>'
            : `<span class="status-fail">FAIL</span> ${severityBadge(finding.severity)}`;
        const remediation = finding.passing || !finding.remediation
            ? ''
            : `<div class="check-remediation">Fix: ${escapeHtml(finding.remediation)}</div>`;
        return `
            <li>
                <div class="check-title">${status} ${escapeHtml(finding.title)}</div>
                <div class="check-detail">${escapeHtml(finding.detail)}</div>
                ${remediation}
            </li>`;
    }).join('');
}

function renderDependencyTable(findings) {
    const body = document.querySelector('#dependency-table tbody');
    if (!findings || findings.length === 0) {
        body.innerHTML = '<tr><td colspan="7" class="empty">No dependency advisories matched.</td></tr>';
        el('dependency-meta').textContent = '';
        return;
    }

    const rows = [];
    let advisoryCount = 0;
    findings.forEach((finding) => {
        const dep = finding.dependency;
        finding.vulnerabilities.forEach((vulnerability, index) => {
            advisoryCount += 1;
            const fixed = vulnerability.fixedVersions && vulnerability.fixedVersions.length
                ? vulnerability.fixedVersions.map((v) => `<code>${escapeHtml(v)}</code>`).join(' ')
                : '<span class="empty">none published</span>';
            rows.push(`
                <tr>
                    <td>${index === 0 ? escapeHtml(dep.mavenName) : ''}</td>
                    <td>${index === 0 ? `<code>${escapeHtml(dep.version)}</code>` : ''}</td>
                    <td><a href="${escapeHtml(vulnerability.detailsUrl)}" target="_blank" rel="noreferrer noopener">${escapeHtml(vulnerability.id)}</a></td>
                    <td>${severityBadge(vulnerability.severity)}</td>
                    <td>${vulnerability.cvssScore === null || vulnerability.cvssScore === undefined ? '&mdash;' : escapeHtml(vulnerability.cvssScore)}</td>
                    <td>${fixed}</td>
                    <td class="summary">${escapeHtml(vulnerability.summary)}</td>
                </tr>`);
        });
    });
    body.innerHTML = rows.join('');
    el('dependency-meta').textContent =
        `${advisoryCount} advisories across ${findings.length} dependencies.`;
}

function renderDiffList(target, entries, emptyMessage) {
    const list = el(target);
    if (!entries || entries.length === 0) {
        list.innerHTML = `<li class="empty">${escapeHtml(emptyMessage)}</li>`;
        return;
    }
    list.innerHTML = entries.map((entry) => {
        const advisory = entry.advisoryId
            ? ` <a href="https://osv.dev/vulnerability/${encodeURIComponent(entry.advisoryId)}" target="_blank" rel="noreferrer noopener">${escapeHtml(entry.advisoryId)}</a>`
            : '';
        return `<li>${severityBadge(entry.severity)} ${escapeHtml(entry.label)}${advisory}</li>`;
    }).join('');
}

function renderDiff(diff) {
    if (!diff) {
        el('diff-meta').textContent = 'No comparison available yet.';
        renderDiffList('fixed-list', [], 'Nothing to compare.');
        renderDiffList('introduced-list', [], 'Nothing to compare.');
        return;
    }
    el('fixed-count').textContent = diff.fixedCount;
    el('introduced-count').textContent = diff.introducedCount;

    if (diff.baseline) {
        el('diff-meta').textContent =
            'This is the first recorded scan, so every finding counts as new. Rescan after a fix to see a comparison.';
    } else {
        el('diff-meta').textContent =
            `Comparing ${formatTimestamp(diff.fromScannedAt)} with ${formatTimestamp(diff.toScannedAt)}. `
            + `${diff.unchangedCount} findings unchanged.`;
    }
    renderDiffList('fixed-list', diff.fixed, 'Nothing fixed since the previous scan.');
    renderDiffList('introduced-list', diff.introduced, 'Nothing new since the previous scan.');
}

/** Inline SVG keeps the page dependency free, so no charting library is loaded. */
function renderHistory(history) {
    const container = el('history-chart');
    const meta = el('history-meta');
    if (!history || history.length < 2) {
        container.innerHTML = '';
        meta.textContent = history && history.length === 1
            ? 'One scan recorded. A trend appears once there are at least two.'
            : 'No scan history recorded yet.';
        return;
    }

    const totals = history.map((snapshot) => snapshot.totalVulnerabilities + snapshot.failingConfigChecks);
    const max = Math.max.apply(null, totals);
    const min = Math.min.apply(null, totals);
    const span = max - min || 1;
    const width = 600;
    const height = 70;
    const padding = 6;

    const points = totals.map((total, index) => {
        const x = totals.length === 1 ? 0 : (index / (totals.length - 1)) * (width - padding * 2) + padding;
        const y = height - padding - ((total - min) / span) * (height - padding * 2);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
    });

    const last = totals[totals.length - 1];
    const first = totals[0];
    const stroke = last < first ? '#4ade80' : (last > first ? '#fca5a5' : '#93c5fd');

    container.innerHTML = `
        <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img"
             aria-label="Total findings across ${totals.length} scans">
            <polyline fill="none" stroke="${stroke}" stroke-width="2" points="${points.join(' ')}"></polyline>
        </svg>`;
    meta.textContent = `${totals.length} scans recorded. Oldest ${first} findings, latest ${last}.`;
}

async function load(refresh) {
    const button = el('rescan');
    button.disabled = true;
    el('scan-meta').textContent = refresh ? 'Rescanning\u2026' : 'Loading\u2026';

    try {
        const report = await getJson(`${API}/scan${refresh ? '?refresh=true' : ''}`);
        clearAlert();
        el('content').hidden = false;

        el('scan-meta').textContent =
            `${report.dependenciesScanned} dependencies checked against ${report.source} at `
            + `${formatTimestamp(report.scannedAt)}.`;

        renderCards(report);
        renderSeverityChart(report.countsBySeverity || {});
        renderConfigChecks(report.configFindings);
        renderDependencyTable(report.dependencyFindings);

        // History and diff are secondary: a failure there must not blank out the scan itself.
        try {
            renderHistory(await getJson(`${API}/history`));
        } catch (e) {
            renderHistory([]);
        }
        try {
            renderDiff(await getJson(`${API}/diff`));
        } catch (e) {
            renderDiff(null);
        }
    } catch (e) {
        el('scan-meta').textContent = 'Scan unavailable.';
        showAlert(`Could not load the scan.\n\n${e.message}`);
    } finally {
        button.disabled = false;
    }
}

el('rescan').addEventListener('click', () => load(true));
load(false);
