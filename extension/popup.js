// Get DOM elements
const scanBtn = document.getElementById('scanBtn');
const errorDiv = document.getElementById('error');
const errorText = document.getElementById('errorText');
const dismissErrorBtn = document.getElementById('dismissError');

const API_URL = 'http://127.0.0.1:8000/check/email';
// Matches #inbox/ID, #search/query/ID, #label/Name/ID, #all/ID, etc.
const GMAIL_MESSAGE_PATTERN =
    /^https:\/\/mail\.google\.com\/mail\/u\/\d+\/#[^/]+(\/[^/]+)*\/[A-Za-z0-9]{10,}$/;

document.addEventListener('DOMContentLoaded', () => {
    scanBtn?.addEventListener('click', check_email);
    dismissErrorBtn?.addEventListener('click', dismissError);

    check_email();
});

async function check_email() {
    const emailResultEl = document.getElementById('emailResult');
    hideError();

    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        // Only process Gmail message pages
        if (!tab?.url || !GMAIL_MESSAGE_PATTERN.test(tab.url.split('?')[0])) {
            emailResultEl.style.display = 'none';
            return;
        }

        const results = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: () => {
                // Use the last (most recent, expanded) message in the thread
                const bodies = document.querySelectorAll('.ii.gt .a3s');
                const body = bodies[bodies.length - 1];
                if (!body) return { body: null, headers: '' };

                const msg = body.closest('.adn') || document;
                const sender = msg.querySelector('.gD');
                const recipients = [...msg.querySelectorAll('.g2')]
                    .map(el => el.getAttribute('email') || el.innerText)
                    .filter(Boolean);
                const subject = document.querySelector('h2.hP')?.innerText;
                const dateEl = msg.querySelector('.g3');
                const date = dateEl?.getAttribute('title') || dateEl?.innerText;

                const lines = [];
                if (sender) {
                    lines.push(
                        `From: ${sender.getAttribute('name') || ''} <${sender.getAttribute('email') || ''}>`
                    );
                }
                if (recipients.length) lines.push(`To: ${recipients.join(', ')}`);
                if (subject) lines.push(`Subject: ${subject}`);
                if (date) lines.push(`Date: ${date}`);

                return { body: body.innerText, headers: lines.join('\n') };
            }
        });

        const emailText = results?.[0]?.result?.body;
        const emailHeaders = (results?.[0]?.result?.headers || '').slice(0, 5000);

        if (!emailText || !emailText.trim()) {
            console.warn('Email body not found in Gmail tab');
            emailResultEl.style.display = 'none';
            return;
        }

        setScanning(true);

        // Backend timeout is 180s, so allow slightly longer here
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 200000);

        let res;
        try {
            res = await fetch(API_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: emailText, headers: emailHeaders }),
                signal: controller.signal
            });
        } finally {
            clearTimeout(timer);
        }

        if (!res.ok) {
            let detail = '';
            try {
                const body = await res.json();
                detail = typeof body.detail === 'string' ? body.detail : '';
            } catch (_) { /* ignore */ }
            throw new Error(detail || `Server error: ${res.status}`);
        }

        const data = await res.json();
        showEmailResult(data);
        return data;

    } catch (err) {
        console.error('Email check error:', err);
        emailResultEl.style.display = 'none';
        showError(
            err.name === 'AbortError'
                ? 'Email scan timed out.'
                : `Email scan failed: ${err.message}`
        );
    } finally {
        setScanning(false);
    }
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
    return el;
}

function showEmailResult(data) {
    const container = document.getElementById('emailResult');

    setText('emailInput', data.input || '—');
    setText('emailLabel', data.classification || '—');
    setText('emailConfidence', data.confidence != null ? `${data.confidence}%` : '—');
    setText(
        'emailProbability',
        data.phishing_probability != null ? `${data.phishing_probability}%` : '—'
    );
    setText('emailReason', data.reason || '—');
    setText('emailRecommendation', data.recommendation || '—');

    // Verdict badge: text + colour driven by classification (not the boolean)
    const phishingEl = setText(
        'emailPhishing',
        data.classification || (data.is_phishing ? 'Phishing' : 'Safe')
    );
    if (phishingEl) {
        phishingEl.className = 'field-value verdict-badge';
        if (data.classification === 'Safe') {
            phishingEl.classList.add('verdict-safe');
        } else if (data.classification === 'Suspicious') {
            phishingEl.classList.add('verdict-warning');
        } else {
            phishingEl.classList.add('verdict-danger');
        }
    }

    // Indicators list (built with textContent, so no HTML injection)
    const listEl = document.getElementById('emailIndicators');
    if (listEl) {
        listEl.replaceChildren();
        (data.indicators || []).forEach(text => {
            const li = document.createElement('li');
            li.textContent = text;
            listEl.appendChild(li);
        });
    }

    container.style.display = 'block';
}

// Utility functions
function setScanning(isScanning) {
    if (!scanBtn) return;
    scanBtn.disabled = isScanning;
    scanBtn.dataset.label ??= scanBtn.textContent;
    scanBtn.textContent = isScanning ? 'Scanning…' : scanBtn.dataset.label;
}

function showError(message) {
    errorText.textContent = message;
    errorDiv.classList.remove('hidden');
}

function dismissError() {
    errorDiv.classList.add('hidden');
}

function hideError() {
    errorDiv?.classList.add('hidden');
}