const LANGS = {
    ru: {
        login_title: 'Вход в панель',
        password_placeholder: 'Пароль',
        login_btn: 'Войти',
        wrong_password: 'Неверный пароль',
        connection_error: 'Ошибка подключения',
        back_link: '← К проверке',
        admin_title: 'Панель администратора',
        logout_btn: 'Выйти',
        stat_total: 'Всего проверок',
        stat_today: 'Сегодня',
        stat_completed: 'Завершено',
        stat_tcp_ok: 'TCP OK',
        search_placeholder: 'Поиск по ссылке или серверу...',
        filter_all: 'Все статусы',
        filter_completed: 'Завершено',
        filter_failed: 'Ошибка',
        filter_running: 'Выполняется',
        filter_pending: 'Ожидание',
        th_time: 'Время',
        th_link: 'Ссылка',
        th_server: 'Сервер',
        th_status: 'Статус',
        status_completed: 'Готово',
        status_failed: 'Ошибка',
        status_running: 'Проверка...',
        status_pending: 'Ожидание',
        status_queued: 'В очереди',
        no_checks: 'Проверок не найдено',
        prev: 'Назад',
        next: 'Вперёд',
        page_of: 'Стр. {page} из {pages}',
        error_label: 'Ошибка',
        pwd_change: 'Сменить пароль',
        pwd_current: 'Текущий пароль',
        pwd_new: 'Новый пароль',
        pwd_save: 'Сохранить',
        pwd_ok: 'Пароль изменён',
        pwd_wrong: 'Неверный текущий пароль',
        pwd_short: 'Минимум 4 символа',
        pwd_error: 'Ошибка смены пароля',
        view_result: 'Открыть результат',
        agents_title: 'Агенты',
        agent_add: 'Добавить агент',
        agent_name_ph: 'Имя агента',
        agent_create: 'Создать',
        agent_created: 'Агент создан! Команда установки (вставить на сервер):',
        agent_col_name: 'Имя',
        agent_col_type: 'Тип',
        agent_col_location: 'Локация',
        agent_col_status: 'Статус',
        agent_online: 'Онлайн',
        agent_offline: 'Оффлайн',
        agent_delete: 'Удалить',
        agent_none: 'Нет агентов',
        copy_btn: 'Скопировать',
        copy_done: 'Скопировано!',
    },
    en: {
        login_title: 'Admin Login',
        password_placeholder: 'Password',
        login_btn: 'Login',
        wrong_password: 'Invalid password',
        connection_error: 'Connection error',
        back_link: '← Back to checker',
        admin_title: 'Admin Dashboard',
        logout_btn: 'Logout',
        stat_total: 'Total Checks',
        stat_today: 'Today',
        stat_completed: 'Completed',
        stat_tcp_ok: 'TCP OK',
        search_placeholder: 'Search by link or server...',
        filter_all: 'All statuses',
        filter_completed: 'Completed',
        filter_failed: 'Failed',
        filter_running: 'Running',
        filter_pending: 'Pending',
        th_time: 'Time',
        th_link: 'Link',
        th_server: 'Server',
        th_status: 'Status',
        status_completed: 'Done',
        status_failed: 'Failed',
        status_running: 'Checking...',
        status_pending: 'Pending',
        status_queued: 'Queued',
        no_checks: 'No checks found',
        prev: 'Prev',
        next: 'Next',
        page_of: 'Page {page} of {pages}',
        error_label: 'Failed',
        pwd_change: 'Change password',
        pwd_current: 'Current password',
        pwd_new: 'New password',
        pwd_save: 'Save',
        pwd_ok: 'Password changed',
        pwd_wrong: 'Wrong current password',
        pwd_short: 'Minimum 4 characters',
        pwd_error: 'Failed to change password',
        view_result: 'View result',
        agents_title: 'Agents',
        agent_add: 'Add agent',
        agent_name_ph: 'Agent name',
        agent_create: 'Create',
        agent_created: 'Agent created! Install command (paste on server):',
        agent_col_name: 'Name',
        agent_col_type: 'Type',
        agent_col_location: 'Location',
        agent_col_status: 'Status',
        agent_online: 'Online',
        agent_offline: 'Offline',
        agent_delete: 'Delete',
        agent_none: 'No agents',
        copy_btn: 'Copy',
        copy_done: 'Copied!',
    },
};

let currentLang = localStorage.getItem('lang') || 'ru';
let token = localStorage.getItem('admin_token') || '';
let currentPage = 1;
let expandedRow = null;

function t(key) { return LANGS[currentLang][key] || key; }

function applyLang() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
        el.textContent = t(el.dataset.i18n);
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        el.placeholder = t(el.dataset['i18nPlaceholder']);
    });
    document.querySelectorAll('.lang-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.lang === currentLang);
    });
    localStorage.setItem('lang', currentLang);
}

document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        currentLang = btn.dataset.lang;
        applyLang();
        if (dashSection.classList.contains('hidden') === false) loadChecks();
    });
});

applyLang();

const loginSection = document.getElementById('loginSection');
const dashSection = document.getElementById('dashSection');

if (token) {
    showDashboard();
}

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const pw = document.getElementById('passwordInput').value;
    const errEl = document.getElementById('loginError');
    errEl.classList.add('hidden');

    try {
        const res = await fetch('/api/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: pw }),
        });
        if (!res.ok) {
            errEl.textContent = t('wrong_password');
            errEl.classList.remove('hidden');
            return;
        }
        const data = await res.json();
        token = data.token;
        localStorage.setItem('admin_token', token);
        showDashboard();
    } catch (err) {
        errEl.textContent = t('connection_error');
        errEl.classList.remove('hidden');
    }
});

document.getElementById('logoutBtn').addEventListener('click', () => {
    token = '';
    localStorage.removeItem('admin_token');
    loginSection.classList.remove('hidden');
    dashSection.classList.add('hidden');
});

let searchTimer;
document.getElementById('searchInput').addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { currentPage = 1; loadChecks(); }, 400);
});
document.getElementById('statusFilter').addEventListener('change', () => { currentPage = 1; loadChecks(); });

async function showDashboard() {
    loginSection.classList.add('hidden');
    dashSection.classList.remove('hidden');
    await Promise.all([loadStats(), loadChecks(), loadAgents()]);
}

async function apiFetch(url) {
    const res = await fetch(url, { headers: { 'Authorization': 'Bearer ' + token } });
    if (res.status === 401) {
        token = '';
        localStorage.removeItem('admin_token');
        loginSection.classList.remove('hidden');
        dashSection.classList.add('hidden');
        throw new Error('Unauthorized');
    }
    return res.json();
}

async function loadStats() {
    try {
        const s = await apiFetch('/api/admin/stats');
        document.getElementById('statTotal').textContent = s.total;
        document.getElementById('statToday').textContent = s.today;
        document.getElementById('statCompleted').textContent = s.completed;
        document.getElementById('statTcpOk').textContent = s.tcp_ok;
    } catch (_) {}
}

async function loadChecks() {
    const search = document.getElementById('searchInput').value.trim();
    const status = document.getElementById('statusFilter').value;
    const params = new URLSearchParams({ page: currentPage, per_page: 20 });
    if (search) params.set('search', search);
    if (status) params.set('status', status);

    try {
        const data = await apiFetch('/api/admin/checks?' + params);
        renderChecks(data.checks, data.total, data.pages);
    } catch (_) {}
}

function renderChecks(checks, total, pages) {
    const body = document.getElementById('checksBody');
    expandedRow = null;

    if (checks.length === 0) {
        body.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--text-secondary);padding:2rem;">${t('no_checks')}</td></tr>`;
        document.getElementById('pagination').innerHTML = '';
        return;
    }

    body.innerHTML = checks.map(c => {
        const time = c.created_at ? new Date(c.created_at + 'Z').toLocaleString(currentLang === 'ru' ? 'ru-RU' : 'en-US') : '—';
        const tcpOk = c.tcp_result?.success;
        const tlsOk = c.tls_result?.success;
        const tcpIcon = tcpOk === true ? '<span style="color:var(--success)">OK</span>' : tcpOk === false ? `<span style="color:var(--danger)">${t('error_label')}</span>` : '—';
        const tlsIcon = tlsOk === true ? '<span style="color:var(--success)">OK</span>' : tlsOk === false ? `<span style="color:var(--danger)">${t('error_label')}</span>` : '—';
        const statusKey = 'status_' + c.status;
        const statusColor = c.status === 'completed' ? 'var(--success)' : c.status === 'failed' ? 'var(--danger)' : 'var(--warning)';
        return `<tr class="check-row" data-id="${c.id}" style="cursor:pointer">
            <td>${time}</td>
            <td title="${esc(c.proxy_link)}">${esc(c.proxy_link)}</td>
            <td>${esc(c.server)}:${c.port}</td>
            <td style="color:${statusColor}">${t(statusKey)}</td>
            <td>${tcpIcon}</td>
            <td>${tlsIcon}</td>
            <td>${esc(c.ip_address || '—')}</td>
            <td><a href="/result/${c.id}" class="result-link" title="${t('view_result')}" onclick="event.stopPropagation()">&#128279;</a></td>
        </tr>`;
    }).join('');

    body.querySelectorAll('.check-row').forEach(row => {
        row.addEventListener('click', () => toggleDetail(row, checks));
    });

    const pageText = t('page_of').replace('{page}', currentPage).replace('{pages}', pages);
    const pag = document.getElementById('pagination');
    pag.innerHTML = `
        <button ${currentPage <= 1 ? 'disabled' : ''} onclick="goPage(${currentPage - 1})">${t('prev')}</button>
        <span>${pageText}</span>
        <button ${currentPage >= pages ? 'disabled' : ''} onclick="goPage(${currentPage + 1})">${t('next')}</button>
    `;
}

function toggleDetail(row, checks) {
    const id = row.dataset.id;
    const existing = row.nextElementSibling;
    if (existing && existing.classList.contains('detail-row')) {
        existing.remove();
        expandedRow = null;
        return;
    }

    if (expandedRow) {
        const old = document.querySelector('.detail-row');
        if (old) old.remove();
    }

    const check = checks.find(c => c.id === id);
    if (!check) return;

    const detail = document.createElement('tr');
    detail.classList.add('detail-row');
    const content = {
        proxy_link: check.proxy_link,
        server: check.server,
        port: check.port,
        sni: check.sni,
        tcp: check.tcp_result,
        tls: check.tls_result,
        fingerprints: check.fingerprint_results,
        error: check.error_message,
    };
    detail.innerHTML = `<td colspan="8"><div class="detail-content">${esc(JSON.stringify(content, null, 2))}</div></td>`;
    row.after(detail);
    expandedRow = id;
}

function goPage(p) {
    currentPage = p;
    loadChecks();
}

// === AGENTS ===
document.getElementById('addAgentToggle').addEventListener('click', () => {
    document.getElementById('addAgentForm').classList.toggle('hidden');
    document.getElementById('agentToken').classList.add('hidden');
});

document.getElementById('agentForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('agentName').value.trim();
    if (!name) return;
    try {
        const res = await fetch('/api/agent/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
            body: JSON.stringify({ name }),
        });
        if (res.ok) {
            const data = await res.json();
            document.getElementById('agentTokenValue').textContent =
                `curl -sL ${location.origin}/static/agent/install.sh | bash -s -- --master ${location.origin} --token ${data.token}`;
            document.getElementById('agentToken').classList.remove('hidden');
            document.getElementById('agentName').value = '';
            loadAgents();
        }
    } catch (_) {}
});

async function loadAgents() {
    try {
        const data = await apiFetch('/api/agent/list');
        const body = document.getElementById('agentsBody');
        if (!data || data.length === 0) {
            body.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-secondary);padding:1rem">${t('agent_none')}</td></tr>`;
            return;
        }
        body.innerHTML = data.map(a => {
            const statusColor = a.online ? 'var(--success)' : 'var(--text-secondary)';
            const statusText = a.online ? t('agent_online') : t('agent_offline');
            const loc = [a.city, a.country].filter(Boolean).join(', ') || '—';
            return `<tr>
                <td>${esc(a.name)}</td>
                <td><code>${esc(a.ip || '—')}</code></td>
                <td>${esc(loc)}</td>
                <td style="color:${statusColor}">${statusText}</td>
                <td style="white-space:nowrap">
                    <button onclick="showToken('${a.id}')" style="background:none;border:none;color:var(--accent);cursor:pointer;font-size:0.8rem">Token</button>
                    <button onclick="deleteAgent('${a.id}')" style="background:none;border:none;color:var(--danger);cursor:pointer;font-size:0.8rem;margin-left:0.3rem">${t('agent_delete')}</button>
                </td>
            </tr>`;
        }).join('');
    } catch (_) {}
}

async function showToken(id) {
    try {
        const res = await fetch('/api/agent/token/' + id, { headers: { 'Authorization': 'Bearer ' + token } });
        if (!res.ok) return;
        const data = await res.json();
        const el = document.getElementById('agentToken');
        document.getElementById('agentTokenValue').textContent =
            `curl -sL ${location.origin}/static/agent/install.sh | bash -s -- --master ${location.origin} --token ${data.token}`;
        el.classList.remove('hidden');
        document.getElementById('addAgentForm').classList.remove('hidden');
    } catch (_) {}
}

async function deleteAgent(id) {
    try {
        await fetch('/api/agent/remove/' + id, {
            method: 'DELETE',
            headers: { 'Authorization': 'Bearer ' + token },
        });
        loadAgents();
    } catch (_) {}
}

// === PASSWORD ===
document.getElementById('pwdToggle').addEventListener('click', () => {
    const wrap = document.getElementById('pwdFormWrap');
    wrap.classList.toggle('hidden');
    document.getElementById('pwdMsg').classList.add('hidden');
});

document.getElementById('pwdForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const cur = document.getElementById('pwdCurrent').value;
    const nw = document.getElementById('pwdNew').value;
    const msg = document.getElementById('pwdMsg');
    msg.classList.add('hidden');

    if (nw.length < 4) {
        msg.textContent = t('pwd_short');
        msg.className = 'pwd-msg err';
        msg.classList.remove('hidden');
        return;
    }

    try {
        const res = await fetch('/api/admin/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
            body: JSON.stringify({ current_password: cur, new_password: nw }),
        });
        if (res.ok) {
            msg.textContent = t('pwd_ok');
            msg.className = 'pwd-msg ok';
            document.getElementById('pwdCurrent').value = '';
            document.getElementById('pwdNew').value = '';
        } else {
            const data = await res.json();
            msg.textContent = data.detail || t('pwd_error');
            msg.className = 'pwd-msg err';
        }
    } catch (_) {
        msg.textContent = t('pwd_error');
        msg.className = 'pwd-msg err';
    }
    msg.classList.remove('hidden');
});

function copyAgentCmd() {
    const text = document.getElementById('agentTokenValue').textContent;
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.left = '-9999px';
    document.body.appendChild(ta); ta.select(); document.execCommand('copy');
    document.body.removeChild(ta);
    const btn = document.getElementById('copyTokenBtn');
    btn.textContent = t('copy_done');
    btn.style.color = 'var(--success)'; btn.style.borderColor = 'var(--success)';
    setTimeout(() => { btn.textContent = t('copy_btn'); btn.style.color = ''; btn.style.borderColor = ''; }, 2000);
}

function esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}
