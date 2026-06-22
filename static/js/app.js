const LANGS = {
    ru: {
        subtitle: 'Проверка Telegram MTProto прокси: подключение и TLS-отпечатки',
        check_btn: 'Проверить',
        results_title: 'Результаты',
        tcp_label: 'TCP соединение',
        tls_label: 'TLS рукопожатие',
        fp_title: 'Тесты TLS-отпечатков',
        server_info_title: 'Информация о сервере',
        checker_info_title: 'Проверка выполнена из',
        tls_cert_title: 'TLS-сертификат',
        stability_title: 'Стабильность соединения',
        dpi_title: 'DPI-детекция',
        dns_title: 'DNS-проверка',
        col_client: 'Клиент', col_mode: 'Режим', col_status: 'Статус', col_time: 'Время',
        submitting: 'Отправка...', in_queue: 'В очереди...', running: 'Выполняются проверки...',
        check_failed: 'Проверка не удалась', request_error: 'Ошибка запроса',
        connected: 'Подключено', error: 'Ошибка', skipped: 'Пропущено',
        ms: 'мс', server: 'Сервер', port: 'Порт',
        mode_single: 'одиночный', mode_parallel: 'параллельный',
        healthy: 'Работает', degraded: 'Частично', unhealthy: 'Не работает',
        lbl_ip: 'IP-адрес', lbl_country: 'Страна', lbl_region: 'Регион', lbl_city: 'Город',
        lbl_isp: 'Провайдер', lbl_org: 'Организация', lbl_as: 'AS', lbl_rdns: 'Reverse DNS',
        lbl_type: 'Тип', type_dc: 'Дата-центр', type_proxy: 'Прокси', type_residential: 'Резидентный',
        cert_subject: 'Субъект', cert_issuer: 'Издатель', cert_expires: 'Действителен до',
        cert_sni_match: 'Совпадение SNI', cert_tls_ver: 'Версия TLS', cert_cipher: 'Шифр',
        cert_bits: 'бит',
        tip_cert_subject: 'Кому выдан сертификат. Должен совпадать с доменом SNI.',
        tip_cert_issuer: 'Кто выдал сертификат. Самоподписанный — норма для прокси.',
        tip_cert_expires: 'Дата окончания действия сертификата.',
        tip_cert_sni_match: 'Совпадает ли домен в сертификате с SNI из ссылки. Несовпадение — норма для MTProto прокси.',
        tip_cert_tls_ver: 'Версия протокола TLS. 1.3 — лучше всего, 1.2 — допустимо.',
        tip_cert_cipher: 'Алгоритм шифрования. Определяет уровень защиты канала.',
        stab_success_rate: 'Успешность', stab_avg: 'Среднее', stab_jitter: 'Джиттер',
        stab_pattern: 'Паттерн',
        pattern_stable: 'Стабильно', pattern_unstable: 'Нестабильно',
        pattern_rate_limited: 'Ограничение частоты', pattern_blocked: 'Заблокировано',
        pattern_connection_refused: 'Соединение отклонено',
        tip_stab_bar: '10 быстрых подключений подряд. Зелёный — успех, красный — ошибка. Показывает стабильность доступа.',
        tip_stab_jitter: 'Разброс времени ответа. Высокий джиттер может указывать на throttling.',
        tip_stab_pattern: 'Анализ паттерна: стабильно, нестабильно, ограничение частоты или полная блокировка.',
        dpi_sni_filter: 'Фильтрация по SNI',
        dpi_http_probe: 'HTTP-проба',
        dpi_rst: 'TCP RST',
        tip_dpi_sni: 'Сравнение подключений с правильным и неправильным SNI. Если правильный блокируется, а неправильный — нет, провайдер фильтрует по SNI.',
        tip_dpi_http: 'Отправка HTTP-запроса на порт прокси. Если сервер отвечает HTTP — он маскируется под веб-сервер.',
        tip_dpi_rst: 'Отправка некорректного TLS-пакета. Если приходит TCP RST вместо закрытия — признак DPI-блокировки.',
        dpi_no: 'Нет', dpi_yes: 'Да', dpi_unknown: 'Неизвестно',
        dpi_http_yes: 'Отвечает HTTP', dpi_http_no: 'Не HTTP', dpi_no_response: 'Нет ответа',
        rst_none: 'Нет RST', rst_detected: 'RST обнаружен', rst_on_connect: 'RST при подключении',
        rst_closed: 'Соединение закрыто', rst_timeout: 'Таймаут',
        dns_system: 'Системный DNS', dns_google: 'Google DNS', dns_cloudflare: 'Cloudflare DNS',
        dns_consistent: 'Согласованность',
        tip_dns_system: 'Резолв через DNS провайдера. Если IP отличается от других DNS — возможен DNS-poisoning.',
        tip_dns_google: 'Резолв через Google (8.8.8.8). Считается незаблокированным.',
        tip_dns_cloudflare: 'Резолв через Cloudflare (1.1.1.1). Считается незаблокированным.',
        tip_dns_consistent: 'Все DNS возвращают одинаковый IP? Если нет — возможна подмена DNS.',
        dns_ok: 'Совпадают', dns_mismatch: 'Расхождение',
        dns_direct_ip: '(прямой IP, DNS не требуется)',
        share_btn: 'Поделиться',
        share_copied: 'Скопировано!',
        safe_mode: 'Безопасный режим (1 запрос/2 сек)',
        tip_safe_mode: 'Некоторые прокси используют SYN rate limiter (MTproxy-reanimation). В безопасном режиме все проверки идут с интервалом 1 сек между подключениями, чтобы не попасть под блокировку. Проверка займёт больше времени.',
        mtproto_label: 'MTProto',
        mtproto_ok: 'Прокси отвечает',
        mtproto_kept_alive: 'Соединение удержано',
        mtproto_fail: 'Не отвечает',
        mtproto_rejected: 'Init отклонён',
        mode_label: 'Режим',
        mode_fake_tls: 'Fake TLS',
        mode_padded: 'Padded Intermediate',
        mode_simple: 'Simple',
        mode_unknown: 'Неизвестно',
        tip_mtproto: 'Проверка MTProto протокола — отправляется обфусцированный пакет инициализации. Если прокси отвечает — он работает.',
        dc_warning_title: 'Сервер отклоняет подключения из дата-центра',
        dc_warning_text: 'Прокси-сервер отказывает в подключении с нашего IP ({ip}, {location}). Многие MTProto-прокси блокируют датацентровые IP для защиты от обнаружения. Прокси может быть доступен с вашего домашнего/мобильного IP.',
        dc_warning_title_timeout: 'Сервер не отвечает из нашего дата-центра',
        dc_warning_text_timeout: 'Прокси-сервер не отвечает на подключения с нашего IP ({ip}, {location}). Сервер может фильтровать подключения по IP или геолокации. Прокси может быть доступен с вашего домашнего/мобильного IP.',
        dc_warning_title_tls: 'TLS не работает из нашего дата-центра',
        dc_warning_text_tls: 'TCP-порт открыт, но TLS-рукопожатие не проходит с нашего IP ({ip}, {location}). Сервер может фильтровать TLS-подключения с датацентровых IP. Прокси может работать с вашего домашнего/мобильного IP.',
    },
    en: {
        subtitle: 'Check Telegram MTProto proxy connectivity and TLS fingerprints',
        check_btn: 'Check',
        results_title: 'Results',
        tcp_label: 'TCP Connection', tls_label: 'TLS Handshake',
        fp_title: 'TLS Fingerprint Tests',
        server_info_title: 'Server Information', checker_info_title: 'Checked from',
        tls_cert_title: 'TLS Certificate',
        stability_title: 'Connection Stability',
        dpi_title: 'DPI Detection',
        dns_title: 'DNS Check',
        col_client: 'Client', col_mode: 'Mode', col_status: 'Status', col_time: 'Duration',
        submitting: 'Submitting...', in_queue: 'In queue...', running: 'Running checks...',
        check_failed: 'Check failed', request_error: 'Request failed',
        connected: 'Connected', error: 'Failed', skipped: 'Skipped',
        ms: 'ms', server: 'Server', port: 'Port',
        mode_single: 'single', mode_parallel: 'parallel',
        healthy: 'Healthy', degraded: 'Degraded', unhealthy: 'Unhealthy',
        lbl_ip: 'IP Address', lbl_country: 'Country', lbl_region: 'Region', lbl_city: 'City',
        lbl_isp: 'ISP', lbl_org: 'Organization', lbl_as: 'AS', lbl_rdns: 'Reverse DNS',
        lbl_type: 'Type', type_dc: 'Datacenter', type_proxy: 'Proxy', type_residential: 'Residential',
        cert_subject: 'Subject', cert_issuer: 'Issuer', cert_expires: 'Valid until',
        cert_sni_match: 'SNI Match', cert_tls_ver: 'TLS Version', cert_cipher: 'Cipher',
        cert_bits: 'bits',
        tip_cert_subject: 'Who the certificate was issued to. Should match the SNI domain.',
        tip_cert_issuer: 'Certificate authority. Self-signed is normal for proxy servers.',
        tip_cert_expires: 'Certificate expiration date.',
        tip_cert_sni_match: 'Whether the certificate domain matches the SNI. Mismatch is normal for MTProto proxies.',
        tip_cert_tls_ver: 'TLS protocol version. 1.3 is best, 1.2 is acceptable.',
        tip_cert_cipher: 'Encryption algorithm. Determines the security level of the channel.',
        stab_success_rate: 'Success rate', stab_avg: 'Average', stab_jitter: 'Jitter',
        stab_pattern: 'Pattern',
        pattern_stable: 'Stable', pattern_unstable: 'Unstable',
        pattern_rate_limited: 'Rate limited', pattern_blocked: 'Blocked',
        pattern_connection_refused: 'Connection refused',
        tip_stab_bar: '10 rapid connections in a row. Green = success, red = failure. Shows access stability.',
        tip_stab_jitter: 'Response time spread. High jitter may indicate throttling.',
        tip_stab_pattern: 'Pattern analysis: stable, unstable, rate limited, or fully blocked.',
        dpi_sni_filter: 'SNI Filtering',
        dpi_http_probe: 'HTTP Probe',
        dpi_rst: 'TCP RST',
        tip_dpi_sni: 'Compares connections with correct vs wrong SNI. If correct is blocked but wrong is not, the ISP filters by SNI.',
        tip_dpi_http: 'Sends HTTP request to proxy port. If server responds with HTTP, it is disguised as a web server.',
        tip_dpi_rst: 'Sends an invalid TLS packet. A TCP RST instead of close indicates DPI blocking.',
        dpi_no: 'No', dpi_yes: 'Yes', dpi_unknown: 'Unknown',
        dpi_http_yes: 'Responds HTTP', dpi_http_no: 'Not HTTP', dpi_no_response: 'No response',
        rst_none: 'No RST', rst_detected: 'RST detected', rst_on_connect: 'RST on connect',
        rst_closed: 'Connection closed', rst_timeout: 'Timeout',
        dns_system: 'System DNS', dns_google: 'Google DNS', dns_cloudflare: 'Cloudflare DNS',
        dns_consistent: 'Consistency',
        tip_dns_system: 'Resolution via ISP DNS. Different IP from other DNS may indicate DNS poisoning.',
        tip_dns_google: 'Resolution via Google (8.8.8.8). Considered unblocked.',
        tip_dns_cloudflare: 'Resolution via Cloudflare (1.1.1.1). Considered unblocked.',
        tip_dns_consistent: 'Do all DNS return the same IP? If not, DNS spoofing is possible.',
        dns_ok: 'Consistent', dns_mismatch: 'Mismatch',
        dns_direct_ip: '(direct IP, no DNS needed)',
        share_btn: 'Share',
        share_copied: 'Copied!',
        safe_mode: 'Safe mode (1 req/2 sec)',
        tip_safe_mode: 'Some proxies use SYN rate limiter (MTproxy-reanimation). Safe mode adds 1 second delay between all connections to avoid being blocked. Checks will take longer.',
        mtproto_label: 'MTProto',
        mtproto_ok: 'Proxy responds',
        mtproto_kept_alive: 'Connection kept alive',
        mtproto_fail: 'No response',
        mtproto_rejected: 'Init rejected',
        mode_label: 'Mode',
        mode_fake_tls: 'Fake TLS',
        mode_padded: 'Padded Intermediate',
        mode_simple: 'Simple',
        mode_unknown: 'Unknown',
        tip_mtproto: 'MTProto protocol check — sends an obfuscated init packet. If the proxy responds, it is working.',
        dc_warning_title: 'Server rejects datacenter connections',
        dc_warning_text: 'The proxy server refuses connections from our IP ({ip}, {location}). Many MTProto proxies block datacenter IPs to avoid detection. The proxy may be accessible from your home/mobile IP.',
        dc_warning_title_timeout: 'Server not responding from our datacenter',
        dc_warning_text_timeout: 'The proxy server does not respond to connections from our IP ({ip}, {location}). The server may filter connections by IP or geolocation. The proxy may be accessible from your home/mobile IP.',
        dc_warning_title_tls: 'TLS not working from our datacenter',
        dc_warning_text_tls: 'TCP port is open, but TLS handshake fails from our IP ({ip}, {location}). The server may filter TLS connections from datacenter IPs. The proxy may work from your home/mobile IP.',
    },
};

let currentLang = localStorage.getItem('lang') || 'ru';
function t(key) { return LANGS[currentLang][key] || key; }

function applyLang() {
    document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
    document.querySelectorAll('.lang-btn').forEach(btn => { btn.classList.toggle('active', btn.dataset.lang === currentLang); });
    localStorage.setItem('lang', currentLang);
}
document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.addEventListener('click', () => { currentLang = btn.dataset.lang; applyLang(); if (lastResults) renderResults(lastResults); });
});
applyLang();

let lastResults = null;
const form = document.getElementById('checkForm');
const input = document.getElementById('proxyLink');
const btn = document.getElementById('checkBtn');
const statusBar = document.getElementById('statusBar');
const spinner = document.getElementById('spinner');
const statusText = document.getElementById('statusText');
const errorMsg = document.getElementById('errorMsg');
const resultsDiv = document.getElementById('results');

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const link = input.value.trim();
    if (!link) return;
    btn.disabled = true;
    statusBar.classList.remove('hidden'); spinner.classList.remove('hidden');
    statusText.textContent = t('submitting');
    errorMsg.classList.add('hidden'); resultsDiv.classList.add('hidden'); lastResults = null;
    try {
        const safeMode = document.getElementById('safeMode').checked;
        const res = await fetch('/api/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proxy_link: link, safe_mode: safeMode }) });
        if (!res.ok) { const data = await res.json(); throw new Error(data.detail || t('request_error')); }
        const { task_id } = await res.json();
        currentCheckId = task_id;
        connectWebSocket(task_id);
    } catch (err) { showError(err.message); btn.disabled = false; statusBar.classList.add('hidden'); }
});

function connectWebSocket(taskId) {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${location.host}/ws/check/${taskId}`);
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'ping') return;
        if (data.status === 'queued') statusText.textContent = t('in_queue');
        else if (data.status === 'running') statusText.textContent = t('running');
        else if (data.status === 'completed') { spinner.classList.add('hidden'); statusBar.classList.add('hidden'); btn.disabled = false; renderResults(data.results); if (currentCheckId) history.replaceState(null, '', '/result/' + currentCheckId); }
        else if (data.status === 'failed') { showError(data.error || t('check_failed')); btn.disabled = false; statusBar.classList.add('hidden'); }
    };
    ws.onerror = () => { ws.close(); fallbackPolling(taskId); };
    ws.onclose = () => { if (btn.disabled) fallbackPolling(taskId); };
}

function fallbackPolling(taskId) {
    const iv = setInterval(async () => {
        try {
            const res = await fetch(`/api/status/${taskId}`);
            const data = await res.json();
            if (data.status === 'completed') { clearInterval(iv); spinner.classList.add('hidden'); statusBar.classList.add('hidden'); btn.disabled = false; renderResults(data.results); if (currentCheckId) history.replaceState(null, '', '/result/' + currentCheckId); }
            else if (data.status === 'failed') { clearInterval(iv); showError(data.error || t('check_failed')); btn.disabled = false; statusBar.classList.add('hidden'); }
        } catch (_) {}
    }, 2000);
}

function showError(msg) { errorMsg.textContent = msg; errorMsg.classList.remove('hidden'); spinner.classList.add('hidden'); }

function flag(code) {
    if (!code) return '';
    return `<img src="https://flagcdn.com/24x18/${code.toLowerCase()}.png" width="24" height="18" alt="${code}" class="flag-img">`;
}

function tip(labelKey, tipKey, valueHtml) {
    return `<div class="info-row">
        <span class="info-label has-tooltip">${t(labelKey)}<span class="tooltip">${t(tipKey)}</span></span>
        <span class="info-value">${valueHtml}</span>
    </div>`;
}

function row(label, value) {
    return `<div class="info-row"><span class="info-label">${label}</span><span class="info-value">${value}</span></div>`;
}

function renderInfoGrid(el, info) {
    if (!info || info.error) { el.parentElement.classList.add('hidden'); return; }
    el.parentElement.classList.remove('hidden');
    let typeTag = '';
    if (info.hosting) typeTag = `<span class="info-tag info-tag-dc">${t('type_dc')}</span>`;
    else if (info.proxy) typeTag = `<span class="info-tag info-tag-proxy">${t('type_proxy')}</span>`;
    else if (info.hosting === false) typeTag = t('type_residential');
    const rows = [];
    if (info.ip) rows.push(row(t('lbl_ip'), `<code>${esc(info.ip)}</code>`));
    if (info.country) rows.push(row(t('lbl_country'), `${flag(info.country_code)}${esc(info.country)}`));
    if (info.region) rows.push(row(t('lbl_region'), esc(info.region)));
    if (info.city) rows.push(row(t('lbl_city'), esc(info.city)));
    if (info.isp) rows.push(row(t('lbl_isp'), esc(info.isp)));
    if (info.org) rows.push(row(t('lbl_org'), esc(info.org)));
    if (info.as_number) rows.push(row(t('lbl_as'), esc(info.as_number)));
    if (info.reverse_dns) rows.push(row(t('lbl_rdns'), `<code>${esc(info.reverse_dns)}</code>`));
    if (typeTag) rows.push(row(t('lbl_type'), typeTag));
    el.innerHTML = rows.join('');
}

function renderTlsCert(r) {
    const el = document.getElementById('tlsCertGrid');
    const card = document.getElementById('tlsCertCard');
    const c = r.tls_cert;
    if (!c || !c.available) { card.classList.add('hidden'); return; }
    card.classList.remove('hidden');
    const matchHtml = c.sni_match
        ? `<span style="color:var(--success)">✓</span>`
        : `<span style="color:var(--warning)">✗</span>`;
    el.innerHTML = [
        tip('cert_subject', 'tip_cert_subject', `<code>${esc(c.subject)}</code>`),
        tip('cert_issuer', 'tip_cert_issuer', `<code>${esc(c.issuer)}</code>`),
        tip('cert_expires', 'tip_cert_expires', esc(c.not_after)),
        tip('cert_sni_match', 'tip_cert_sni_match', matchHtml),
        tip('cert_tls_ver', 'tip_cert_tls_ver', esc(c.tls_version)),
        tip('cert_cipher', 'tip_cert_cipher', `${esc(c.cipher_suite)} (${c.cipher_bits} ${t('cert_bits')})`),
    ].join('');
}

function renderStability(r) {
    const el = document.getElementById('stabilityContent');
    const card = document.getElementById('stabilityCard');
    const s = r.stability;
    if (!s) { card.classList.add('hidden'); return; }
    card.classList.remove('hidden');
    const dots = (s.details || []).map((d, i) => {
        const cls = d.ok ? 'ok' : 'fail';
        const label = d.ok ? d.rtt_ms : '✗';
        return `<div class="stability-dot ${cls}">${label}</div>`;
    }).join('');
    const patternKey = 'pattern_' + s.pattern;
    const patternColor = s.pattern === 'stable' ? 'var(--success)' : s.pattern === 'blocked' ? 'var(--danger)' : 'var(--warning)';
    el.innerHTML = `
        <div class="has-tooltip">
            <div class="stability-bar">${dots}</div>
            <span class="tooltip">${t('tip_stab_bar')}</span>
        </div>
        <div class="stability-stats">
            <span>${t('stab_success_rate')}: <span class="val">${s.success_rate}%</span></span>
            <span>${t('stab_avg')}: <span class="val">${s.avg_rtt_ms} ${t('ms')}</span></span>
            <span class="has-tooltip">${t('stab_jitter')}: <span class="val">${s.jitter_ms} ${t('ms')}</span><span class="tooltip">${t('tip_stab_jitter')}</span></span>
            <span class="has-tooltip">${t('stab_pattern')}: <span class="val" style="color:${patternColor}">${t(patternKey)}</span><span class="tooltip">${t('tip_stab_pattern')}</span></span>
        </div>`;
}

function renderDpi(r) {
    const el = document.getElementById('dpiGrid');
    const card = document.getElementById('dpiCard');
    const d = r.dpi;
    if (!d) { card.classList.add('hidden'); return; }
    card.classList.remove('hidden');
    const rows = [];

    if (d.sni_filtering !== undefined) {
        let val, color;
        if (d.sni_filtering === true) { val = t('dpi_yes'); color = 'var(--danger)'; }
        else if (d.sni_filtering === false) { val = t('dpi_no'); color = 'var(--success)'; }
        else { val = t('dpi_unknown'); color = 'var(--text-secondary)'; }
        rows.push(tip('dpi_sni_filter', 'tip_dpi_sni', `<span style="color:${color}">${val}</span>`));
    }

    if (d.http_probe) {
        const hp = d.http_probe;
        let val;
        if (hp.responds && hp.is_http) val = `<span style="color:var(--success)">${t('dpi_http_yes')}</span>`;
        else if (hp.responds) val = t('dpi_http_no');
        else val = `<span style="color:var(--text-secondary)">${t('dpi_no_response')}</span>`;
        rows.push(tip('dpi_http_probe', 'tip_dpi_http', val));
    }

    if (d.rst_detected) {
        const rst = d.rst_detected;
        let val, color = 'var(--text-secondary)';
        if (rst.type === 'rst' || rst.type === 'rst_on_connect') { val = t(rst.type === 'rst' ? 'rst_detected' : 'rst_on_connect'); color = 'var(--danger)'; }
        else if (rst.type === 'connection_closed') { val = t('rst_closed'); }
        else if (rst.type === 'no_response' || rst.type === 'connect_timeout') { val = t('rst_timeout'); }
        else { val = t('rst_none'); color = 'var(--success)'; }
        rows.push(tip('dpi_rst', 'tip_dpi_rst', `<span style="color:${color}">${val}</span>`));
    }

    el.innerHTML = rows.join('');
}

function renderDns(r) {
    const el = document.getElementById('dnsGrid');
    const card = document.getElementById('dnsCard');
    const d = r.dns;
    if (!d) { card.classList.add('hidden'); return; }
    card.classList.remove('hidden');

    if (d.direct_ip) {
        el.innerHTML = row('IP', `<code>${esc(d.all_ips?.[0])}</code> <span style="color:var(--text-secondary)">${t('dns_direct_ip')}</span>`);
        return;
    }

    const rows = [];
    for (const [key, tipKey] of [['system', 'tip_dns_system'], ['google', 'tip_dns_google'], ['cloudflare', 'tip_dns_cloudflare']]) {
        const entry = d[key];
        if (!entry) continue;
        const labelKey = 'dns_' + key;
        const ips = entry.ips?.join(', ') || entry.error || '—';
        const okIcon = entry.ok ? '<span style="color:var(--success)">✓</span> ' : '<span style="color:var(--danger)">✗</span> ';
        rows.push(tip(labelKey, tipKey, okIcon + `<code>${esc(ips)}</code>`));
    }
    if (d.consistent !== undefined) {
        const val = d.consistent
            ? `<span style="color:var(--success)">${t('dns_ok')}</span>`
            : `<span style="color:var(--danger)">${t('dns_mismatch')}</span>`;
        rows.push(tip('dns_consistent', 'tip_dns_consistent', val));
    }
    el.innerHTML = rows.join('');
}

function renderResults(r) {
    lastResults = r;
    resultsDiv.classList.remove('hidden');
    const badge = document.getElementById('overallBadge');
    badge.textContent = t(r.overall_status);
    badge.className = 'badge badge-' + r.overall_status;

    document.getElementById('serverInfo').innerHTML =
        `<span><span class="label-sm">${t('server')}:</span> <span class="val">${esc(r.server)}</span></span>` +
        `<span><span class="label-sm">${t('port')}:</span> <span class="val">${r.port}</span></span>` +
        (r.sni ? `<span><span class="label-sm">SNI:</span> <span class="val">${esc(r.sni)}</span></span>` : '');

    const tcp = r.tcp;
    document.getElementById('tcpResult').innerHTML = tcp.success
        ? `<span class="ok">${t('connected')}</span><span class="rtt">${tcp.rtt_ms} ${t('ms')}</span>`
        : `<span class="fail">${t('error')}</span><span class="rtt">${esc(tcp.error)}</span>`;
    const tls = r.tls;
    if (tls.success === null || tls.success === undefined)
        document.getElementById('tlsResult').innerHTML = `<span class="skip">${t('skipped')}</span><span class="rtt">${esc(tls.error)}</span>`;
    else if (tls.success)
        document.getElementById('tlsResult').innerHTML = `<span class="ok">OK</span><span class="rtt">${tls.rtt_ms} ${t('ms')}</span>`;
    else
        document.getElementById('tlsResult').innerHTML = `<span class="fail">${t('error')}</span><span class="rtt">${esc(tls.error)}</span>`;

    const mtItem = document.getElementById('mtprotoItem');
    const mtResult = document.getElementById('mtprotoResult');
    if (r.mtproto) {
        mtItem.style.display = '';
        const mt = r.mtproto;
        if (mt.success && mt.detail === 'responded') {
            mtResult.innerHTML = `<span class="ok">${t('mtproto_ok')}</span><span class="rtt">${mt.rtt_ms} ${t('ms')}</span>`;
        } else if (mt.success && mt.detail === 'kept_alive') {
            mtResult.innerHTML = `<span class="ok">${t('mtproto_kept_alive')}</span><span class="rtt">${mt.rtt_ms} ${t('ms')}</span>`;
        } else if (mt.error === 'init rejected') {
            mtResult.innerHTML = `<span class="skip">${t('mtproto_rejected')}</span><span class="rtt">${mt.rtt_ms} ${t('ms')}</span>`;
        } else {
            mtResult.innerHTML = `<span class="fail">${t('mtproto_fail')}</span><span class="rtt">${esc(mt.error)}</span>`;
        }
    } else {
        mtItem.style.display = 'none';
    }

    const modeItem = document.getElementById('modeItem');
    const modeResult = document.getElementById('modeResult');
    if (r.proxy_mode) {
        modeItem.style.display = '';
        modeResult.textContent = t('mode_' + r.proxy_mode);
    } else {
        modeItem.style.display = 'none';
    }

    const dcWarn = document.getElementById('dcWarning');
    const tcpFail = !tcp.success && tcp.error;
    const tlsFail = tls.success === false;
    const showWarn = r.checker_info && r.checker_info.ip && (tcpFail || (tcp.success && tlsFail && r.overall_status === 'unhealthy'));

    if (showWarn) {
        const ci = r.checker_info;
        const loc = [ci.city, ci.country].filter(Boolean).join(', ');
        let titleKey, textKey;
        if (tcpFail && tcp.error.toLowerCase().includes('refused')) {
            titleKey = 'dc_warning_title'; textKey = 'dc_warning_text';
        } else if (tcpFail) {
            titleKey = 'dc_warning_title_timeout'; textKey = 'dc_warning_text_timeout';
        } else {
            titleKey = 'dc_warning_title_tls'; textKey = 'dc_warning_text_tls';
        }
        const msg = t(textKey).replace('{ip}', ci.ip).replace('{location}', loc);
        dcWarn.innerHTML = `<span class="warn-icon">&#9888;</span><span class="warn-text"><strong>${t(titleKey)}</strong><br>${msg}</span>`;
        dcWarn.classList.remove('hidden');
    } else {
        dcWarn.classList.add('hidden');
    }

    renderInfoGrid(document.getElementById('serverInfoGrid'), r.server_info);
    renderInfoGrid(document.getElementById('checkerInfoGrid'), r.checker_info);
    renderTlsCert(r);
    renderStability(r);
    renderDpi(r);
    renderDns(r);

    const fpBody = document.getElementById('fpBody');
    const fpCard = document.getElementById('fpCard');
    if (!r.fingerprints || r.fingerprints.length === 0) { fpCard.classList.add('hidden'); return; }
    fpCard.classList.remove('hidden');
    fpBody.innerHTML = r.fingerprints.map(fp => {
        const name = fp.client_name.replace(/_/g, ' ');
        const icon = fp.success ? 'icon-ok' : 'icon-fail';
        const dur = fp.duration_ms ? fp.duration_ms + ' ' + t('ms') : '—';
        let errText = '';
        if (fp.error) {
            let short = fp.error.replace(/\[Errno \d+\]\s*/g, '').split(';')[0].trim();
            if (short.length > 40) short = short.substring(0, 40) + '...';
            errText = ` <span class="rtt">(${esc(short)})</span>`;
        }
        return `<tr><td>${esc(name)}</td><td>${t('mode_' + fp.mode)}</td><td><span class="${icon}"></span>${errText}</td><td>${dur}</td></tr>`;
    }).join('');
}

let currentCheckId = null;

document.getElementById('shareBtn').addEventListener('click', () => {
    if (!currentCheckId) return;
    const url = `${location.origin}/result/${currentCheckId}`;
    copyText(url).then(() => {
        const btn = document.getElementById('shareBtn');
        const span = btn.querySelector('span');
        btn.classList.add('copied');
        span.textContent = t('share_copied');
        setTimeout(() => { btn.classList.remove('copied'); span.textContent = t('share_btn'); }, 2000);
    });
});

function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text);
    }
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    return Promise.resolve();
}

(async function loadSharedResult() {
    const m = location.pathname.match(/^\/result\/([a-f0-9-]+)$/);
    if (!m) return;
    const checkId = m[1];
    try {
        const res = await fetch(`/api/result/${checkId}`);
        if (!res.ok) return;
        const data = await res.json();
        if (data.results) {
            input.value = data.proxy_link || '';
            currentCheckId = checkId;
            renderResults(data.results);
        }
    } catch (_) {}
})();

function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
