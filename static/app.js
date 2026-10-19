    let currentJobId = null;
    let pollInterval = null;
    let allResults = [];
    let filteredResults = [];
    let sortState = { column: null, asc: true };
    let activeFilter = 'all';
    let activeRequested = false;
    let permRequested = false;

    const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    const SOURCES = ['crt.sh','HackerTarget','AlienVault','RapidDNS','URLScan','ThreatCrowd','Wayback','Anubis','BufferOver','CertSpotter','ThreatMiner','SubdomainCenter','SecurityTrails','Shodan','c99'];

    function toggleAdvanced() {
      const p = document.getElementById('advancedPanel');
      const c = document.getElementById('advChevron');
      const open = !p.classList.toggle('hidden');
      c.textContent = open ? '▾' : '▸';
      const btn = document.getElementById('advToggleBtn');
      if (btn) btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    }

    function toggleActive() {
      const on = document.getElementById('activeToggle').checked;
      document.getElementById('activeOptions').classList.toggle('hidden', !on);
    }

    function statusBadge(status) {
      switch (status) {
        case 'running': return '<span class="text-yellow-400 animate-pulse">🔄 Running</span>';
        case 'done': return '<span class="text-green-400">✅ Done</span>';
        case 'error': return '<span class="text-red-400">❌ Error</span>';
        default: return '<span class="text-gray-500">⏳ Pending</span>';
      }
    }

    async function startScan() {
      const input = document.getElementById('domainInput');
      const domain = input.value.trim().toLowerCase();
      const err = document.getElementById('domainError');
      if (!DOMAIN_RE.test(domain)) {
        err.classList.remove('hidden');
        return;
      }
      err.classList.add('hidden');

      const body = { domain };
      const st = document.getElementById('stKey').value.trim();
      const sh = document.getElementById('shodanKey').value.trim();
      const c99 = document.getElementById('c99Key').value.trim();
      if (st) body.securitytrails_key = st;
      if (sh) body.shodan_key = sh;
      if (c99) body.c99_key = c99;

      // Active DNS discovery (fields omitted entirely when active is off, so
      // the request is byte-for-byte the passive-only shape).
      const activeOn = document.getElementById('activeToggle').checked;
      const permOn = document.getElementById('permToggle').checked;
      activeRequested = activeOn;
      permRequested = activeOn && permOn;
      if (activeOn) {
        body.active = true;
        if (permOn) body.permutations = true;
        const wl = document.getElementById('wordlistInput').value;
        if (wl && wl.trim()) {
          body.wordlist = wl;
          body.wordlist_mode = document.getElementById('wordlistMode').value;
        }
      }

      document.getElementById('startBtn').disabled = true;
      document.getElementById('resultsPanel').classList.add('hidden');
      document.getElementById('progressPanel').classList.remove('hidden');
      renderSourceTable({});
      updateProgress(0, 0);

      try {
        const resp = await fetch('/api/enumerate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        if (!resp.ok) {
          const e = await resp.json().catch(() => ({}));
          throw new Error(e.detail || 'Request failed');
        }
        const data = await resp.json();
        currentJobId = data.job_id;
        pollInterval = setInterval(pollStatus, 2000);
        pollStatus();
      } catch (e) {
        alert('Failed to start scan: ' + e.message);
        document.getElementById('startBtn').disabled = false;
        document.getElementById('progressPanel').classList.add('hidden');
      }
    }

    function updateProgress(pct, found) {
      document.getElementById('progressBar').style.width = pct + '%';
      document.getElementById('progressText').textContent = `Discovered ${found} subdomains so far`;
    }

    function renderSourceTable(statuses) {
      const tbody = document.getElementById('sourceTable');
      // Base passive sources, plus the active phases when active was requested
      // (and the server has registered them). statusBadge returns a fixed
      // whitelist of strings; source names are from the known-constant lists.
      const rows = SOURCES.slice();
      if (activeRequested || 'bruteforce' in statuses) rows.push('bruteforce');
      if (permRequested || 'permutation' in statuses) rows.push('permutation');
      const labels = { bruteforce: 'Brute-force (active)', permutation: 'Permutation (active)' };
      tbody.innerHTML = rows.map(s => {
        const st = statuses[s] || 'pending';
        const name = labels[s] || s;
        return `<tr class="border-b border-gray-800/60"><td class="py-2">${name}</td><td class="py-2">${statusBadge(st)}</td></tr>`;
      }).join('');
    }

    function renderNotes(notes) {
      const box = document.getElementById('scanNotes');
      if (!box) return;
      const list = Array.isArray(notes) ? notes : [];
      box.innerHTML = '';
      if (!list.length) { box.classList.add('hidden'); return; }
      box.classList.remove('hidden');
      list.forEach(n => {
        const p = document.createElement('p');
        p.textContent = n;  // textContent → no HTML interpolation of server data
        box.appendChild(p);
      });
    }

    async function pollStatus() {
      if (!currentJobId) return;
      try {
        const resp = await fetch(`/api/status/${currentJobId}`);
        if (!resp.ok) return;
        const data = await resp.json();
        updateProgress(data.progress, data.subdomains_found);
        renderSourceTable(data.source_statuses || {});
        renderNotes(data.notes);

        if (data.status === 'done') {
          clearInterval(pollInterval);
          pollInterval = null;
          await loadResults();
        } else if (data.status === 'error') {
          clearInterval(pollInterval);
          pollInterval = null;
          alert('Scan failed: ' + (data.error || 'unknown error'));
          document.getElementById('startBtn').disabled = false;
        }
      } catch (e) {
        // transient; keep polling
      }
    }

    async function loadResults() {
      const resp = await fetch(`/api/results/${currentJobId}`);
      if (!resp.ok) {
        alert('Failed to load results');
        document.getElementById('startBtn').disabled = false;
        return;
      }
      const data = await resp.json();
      displayResults(data);
    }

    function displayResults(data) {
      allResults = data.subdomains || [];
      document.getElementById('progressPanel').classList.add('hidden');
      document.getElementById('resultsPanel').classList.remove('hidden');
      document.getElementById('startBtn').disabled = false;
      document.getElementById('resultDomain').textContent = data.domain;

      document.getElementById('cardTotal').textContent = data.total;
      document.getElementById('cardAlive').textContent = data.alive;
      document.getElementById('cardVulnerable').textContent = data.vulnerable || 0;
      document.getElementById('cardHigh').textContent = data.high_risk;
      document.getElementById('cardVerify').textContent = data.verify || 0;
      document.getElementById('cardMedium').textContent = data.medium_risk;

      const total = data.total || 1;
      const high = data.high_risk;
      const verify = data.verify || 0;
      const medium = data.medium_risk;
      const none = Math.max(0, data.total - high - verify - medium);
      document.getElementById('barHigh').style.width = (100 * high / total) + '%';
      document.getElementById('barVerify').style.width = (100 * verify / total) + '%';
      document.getElementById('barMedium').style.width = (100 * medium / total) + '%';
      document.getElementById('barNone').style.width = (100 * none / total) + '%';

      activeFilter = 'all';
      setActiveFilterButton();
      applyFilters();
    }

    function setActiveFilterButton() {
      document.querySelectorAll('.filter-btn').forEach(btn => {
        if (btn.dataset.filter === activeFilter) {
          btn.className = 'filter-btn bg-brand-600 text-white px-3 py-1.5 rounded-lg text-sm';
        } else {
          btn.className = 'filter-btn bg-gray-800 text-gray-300 px-3 py-1.5 rounded-lg text-sm';
        }
      });
    }

    document.getElementById('filterBtns').addEventListener('click', (e) => {
      const btn = e.target.closest('.filter-btn');
      if (!btn) return;
      activeFilter = btn.dataset.filter;
      setActiveFilterButton();
      applyFilters();
    });

    function applyFilters() {
      const search = document.getElementById('searchInput').value.trim().toLowerCase();
      filteredResults = allResults.filter(r => {
        if (search && !r.subdomain.toLowerCase().includes(search)) return false;
        switch (activeFilter) {
          case 'alive': return r.alive;
          case 'vulnerable': return r.takeover_verdict === 'VULNERABLE';
          case 'high': return r.takeover_risk === 'HIGH';
          case 'verify': return r.takeover_risk === 'VERIFY';
          case 'medium': return r.takeover_risk === 'MEDIUM';
          case 'unresolved': return !r.resolved;
          default: return true;
        }
      });
      if (sortState.column) applySort();
      renderTable();
    }

    function sortResults(column) {
      if (sortState.column === column) {
        sortState.asc = !sortState.asc;
      } else {
        sortState.column = column;
        sortState.asc = true;
      }
      applySort();
      renderTable();
    }

    function applySort() {
      const col = sortState.column;
      const dir = sortState.asc ? 1 : -1;
      const riskOrder = { HIGH: 4, VERIFY: 3, MEDIUM: 2, LOW: 1, NONE: 0 };
      filteredResults.sort((a, b) => {
        let va = a[col], vb = b[col];
        if (col === 'takeover_risk') { va = riskOrder[va] ?? 0; vb = riskOrder[vb] ?? 0; }
        if (col === 'alive') { va = va ? 1 : 0; vb = vb ? 1 : 0; }
        if (va == null) va = -Infinity;
        if (vb == null) vb = -Infinity;
        if (typeof va === 'string') return va.localeCompare(vb) * dir;
        return (va - vb) * dir;
      });
    }

    function riskBadge(risk) {
      // Whitelist the risk value before it reaches innerHTML. takeover_risk is
      // a server-controlled enum today, but data on this page originates from
      // attacker-poisonable third-party cert logs, so never trust it raw.
      const label = (risk === 'HIGH' || risk === 'VERIFY' || risk === 'MEDIUM' || risk === 'LOW' || risk === 'NONE')
        ? risk : 'NONE';
      // Fixed Tailwind classes per label (no raw interpolation). VERIFY sits
      // between MEDIUM and HIGH and uses an amber badge; it also needs dark
      // text for contrast against the lighter amber background.
      let cls = 'bg-gray-500';
      let text = 'text-white';
      if (label === 'HIGH') cls = 'bg-red-500';
      else if (label === 'VERIFY') { cls = 'bg-amber-500'; text = 'text-black'; }
      else if (label === 'MEDIUM') cls = 'bg-orange-500';
      return `<span class="${cls} ${text} text-xs font-semibold px-2 py-0.5 rounded">${label}</span>`;
    }

    function verdictBadge(v) {
      // Active-verification verdict. Like riskBadge, whitelist the value before
      // it reaches innerHTML — this data derives from attacker-poisonable
      // third-party sources, so never trust it raw. Any value outside the
      // fixed whitelist (including '') renders blank.
      if (v === 'VULNERABLE') {
        return `<span class="bg-red-600 text-white text-xs font-semibold px-2 py-0.5 rounded">Vulnerable</span>`;
      }
      if (v === 'NOT_VULNERABLE') {
        return `<span class="bg-emerald-600 text-white text-xs font-semibold px-2 py-0.5 rounded">Not vulnerable</span>`;
      }
      if (v === 'INCONCLUSIVE') {
        return `<span class="bg-gray-600 text-white text-xs font-semibold px-2 py-0.5 rounded">Inconclusive</span>`;
      }
      return '';
    }

    function statusCell(v) {
      // Coerce HTTP status codes to integers before injecting into the DOM so
      // only a number (or an em dash) can ever reach innerHTML.
      return Number.isInteger(v) ? v : '—';
    }

    // Fixed whitelist of record types rendered in the per-subdomain Records
    // panel, in display order. Mirrors the backend DNS_RECORD_TYPES.
    const DNS_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA'];

    function dnsRecordsPanel(records) {
      // Build the Records detail body. EVERY value from r.dns_records is
      // attacker-poisonable (third-party cert logs / DNS answers), so each one
      // is escapeHtml-ed before it reaches innerHTML — never innerHTML of raw
      // server data. The record-type labels come from the fixed whitelist, not
      // from server data.
      const data = (records && typeof records === 'object') ? records : {};
      const rows = [];
      const types = DNS_RECORD_TYPES.concat(
        Object.keys(data).filter(t => DNS_RECORD_TYPES.indexOf(t) === -1)
      );
      for (const t of types) {
        const values = Array.isArray(data[t]) ? data[t] : [];
        if (!values.length) continue;
        const items = values.map(v => escapeHtml(String(v))).join('<br>');
        rows.push(
          `<div class="flex gap-3 py-0.5">
            <span class="w-12 shrink-0 font-semibold text-brand-300">${escapeHtml(t)}</span>
            <span class="text-gray-300 font-mono text-xs break-all">${items}</span>
          </div>`
        );
      }
      if (!rows.length) {
        return '<span class="text-gray-500 text-xs">No DNS records found.</span>';
      }
      return rows.join('');
    }

    function toggleRecords(idx) {
      const row = document.getElementById('recrow-' + idx);
      const tri = document.getElementById('rectri-' + idx);
      if (!row) return;
      const hidden = row.classList.toggle('hidden');
      if (tri) tri.textContent = hidden ? '▸' : '▾';
    }

    function escapeHtml(s) {
      return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }

    function sourceChips(sources) {
      // Build chips ONLY from a fixed JS whitelist keyed on known active-source
      // tags; nothing from server data is interpolated into the markup, so this
      // stays XSS-safe. The textual source list itself is escapeHtml-ed below.
      const list = Array.isArray(sources) ? sources : [];
      let html = '';
      if (list.includes('bruteforce')) {
        html += ' <span class="bg-amber-500 text-black text-[10px] font-semibold px-1.5 py-0.5 rounded">BF</span>';
      }
      if (list.includes('permutation')) {
        html += ' <span class="bg-violet-500 text-white text-[10px] font-semibold px-1.5 py-0.5 rounded">PERM</span>';
      }
      return html;
    }

    function renderTable() {
      const tbody = document.getElementById('resultsTable');
      const empty = document.getElementById('emptyRow');
      if (!filteredResults.length) {
        tbody.innerHTML = '';
        empty.classList.remove('hidden');
        return;
      }
      empty.classList.add('hidden');
      tbody.innerHTML = filteredResults.map((r, idx) => {
        const dot = r.alive
          ? '<span class="text-green-400">●</span>'
          : '<span class="text-gray-600">●</span>';
        const title = r.takeover_detail ? ` title="${escapeHtml(r.takeover_detail)}"` : '';
        // Verdict evidence surfaced on hover, escapeHtml-ed so hostile evidence
        // text stays inert (never innerHTML of raw server data).
        const verdictTitle = r.takeover_evidence ? ` title="${escapeHtml(r.takeover_evidence)}"` : '';
        // Full CNAME chain (additive JSON from the backend) is surfaced as a
        // title attribute, joined with ' -> ' and escapeHtml-ed so hostile
        // chain entries stay inert; the cell text keeps the single-cname value.
        const chain = Array.isArray(r.cname_chain) ? r.cname_chain : [];
        const cnameTitle = chain.length > 1 ? ` title="${escapeHtml(chain.join(' -> '))}"` : '';
        // Per-subdomain Records affordance: a small ▸ toggle that reveals a
        // detail row listing all DNS record types. The panel body is built by
        // dnsRecordsPanel, which escapeHtml-es every server value.
        const recordsPanel = dnsRecordsPanel(r.dns_records);
        // PART 4: recommended_action is server data (derived from verdict), so
        // it is escapeHtml-ed before reaching innerHTML. Shown only when set.
        const recAction = r.recommended_action
          ? `<div class="mt-2 text-xs"><span class="font-semibold text-amber-300">Recommended action:</span>
              <span class="text-gray-300">${escapeHtml(String(r.recommended_action))}</span></div>`
          : '';
        return `<tr class="border-b border-gray-800/60 animate-fadein hover:bg-gray-800/40">
          <td class="sticky-col py-2 px-3 font-mono text-brand-300 whitespace-nowrap">
            <button type="button" data-rec="${idx}" title="Show all DNS records"
              class="mr-1 text-gray-500 hover:text-brand-300 focus:outline-none" aria-label="Toggle DNS records">
              <span id="rectri-${idx}">▸</span>
            </button>${escapeHtml(r.subdomain)}</td>
          <td class="py-2 px-3 text-gray-400 font-mono text-xs whitespace-nowrap">${escapeHtml((r.ip_addresses||[]).join(', ')) || '—'}</td>
          <td class="py-2 px-3 text-gray-400 font-mono text-xs whitespace-nowrap"${cnameTitle}>${escapeHtml(r.cname || '') || '—'}</td>
          <td class="py-2 px-3 text-gray-400 font-mono text-xs whitespace-nowrap">${escapeHtml(r.dns_status || '') || '—'}</td>
          <td class="py-2 px-3 whitespace-nowrap">${statusCell(r.http_status)}</td>
          <td class="py-2 px-3 whitespace-nowrap">${statusCell(r.https_status)}</td>
          <td class="py-2 px-3 text-gray-500 text-xs whitespace-nowrap">${escapeHtml((r.sources||[]).join(', '))}${sourceChips(r.sources)}</td>
          <td class="py-2 px-3 whitespace-nowrap">
            <span${title}>${riskBadge(r.takeover_risk)}</span><span class="ml-1"${verdictTitle}>${verdictBadge(r.takeover_verdict)}</span>
          </td>
          <td class="py-2 px-3 text-center whitespace-nowrap">${dot}</td>
        </tr>
        <tr id="recrow-${idx}" class="hidden bg-gray-900/60 border-b border-gray-800/60">
          <td colspan="9" class="py-2 px-6">
            <div class="text-xs text-gray-400 mb-1 font-semibold">DNS records</div>
            ${recordsPanel}
            ${recAction}
          </td>
        </tr>`;
      }).join('');
    }

    function cancelScan() {
      if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
      currentJobId = null;
      document.getElementById('progressPanel').classList.add('hidden');
      document.getElementById('startBtn').disabled = false;
    }

    function downloadCSV() {
      if (currentJobId) window.open(`/api/download/${currentJobId}`);
    }

    // --- Lookalike Domains mode -------------------------------------------
    // Separate state from the subdomain scan above so switching modes never
    // mutates the other mode's DOM or data. Drives the FEAT-001 endpoints:
    //   POST /api/lookalike {domain, check_whois}
    //   GET  /api/lookalike/status/{id}  -> candidates_generated/checked/registered_count
    //   GET  /api/lookalike/results/{id} -> {domain, candidates:[...], summary:{...}}
    //   GET  /api/lookalike/download/{id}
    let lookalikeJobId = null;
    let lookalikePollInterval = null;
    let lookalikeResults = [];
    let lookalikeFilteredResults = [];
    let lookalikeSort = { column: null, asc: true };
    let lookalikeFilter = 'all';

    function switchMode(mode) {
      // Toggle visibility of the two mode containers and the active-tab
      // styling. No container's inner state is touched, so each mode keeps its
      // DOM. Subdomains stays the default when mode is anything unexpected.
      const sub = document.getElementById('subdomainMode');
      const look = document.getElementById('lookalikeMode');
      const subBtn = document.getElementById('modeSubdomains');
      const lookBtn = document.getElementById('modeLookalike');
      const active = 'px-5 py-2 rounded-lg text-sm font-semibold bg-brand-600 text-white';
      const inactive = 'px-5 py-2 rounded-lg text-sm font-semibold bg-transparent text-gray-300';
      if (mode === 'lookalike') {
        sub.classList.add('hidden');
        look.classList.remove('hidden');
        lookBtn.className = active;
        subBtn.className = inactive;
        lookBtn.setAttribute('aria-selected', 'true');
        subBtn.setAttribute('aria-selected', 'false');
      } else {
        look.classList.add('hidden');
        sub.classList.remove('hidden');
        subBtn.className = active;
        lookBtn.className = inactive;
        subBtn.setAttribute('aria-selected', 'true');
        lookBtn.setAttribute('aria-selected', 'false');
      }
    }

    async function startLookalike() {
      const input = document.getElementById('lookalikeDomainInput');
      const domain = input.value.trim().toLowerCase();
      const err = document.getElementById('lookalikeDomainError');
      if (!DOMAIN_RE.test(domain)) {
        err.classList.remove('hidden');
        return;
      }
      err.classList.add('hidden');

      const check_whois = document.getElementById('lookalikeWhois').checked;
      const body = { domain, check_whois };

      document.getElementById('findLookalikesBtn').disabled = true;
      document.getElementById('lookalikeResultsPanel').classList.add('hidden');
      document.getElementById('lookalikeProgressPanel').classList.remove('hidden');
      updateLookalikeProgress(0, 0, 0, 0);

      try {
        const resp = await fetch('/api/lookalike', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        if (!resp.ok) {
          const e = await resp.json().catch(() => ({}));
          throw new Error(e.detail || 'Request failed');
        }
        const data = await resp.json();
        lookalikeJobId = data.job_id;
        lookalikePollInterval = setInterval(pollLookalikeStatus, 2000);
        pollLookalikeStatus();
      } catch (e) {
        alert('Failed to start lookalike scan: ' + e.message);
        document.getElementById('findLookalikesBtn').disabled = false;
        document.getElementById('lookalikeProgressPanel').classList.add('hidden');
      }
    }

    function updateLookalikeProgress(pct, generated, checked, registered) {
      document.getElementById('lookalikeProgressBar').style.width = pct + '%';
      document.getElementById('lookalikeProgressText').textContent =
        `${generated} candidates generated, ${checked} checked, ${registered} registered`;
    }

    async function pollLookalikeStatus() {
      if (!lookalikeJobId) return;
      try {
        const resp = await fetch(`/api/lookalike/status/${lookalikeJobId}`);
        if (!resp.ok) return;
        const data = await resp.json();
        updateLookalikeProgress(
          data.progress || 0,
          data.candidates_generated || 0,
          data.candidates_checked || 0,
          data.registered_count || 0
        );

        if (data.status === 'done') {
          clearInterval(lookalikePollInterval);
          lookalikePollInterval = null;
          await loadLookalikeResults();
        } else if (data.status === 'error') {
          clearInterval(lookalikePollInterval);
          lookalikePollInterval = null;
          alert('Lookalike scan failed: ' + (data.error || 'unknown error'));
          document.getElementById('findLookalikesBtn').disabled = false;
        }
      } catch (e) {
        // transient; keep polling
      }
    }

    async function loadLookalikeResults() {
      const resp = await fetch(`/api/lookalike/results/${lookalikeJobId}`);
      if (!resp.ok) {
        alert('Failed to load lookalike results');
        document.getElementById('findLookalikesBtn').disabled = false;
        return;
      }
      const data = await resp.json();
      displayLookalikeResults(data);
    }

    function displayLookalikeResults(data) {
      lookalikeResults = data.candidates || [];
      document.getElementById('lookalikeProgressPanel').classList.add('hidden');
      document.getElementById('lookalikeResultsPanel').classList.remove('hidden');
      document.getElementById('findLookalikesBtn').disabled = false;
      document.getElementById('lookalikeResultDomain').textContent = data.domain || '';

      const summary = data.summary || {};
      document.getElementById('lookalikeCardTotal').textContent = summary.total || 0;
      document.getElementById('lookalikeCardLive').textContent =
        summary.registered != null ? summary.registered : (summary.live || 0);
      document.getElementById('lookalikeCardHigh').textContent = summary.high || 0;
      document.getElementById('lookalikeCardAvailable').textContent = summary.available || 0;

      lookalikeFilter = 'all';
      setLookalikeFilterButton();
      applyLookalikeFilters();
    }

    function setLookalikeFilterButton() {
      document.querySelectorAll('.lookalike-filter-btn').forEach(btn => {
        if (btn.dataset.filter === lookalikeFilter) {
          btn.className = 'lookalike-filter-btn bg-brand-600 text-white px-3 py-1.5 rounded-lg text-sm';
        } else {
          btn.className = 'lookalike-filter-btn bg-gray-800 text-gray-300 px-3 py-1.5 rounded-lg text-sm';
        }
      });
    }

    function applyLookalikeFilters() {
      const search = document.getElementById('lookalikeSearchInput').value.trim().toLowerCase();
      lookalikeFilteredResults = lookalikeResults.filter(r => {
        if (search && !String(r.candidate || '').toLowerCase().includes(search)) return false;
        switch (lookalikeFilter) {
          case 'live': return r.registered === true || Number.isInteger(r.http_status) || Number.isInteger(r.https_status);
          case 'high': return r.risk === 'HIGH';
          case 'medium': return r.risk === 'MEDIUM';
          case 'available': return r.risk === 'AVAILABLE';
          default: return true;
        }
      });
      if (lookalikeSort.column) applyLookalikeSort();
      renderLookalikeTable();
    }

    function sortLookalikeResults(column) {
      if (lookalikeSort.column === column) {
        lookalikeSort.asc = !lookalikeSort.asc;
      } else {
        lookalikeSort.column = column;
        lookalikeSort.asc = true;
      }
      applyLookalikeSort();
      renderLookalikeTable();
    }

    function applyLookalikeSort() {
      const col = lookalikeSort.column;
      const dir = lookalikeSort.asc ? 1 : -1;
      const riskOrder = { HIGH: 4, MEDIUM: 3, LOW: 2, AVAILABLE: 1, NONE: 0 };
      lookalikeFilteredResults.sort((a, b) => {
        let va = a[col], vb = b[col];
        if (col === 'risk') { va = riskOrder[va] ?? 0; vb = riskOrder[vb] ?? 0; }
        if (va == null) va = -Infinity;
        if (vb == null) vb = -Infinity;
        if (typeof va === 'string') return va.localeCompare(vb) * dir;
        return (va - vb) * dir;
      });
    }

    function lookalikeRiskBadge(risk) {
      // Whitelist the risk enum before it reaches innerHTML. Values come from
      // the backend score_lookalike(), but are whitelisted here as defense in
      // depth (never trust server data raw). AVAILABLE uses a distinct sky/info
      // color to stand apart from the HIGH/MEDIUM/LOW scale.
      const label = (risk === 'HIGH' || risk === 'MEDIUM' || risk === 'LOW'
        || risk === 'AVAILABLE' || risk === 'NONE') ? risk : 'NONE';
      let cls = 'bg-gray-500';
      let text = 'text-white';
      if (label === 'HIGH') cls = 'bg-red-500';
      else if (label === 'MEDIUM') { cls = 'bg-amber-500'; text = 'text-black'; }
      else if (label === 'LOW') cls = 'bg-gray-600';
      else if (label === 'AVAILABLE') cls = 'bg-sky-500';
      return `<span class="${cls} ${text} text-xs font-semibold px-2 py-0.5 rounded">${label}</span>`;
    }

    function registeredCell(v) {
      // registered is True | False | 'unknown' from the backend. Render a fixed
      // label from a whitelist so no raw server value reaches innerHTML.
      if (v === true) return '<span class="text-amber-400">Yes</span>';
      if (v === false) return '<span class="text-emerald-400">No</span>';
      return '<span class="text-gray-500">—</span>';
    }

    function renderLookalikeTable() {
      const tbody = document.getElementById('lookalikeResultsTable');
      const empty = document.getElementById('lookalikeEmptyRow');
      if (!lookalikeFilteredResults.length) {
        tbody.innerHTML = '';
        empty.classList.remove('hidden');
        return;
      }
      empty.classList.add('hidden');
      tbody.innerHTML = lookalikeFilteredResults.map((r) => {
        // Every candidate/page_title/registrar/technique value is attacker-
        // influenced (generated from or fetched about an arbitrary domain), so
        // each is escapeHtml-ed before reaching innerHTML. http/https statuses
        // are coerced to ints via statusCell; risk via the whitelisted badge.
        const mx = r.has_mx ? '<span class="text-amber-400">MX</span>' : '<span class="text-gray-600">—</span>';
        const registrar = r.registrar
          ? ` title="${escapeHtml(String(r.registrar))}"`
          : '';
        return `<tr class="border-b border-gray-800/60 animate-fadein hover:bg-gray-800/40">
          <td class="sticky-col py-2 px-3 font-mono text-brand-300 whitespace-nowrap">${escapeHtml(r.candidate || '')}</td>
          <td class="py-2 px-3 text-gray-400 text-xs whitespace-nowrap">${escapeHtml(r.technique || '') || '—'}</td>
          <td class="py-2 px-3 text-gray-400 font-mono text-xs whitespace-nowrap">${escapeHtml(r.dns_status || '') || '—'}</td>
          <td class="py-2 px-3 whitespace-nowrap">${statusCell(r.http_status)} / ${statusCell(r.https_status)}</td>
          <td class="py-2 px-3 text-gray-400 text-xs max-w-xs truncate">${escapeHtml(r.page_title || '') || '—'}</td>
          <td class="py-2 px-3 text-center whitespace-nowrap">${mx}</td>
          <td class="py-2 px-3 whitespace-nowrap"${registrar}>${registeredCell(r.registered)}</td>
          <td class="py-2 px-3 whitespace-nowrap">${lookalikeRiskBadge(r.risk)}</td>
          <td class="py-2 px-3 text-gray-300 text-xs max-w-xs truncate">${escapeHtml(r.recommended_action || '') || '—'}</td>
        </tr>`;
      }).join('');
    }

    function cancelLookalike() {
      if (lookalikePollInterval) { clearInterval(lookalikePollInterval); lookalikePollInterval = null; }
      lookalikeJobId = null;
      document.getElementById('lookalikeProgressPanel').classList.add('hidden');
      document.getElementById('findLookalikesBtn').disabled = false;
    }

    function downloadLookalikeCSV() {
      if (lookalikeJobId) window.open(`/api/lookalike/download/${lookalikeJobId}`);
    }

    document.getElementById('domainInput').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') startScan();
    });

    // --- Event wiring (CSP-safe) -------------------------------------------
    // The Content-Security-Policy served by the backend uses script-src 'self'
    // with NO 'unsafe-inline', so inline on* handler attributes would be
    // blocked. All interactivity is wired here with addEventListener instead;
    // behavior is identical to the former inline handlers.
    document.getElementById('startBtn').addEventListener('click', startScan);
    document.getElementById('advToggleBtn').addEventListener('click', toggleAdvanced);
    document.getElementById('activeToggle').addEventListener('change', toggleActive);
    document.getElementById('cancelBtn').addEventListener('click', cancelScan);
    document.getElementById('downloadBtn').addEventListener('click', downloadCSV);
    document.getElementById('searchInput').addEventListener('input', applyFilters);

    // Sortable column headers carry a data-sort attribute (formerly an inline
    // onclick="sortResults(...)"). Scoped to #subdomainMode so the lookalike
    // table's own data-sort headers are wired separately below.
    document.querySelectorAll('#subdomainMode th[data-sort]').forEach((th) => {
      // Keyboard accessibility: make the sortable header focusable and act on
      // Enter/Space, mirroring the click behavior (no functional change to how
      // sorting works — just reachable without a mouse).
      th.setAttribute('tabindex', '0');
      th.setAttribute('role', 'button');
      th.addEventListener('click', () => sortResults(th.dataset.sort));
      th.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sortResults(th.dataset.sort); }
      });
    });

    // The per-row "show DNS records" toggle buttons are re-rendered on every
    // table paint, so wire them with event delegation on the table body. Each
    // button carries data-rec="<row index>" (formerly onclick="toggleRecords").
    document.getElementById('resultsTable').addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-rec]');
      if (!btn) return;
      toggleRecords(Number(btn.dataset.rec));
    });

    // --- Lookalike mode wiring (CSP-safe, addEventListener only) -----------
    document.getElementById('modeSubdomains').addEventListener('click', () => switchMode('subdomains'));
    document.getElementById('modeLookalike').addEventListener('click', () => switchMode('lookalike'));
    document.getElementById('findLookalikesBtn').addEventListener('click', startLookalike);
    document.getElementById('lookalikeCancelBtn').addEventListener('click', cancelLookalike);
    document.getElementById('lookalikeDownloadBtn').addEventListener('click', downloadLookalikeCSV);
    document.getElementById('lookalikeSearchInput').addEventListener('input', applyLookalikeFilters);
    document.getElementById('lookalikeDomainInput').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') startLookalike();
    });

    // Lookalike filter buttons via delegation on their container.
    document.getElementById('lookalikeFilterBtns').addEventListener('click', (e) => {
      const btn = e.target.closest('.lookalike-filter-btn');
      if (!btn) return;
      lookalikeFilter = btn.dataset.filter;
      setLookalikeFilterButton();
      applyLookalikeFilters();
    });

    // Lookalike sortable column headers, scoped to #lookalikeMode.
    document.querySelectorAll('#lookalikeMode th[data-sort]').forEach((th) => {
      // Keyboard accessibility: focusable + Enter/Space, mirroring click.
      th.setAttribute('tabindex', '0');
      th.setAttribute('role', 'button');
      th.addEventListener('click', () => sortLookalikeResults(th.dataset.sort));
      th.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sortLookalikeResults(th.dataset.sort); }
      });
    });
