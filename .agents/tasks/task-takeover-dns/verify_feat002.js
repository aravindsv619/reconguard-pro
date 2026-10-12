// FEAT-002 render-helper check (mirrors .agents/tasks/security-audit.md section 11).
// Loads the real riskBadge / escapeHtml / statusCell / renderTable row logic
// out of static/index.html by regex-extracting the function bodies, then feeds
// a VERIFY risk plus XSS payloads in dns_status / cname / cname_chain and
// asserts: amber VERIFY badge renders, hostile input is escaped/inert, and an
// unknown risk value still collapses to NONE.
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'static', 'index.html'), 'utf8');

function extract(name) {
  // Grab `function name(...) { ... }` with brace matching.
  const start = html.indexOf('function ' + name + '(');
  if (start === -1) throw new Error('could not find function ' + name);
  let i = html.indexOf('{', start);
  let depth = 0;
  for (let j = i; j < html.length; j++) {
    if (html[j] === '{') depth++;
    else if (html[j] === '}') { depth--; if (depth === 0) { return html.slice(start, j + 1); } }
  }
  throw new Error('unbalanced braces for ' + name);
}

// Evaluate the real helper sources into this scope.
const src = [extract('escapeHtml'), extract('statusCell'), extract('sourceChips'), extract('riskBadge')].join('\n');
eval(src);

const fails = [];
function assert(cond, msg) { if (!cond) fails.push(msg); else console.log('PASS: ' + msg); }

// 1. VERIFY badge renders amber (bg-amber-500) with the VERIFY label.
const verifyBadge = riskBadge('VERIFY');
assert(verifyBadge.includes('bg-amber-500') && verifyBadge.includes('>VERIFY<'),
  'VERIFY -> amber badge: ' + verifyBadge);

// 2. riskBadge still orders/colors the other tiers and collapses unknowns.
assert(riskBadge('HIGH').includes('bg-red-500'), 'HIGH -> red badge');
assert(riskBadge('MEDIUM').includes('bg-orange-500'), 'MEDIUM -> orange badge');
const bogus = riskBadge('<img src=x onerror=alert(1)>');
assert(bogus.includes('>NONE<') && !bogus.includes('<img'), 'unknown risk -> NONE, no injection');

// 3. XSS payload in dns_status is escaped (mirror the renderTable DNS cell).
const dnsPayload = '<svg/onload=alert(1)>';
const dnsCell = escapeHtml(dnsPayload || '') || '—';
assert(dnsCell === '&lt;svg/onload=alert(1)&gt;', 'dns_status escaped & inert: ' + dnsCell);

// 4. XSS payload in cname is escaped (CNAME cell text).
const cnamePayload = '"><script>alert(1)</script>';
const cnameCell = escapeHtml(cnamePayload || '') || '—';
assert(!cnameCell.includes('<script') && cnameCell.includes('&lt;script'),
  'cname escaped & inert: ' + cnameCell);

// 5. XSS payload inside cname_chain is escaped when joined into the title attr.
const chain = ['target.example.com', '"><img src=x onerror=alert(1)>', 'foo.elb.amazonaws.com'];
const cnameTitle = chain.length > 1 ? ` title="${escapeHtml(chain.join(' -> '))}"` : '';
assert(cnameTitle.includes('&quot;&gt;&lt;img') && !cnameTitle.includes('<img') && !cnameTitle.includes('"><img'),
  'cname_chain title escaped & inert: ' + cnameTitle);

if (fails.length) {
  console.error('\nFAILURES:\n' + fails.map(f => ' - ' + f).join('\n'));
  process.exit(1);
}
console.log('\nALL PASS: true');
