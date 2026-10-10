
function cp(s){ return Array.from(s); }
function cnt(s, c){ return s.split(c).length - 1; }

function extract(url){
  const full = url.includes('://') ? url : 'http://' + url;
  const i = full.indexOf('://');
  const scheme = full.slice(0, i).toLowerCase();
  const rest = full.slice(i + 3);
  let e = rest.search(/[\/?#]/);
  const netloc = e === -1 ? rest : rest.slice(0, e);
  let rem = e === -1 ? '' : rest.slice(e);
  const h = rem.indexOf('#'); if (h !== -1) rem = rem.slice(0, h);
  const q = rem.indexOf('?');
  const path = q === -1 ? rem : rem.slice(0, q);
  const query = q === -1 ? '' : rem.slice(q + 1);
  const host = netloc.toLowerCase();
  const f = {};
  const chars = cp(url);
  f.url_length = chars.length;
  f.hostname_length = cp(host).length;
  f.path_length = cp(path).length;
  f.num_subdomains = cnt(host, '.');
  f.uses_https = scheme === 'https' ? 1 : 0;
  f.has_ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(host.split(':')[0]) ? 1 : 0;
  f.num_special_chars = ['-', '_', '@', '%'].reduce((a, c) => a + cnt(url, c), 0);
  f.num_digits = chars.filter(c => /\p{Nd}/u.test(c)).length;
  let ent = 0;
  if (chars.length > 0) {
    const m = {}; chars.forEach(c => m[c] = (m[c] || 0) + 1);
    for (const k in m) { const p = m[k] / chars.length; ent -= p * Math.log2(p); }
  }
  f.entropy = ent;
  const low = url.toLowerCase();
  f.keyword_count = ['login','verify','secure','account','update','signin','bank'].filter(k => low.includes(k)).length;
  f.is_shortened = ['bit.ly','tinyurl','goo.gl','t.co','ow.ly'].some(s => host.includes(s)) ? 1 : 0;
  f.num_query_params = cnt(query, '=');
  f.has_at_symbol = url.includes('@') ? 1 : 0;
  f.num_dots = cnt(url, '.');
  f.tld_length = host.includes('.') ? cp(host.split('.').pop()).length : 0;
  const nonAscii = cp(host).some(c => c.codePointAt(0) > 127);
  f.has_non_ascii = nonAscii ? 1 : 0;
  f.is_punycode_needed = nonAscii ? 1 : 0;
  return f;
}

function score(url, model){
  const f = extract(url);
  if (f.has_non_ascii || f.is_punycode_needed) return 0.95;   // lookalike-character rule
  const x = model.features.map(n => f[n]);
  let total = 0;
  for (const t of model.trees) {
    let n = 0;
    while (t.l[n] !== -1) n = x[t.f[n]] <= t.t[n] ? t.l[n] : t.r[n];
    total += t.p[n];
  }
  return Math.round(total / model.trees.length * 10000) / 10000;
}
if (typeof module !== 'undefined') module.exports = { score };
