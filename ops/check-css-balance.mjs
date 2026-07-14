import fs from 'fs';
const h = fs.readFileSync('public/album.html', 'utf8');
const s = h.indexOf('<style>');
const e = h.indexOf('</style>', s);
const css = h.slice(s + 7, e);
let d = 0, inC = false, inS = null, line = 1;
const opens = [];
for (let i = 0; i < css.length; i++) {
  const c = css[i], n = css[i + 1];
  if (c === '\n') line++;
  if (inC) { if (c === '*' && n === '/') { inC = false; i++; } continue; }
  if (inS) { if (c === '\\') { i++; continue; } if (c === inS) inS = null; continue; }
  if (c === '/' && n === '*') { inC = true; i++; continue; }
  if (c === '"' || c === "'") { inS = c; continue; }
  if (c === '{') { d++; opens.push(line); }
  else if (c === '}') { d--; opens.pop(); }
}
console.log('finalDepth', d);
if (d !== 0) console.log('unclosed open lines (approx):', opens.slice(-5));
