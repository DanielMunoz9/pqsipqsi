import fs from 'fs';
const rawNames = [
  'Heather Yack', 'Thunder !',
  'Lucifer der vosgronne', 'SAK',
  '𝕽𝐲𝐮𝐮.', 'Fear.',
  'тєηкα', 'Dhaela',
  '丂єρτιмυѕ ƒɢο', 'Musashi',
  'RagnaKurenai', 'Prrox',
  'NeroAggelo', 'Setta rojas (Cejotas)',
  'Artoria', 'Lucent',
  'GULTARD GABANNA', 'REVAN'
];

const roster = JSON.parse(fs.readFileSync('c:/Users/Daniel/Desktop/valhala/players.json', 'utf8'));

function similarity(s1, s2) {
  let longer = s1;
  let shorter = s2;
  if (s1.length < s2.length) { longer = s2; shorter = s1; }
  let longerLength = longer.length;
  if (longerLength == 0) { return 1.0; }
  return (longerLength - editDistance(longer, shorter)) / parseFloat(longerLength);
}

function editDistance(s1, s2) {
  s1 = s1.toLowerCase();
  s2 = s2.toLowerCase();
  let costs = new Array();
  for (let i = 0; i <= s1.length; i++) {
    let lastValue = i;
    for (let j = 0; j <= s2.length; j++) {
      if (i == 0) costs[j] = j;
      else {
        if (j > 0) {
          let newValue = costs[j - 1];
          if (s1.charAt(i - 1) != s2.charAt(j - 1))
            newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
          costs[j - 1] = lastValue;
          lastValue = newValue;
        }
      }
    }
    if (i > 0) costs[s2.length] = lastValue;
  }
  return costs[s2.length];
}

const mappings = {};
for (const n of rawNames) {
  let best = null;
  let bestScore = -1;
  // first try substring match (ignoring case)
  const normN = n.toLowerCase().replace(/[^a-z0-9]/g, '');
  for (const r of roster) {
    const normR = r.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (normR.includes(normN) || normN.includes(normR)) {
      best = r;
      bestScore = 1;
      break;
    }
    let sim = similarity(n, r);
    if (sim > bestScore) {
      bestScore = sim;
      best = r;
    }
  }
  mappings[n] = best;
}

console.log(JSON.stringify(mappings, null, 2));
