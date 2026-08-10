import fs from 'fs';
let text = fs.readFileSync('c:/Users/Daniel/Desktop/valhala/bracket_bets_handlers.go', 'utf8');
text = text.replace(
  "SELECT fight_id, division, label, fighter_a, fighter_b, status FROM bet_fights WHERE status = 'open'",
  "SELECT fight_id, division, label, fighter_a, fighter_b, status FROM bet_fights WHERE status = 'open' OR status = 'closed' ORDER BY created_at DESC"
);
fs.writeFileSync('c:/Users/Daniel/Desktop/valhala/bracket_bets_handlers.go', text);
console.log('Replaced query in bracket_bets_handlers.go');
