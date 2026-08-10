import fs from 'fs';
let text = fs.readFileSync('c:/Users/Daniel/Desktop/valhala/bracket_bets_handlers.go', 'utf8');
text = text.replace(
  '"strings"\n',
  '// "strings"\n'
);
text = text.replace(
  'event :=',
  '_ ='
);
fs.writeFileSync('c:/Users/Daniel/Desktop/valhala/bracket_bets_handlers.go', text);
console.log('Fixed compile errors');
