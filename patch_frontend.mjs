import fs from 'fs';
let text = fs.readFileSync('c:/Users/Daniel/Desktop/valhala/public/apuestas.html', 'utf8');

// The replacement for the fight card
text = text.replace(
  /<div class="fight-card">/g,
  '<div class="fight-card" style="position:relative;">\n              ${f.status === \\\'closed\\\' ? \\\'<div style="position:absolute; inset:0; background:rgba(0,0,0,0.75); z-index:10; display:flex; align-items:center; justify-content:center; border-radius:16px; pointer-events:all; cursor:not-allowed;"><span style="font-family:\\\\\\\'Teko\\\\\\\',sans-serif; font-size:3.5rem; color:#ff4444; font-weight:bold; border:4px solid #ff4444; padding:5px 25px; border-radius:12px; transform:rotate(-15deg); box-shadow:0 0 20px rgba(255,68,68,0.5); text-shadow:0 0 10px rgba(255,68,68,0.5); letter-spacing:2px;">CERRADA</span></div>\\\' : \\\'\\\'}'
);

fs.writeFileSync('c:/Users/Daniel/Desktop/valhala/public/apuestas.html', text);
console.log('Patched apuestas.html');
