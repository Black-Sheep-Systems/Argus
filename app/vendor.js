// Copies the terminal component and the QR code maker into the screen folder, because the window
// may only load files from renderer/ (nothing from node_modules or the web).
const fs = require('fs');
const path = require('path');
const out = path.join(__dirname, 'renderer', 'vendor');
fs.mkdirSync(out, { recursive: true });
for (const [from, to] of [
  ['@xterm/xterm/lib/xterm.js', 'xterm.js'],
  ['@xterm/xterm/css/xterm.css', 'xterm.css'],
  ['@xterm/addon-fit/lib/addon-fit.js', 'addon-fit.js'],
  ['qrcode-generator', 'qrcode.js'], // its package exports only its main file
]) {
  fs.copyFileSync(require.resolve(from), path.join(out, to));
}
console.log('terminal component and QR code maker copied to renderer/vendor');
