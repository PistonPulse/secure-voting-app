// reset.js
const fs = require('fs');
const path = require('path');
console.log('Resetting project data...');
const dataDir = path.join(__dirname, 'data');
// Clear votes
fs.writeFileSync(path.join(dataDir, 'votes.json'), JSON.stringify({}));
console.log('All votes have been cleared.');
// Clear users
fs.writeFileSync(path.join(dataDir, 'users.json'), JSON.stringify([]));
console.log('All users have been cleared.');
console.log('Reset complete. Admin account and standard poll remain.');
