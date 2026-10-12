/** Write the bundled advisories to feed/advisories.json (the feed's source of truth starts from them). */
import { writeFileSync } from 'node:fs';
import { ADVISORIES } from '../src/vulns/advisories.js';
writeFileSync('feed/advisories.json', JSON.stringify(ADVISORIES, null, 2) + '\n');
console.log(`Wrote ${ADVISORIES.length} advisories to feed/advisories.json`);
