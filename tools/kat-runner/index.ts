// Dev-only npm script entry: `npm run -w @elabify/core kat:run`.
// All logic lives in src/cli/runKat.ts so the shipped CLI's `kat-run`
// subcommand and this dev runner share one implementation.

import { runKat } from '../../src/cli/runKat.js';

const result = runKat();
process.exit(result.failures === 0 ? 0 : 1);
