const { createRequire } = require('module');

// CRA's Jest 27 must not load the app's legacy Jest 24 jsdom environment.
const fromCRA = createRequire(require.resolve('react-scripts/package.json'));
const fromJest = createRequire(fromCRA.resolve('jest'));
const fromCLI = createRequire(fromJest.resolve('jest-cli'));
const fromConfig = createRequire(fromCLI.resolve('jest-config'));
process.argv.push(`--env=${fromConfig.resolve('jest-environment-jsdom')}`);
require('react-scripts/scripts/test');
