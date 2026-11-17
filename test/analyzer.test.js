// Run with:  node --test test/
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const readJson = f => JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', f), 'utf8'));
const lists = { keywords: readJson('keywords.json'), brands: readJson('brands.json') };
const PG = {
  config: require('../shared/config.js'),
  domain: require('../shared/domain-utils.js'),
  analyzer: require('../shared/analyzer.js'),
  ai: require('../shared/ai-utils.js'),
  feedback: require('../shared/feedback.js'),
  qr: require('../shared/qr.js'),
  filecheck: require('../shared/filecheck.js'),
  sensitive: require('../shared/sensitive.js'),
  blocklist: require('../shared/blocklist.js'),
  eml: require('../shared/eml.js'),
  scoreboard: require('../shared/scoreboard.js'),
  learnmd: require('../shared/learnmd.js')
};
const samples = require('./samples.js');
const env = { test, assert, PG, lists, samples, qrFixtures: require('./qr-fixtures.js') };

require('./cases.js')(env);
require('./qr-cases.js')(env);
require('./file-cases.js')(env);
require('./reply-cases.js')(env);
require('./intel-cases.js')(env);
require('./score-cases.js')(env);
require('./learn-cases.js')(env);
