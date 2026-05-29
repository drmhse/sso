#!/usr/bin/env node

const { main } = require('./authos-bootstrap/index');

main().catch((error) => {
  console.error(`\nAuthOS bootstrap failed: ${error.message}`);
  process.exitCode = 1;
});
