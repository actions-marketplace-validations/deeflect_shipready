#!/usr/bin/env node
// Launcher: runs the bundled check.py with the system Python 3.10+, passing args and exit code through.
"use strict";
const { spawnSync } = require("child_process");
const path = require("path");

const checkPy = path.join(__dirname, "..", "check.py");
const versionOk = "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)";
const python = ["python3", "python"].find(
  (cmd) => spawnSync(cmd, ["-c", versionOk], { stdio: "ignore" }).status === 0
);

if (!python) {
  console.error("shipready needs Python 3.10 or newer on PATH (python3 or python). Install it from https://www.python.org/downloads/ and run again.");
  process.exit(2);
}

const run = spawnSync(python, [checkPy, ...process.argv.slice(2)], { stdio: "inherit" });
if (run.error) {
  console.error(`shipready could not start ${python}: ${run.error.message}`);
  process.exit(2);
}
process.exit(run.status === null ? 1 : run.status);
