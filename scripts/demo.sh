#!/usr/bin/env bash
# A 60-second guided demo: grade a clean server, a server with a real gap, and
# a public server. Run `npm run build` first. Record with:
#   asciinema rec docs/demo.cast -c scripts/demo.sh
set -euo pipefail
CLI="node $(dirname "$0")/../dist/cli.js"

say() { printf "\n\033[1;36m$ %s\033[0m\n" "$*"; }

say "npx mcp-authcheck https://mcp.linear.app/mcp    # a clean, conformant server"
$CLI https://mcp.linear.app/mcp || true
sleep 1

say "npx mcp-authcheck https://mcp.intercom.com/mcp  # challenges for OAuth, serves no PRM"
$CLI https://mcp.intercom.com/mcp || true
sleep 1

say "npx mcp-authcheck https://mcp.deepwiki.com/mcp  # a public server — graded N/A"
$CLI https://mcp.deepwiki.com/mcp || true
