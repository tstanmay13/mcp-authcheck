# Releasing

Publishing is automated and **token-less**. A GitHub Release triggers
`.github/workflows/release.yml`, which publishes to npm via OIDC Trusted
Publishing (npm trusts this repo+workflow directly) with build provenance.

## One-time setup

On npmjs.com → the `mcp-authcheck` package → **Settings → Trusted Publishers**,
add a GitHub Actions publisher:

| Field | Value |
|-------|-------|
| Organization or user | `tstanmay13` |
| Repository | `mcp-authcheck` |
| Workflow filename | `release.yml` |
| Environment | *(leave blank)* |

After this, no npm token is stored in GitHub or anywhere else.

## Cutting a release

1. Bump the version and commit:
   ```bash
   npm version patch   # or minor / major — updates package.json + tags
   git push --follow-tags
   ```
2. Create the GitHub Release for that tag:
   ```bash
   gh release create "v$(node -p "require('./package.json').version")" \
     --title "v$(node -p "require('./package.json').version")" \
     --generate-notes
   ```
3. The `Release` workflow runs typecheck + tests + build, then
   `npm publish --provenance`. Watch it with `gh run watch`.

## Fallback (if you ever prefer a token over OIDC)

Store a granular npm token as the `NPM_TOKEN` repo secret and add
`env: { NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }} }` to the publish step.
OIDC is preferred — nothing to rotate, and provenance is automatic.
