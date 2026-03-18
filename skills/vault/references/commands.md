# Midsummer Vault Command Reference

## vault project

```
vault project create "name"     Create project, init vault, write .vault.toml
vault project list              List all local projects
vault project rename "name"     Rename current project
vault project use "name"        Switch to existing project
vault project delete --yes      Delete vault and project
```

## vault set

```
vault set KEY "value"                    Store in development (default)
vault set KEY "value" --env production   Store in specific environment
vault set KEY "value" --desc "info"      Store with description
vault set --global KEY "value"           Store in global vault (~/.vault/)
```

Flags: `--env`, `--global`, `--desc`, `--rotate`

## vault rename

```
vault rename OLD_NAME NEW_NAME           Rename a secret
vault rename OLD NEW --env production    Rename in specific environment
vault rename OLD NEW --global            Rename in global vault
```

Flags: `--env`, `--global` (NO --desc flag — use vault describe separately)

## vault describe

```
vault describe KEY "description"         Add/update description, creates .vault/docs/KEY.md
```

## vault run

```
vault run -- npm start                   Inject development secrets
vault run --env production -- npm start  Inject production secrets
```

## vault list

```
vault list                    List development secret names
vault list -v                 List with descriptions
vault list --all              List project + global
vault list --env production   List production secrets
vault list --global           List global vault
vault list --remote           List from remote server
```

## vault env

```
vault env                     Generate .env.local from vault
vault env --format json       Output as JSON
vault env --format shell      Output as export statements
vault env --stdout            Print to stdout instead of file
```

## vault init

```
vault init                           Create vault with key file
vault init --passphrase "pw"         Create vault with passphrase (no key file)
vault init --global                  Create global vault at ~/.vault/
```

## Passphrase Mode

No key file to lose. Key derived via Argon2id:

```
vault init --passphrase "password"
VAULT_PASSPHRASE="password" vault run -- npm start
```

CI/CD: set `VAULT_PASSPHRASE` env var.

## CI/CD

```yaml
env:
  VAULT_KEY: ${{ secrets.VAULT_KEY }}
steps:
  - run: vault run -- npm test
```
