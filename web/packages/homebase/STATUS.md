# Sign in with Homebase (Ente Photos web): status

## Todd: approve consent

The dev server must be running (see "How to run"). Then:

1. Open **http://localhost:3020/** in your browser.
2. Below the email login, enter `frodo.baggins.demo.rocks` under **Homebase identity** and
   click **Sign in with Homebase**.
3. On frodo: log in with frodo's owner password, then approve **Ente Photos** (it asks for
   one new drive, "Ente Photos", read and write).
4. You land on **Signed in with Homebase**, with frodo's name and avatar,
   **Password: created now**, and a fingerprint (8 hex digits). Note the fingerprint.
5. Reload the page: still signed in, now **Password: found on Homebase**, same fingerprint.
6. Click **Sign out**, then sign in again (steps 2–3; frodo may not ask again):
   **Password: found on Homebase**, and **the fingerprint must match** step 4.
7. Optional: do step 6 in a second browser profile; the fingerprint must still match.

Tell me what you see at each step (and the fingerprints), or any error message.

## What works (checked)

| What                                                                                                           | How it was checked                                                                                           |
| -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| YouAuth start, callback, token exchange, drive key                                                             | Unit tests against an in-memory identity that plays odin-core's side (`session.test.ts`, `fake-identity.ts`) |
| Ente's own app registration (appId, slug `ente-photos`, a new zero-knowledge drive)                            | Unit test of the authorize URL; frodo accepts the request (redirects to its owner login)                     |
| Password file: create, read by uniqueId, encrypted on the drive, a duplicate create refused                    | Live against frodo (`drive.live.test.ts`, on the Immich drive with a test tag, cleaned up)                   |
| First sign-in creates the password; later ones find it; a lost create race reads the winner's                  | Unit tests                                                                                                   |
| Credentials sealed in IndexedDB; sign out deletes them and the sealing key                                     | Unit tests                                                                                                   |
| Login page shows the Homebase form (Photos only); bad identity is refused; the button goes to frodo            | Headless Chrome against the dev server                                                                       |
| A callback that wasn't started in this tab shows the state-mismatch message; its query is dropped from history | Headless Chrome                                                                                              |
| `/homebase` when not signed in goes back to `/`                                                                | Headless Chrome                                                                                              |
| tsc, eslint, prettier, `npm test --workspace ente-homebase`                                                    | All pass                                                                                                     |

## Not checked yet

- **The real consent** (steps above): needs the owner. Until then, the callback has run only
  against the in-memory identity.
- The other error kinds (`denied`, `revoked`, `exchange-failed`, `no-zero-knowledge`,
  `unauthorized`) have messages and are unit-tested in the library, but haven't been seen
  in the browser.

## Not in scope

Ente key setup, the master key, the gallery, the proxy, mobile. A Homebase sign-in never
goes to `/gallery` and never calls Ente's server.

## Design notes

- **Constants** (`constants.ts`): appId `4d8d9eed-…`, slug `ente-photos` (immutable once
  registered), drive alias `0ada68d6…`, password file uniqueId `c7a886cd-…`, fileType 7200.
- **Password**: 32 random bytes, base64url, from `crypto.getRandomValues`. Stored only in the
  password file's `appData.content`, encrypted with the file's key, which is locked with the
  drive key. Never stored on the device; the page shows only the first 8 hex digits of its
  SHA-256.
- **Race**: the file is created with a fixed uniqueId. Odin refuses a second create with
  HTTP 400, `errorCode: existingFileWithUniqueId` (checked live), and the loser reads the
  winner's file. An existing password file is never overwritten.
- **Credentials**: IndexedDB database `ente-homebase`, AES-GCM under a non-extractable key.
  The pending sign-in is in sessionStorage until the callback, then deleted either way.
- **Logs**: only the kind of failure (`YouAuthError(kind)` or `HTTP status`), never error
  details, headers, bodies or the callback query.
- **Login page hook**: `AuthPageConfig.LoginExtra`, an optional component rendered below the
  email form. Only Photos sets it.

## How to run

```sh
# Once: Rust and wasm-pack (installed on this Mac on 2026-10-30)
#   rustup with the wasm32-unknown-unknown target; brew install wasm-pack
cd web
npm run dev:photos-homebase      # http://localhost:3020 (port 3000 is someone else's)
npm test --workspace ente-homebase
HOMEBASE_CREDENTIALS=/Users/todd/src/odin/immich/packages/homebase-client/.credentials.json \
    npm test --workspace ente-homebase   # adds the live drive test against frodo
```
