# Proton Mail Bridge
Copyright (c) 2026 Proton AG

This repository holds the Proton Mail Bridge application.
For a detailed build information see [BUILDS](./BUILDS.md).
The license can be found in [LICENSE](./LICENSE) file, for more licensing information see [COPYING_NOTES](./COPYING_NOTES.md).
For contribution policy see [CONTRIBUTING](./CONTRIBUTING.md).


## Description Bridge
Proton Mail Bridge for e-mail clients.

When launched, Bridge will initialize local IMAP/SMTP servers and render 
its GUI.

To configure an e-mail client, first log in using your Proton Mail credentials. 
Open your e-mail client and add a new account using the settings which are 
located in the Bridge GUI. The client will only be able to sync with 
your Proton Mail account when the Bridge is running, thus the option 
to start Bridge on startup is enabled by default.

When the main window is closed, Bridge will continue to run in the
background.

More details [on the public website](https://proton.me/mail/bridge).

## Launcher
The launcher is a binary used to run the Proton Mail Bridge.

The Official distribution of the Proton Mail Bridge application contains
both a launcher and the app itself. The launcher is installed in a protected
area of the system (i.e. an area accessible only with admin privileges) and is
used to run the app. The launcher ensures that nobody tampered with the app's
files by verifying their signature using a hardcoded public key. App files are
placed in regular userspace and are signed by Proton's private key. This
feature enables the app to securely update itself automatically without asking
the user for a password.

## Keychain
You need to have a keychain in order to run Proton Mail Bridge. On Mac or
Windows, Bridge uses native credential managers. On Linux, use `secret-service` freedesktop.org API
(e.g. [Gnome keyring](https://wiki.gnome.org/Projects/GnomeKeyring/))
or
[pass](https://www.passwordstore.org/). We are working on allowing other secret
services (e.g. KeepassXC), but for now only gnome-keyring is usable without
major problems.


## Environment Variables

### Dev build or run
- `APP_VERSION`: set the bridge app version used during testing or building
- `PROTONMAIL_ENV`: when set to `dev` it is not using Sentry to report crashes
- `VERBOSITY`: set log level used during test time and by the makefile

### Integration testing
- `TEST_ENV`: set which env to use (fake or live)
- `TEST_ACCOUNTS`: set JSON file with configured accounts
- `TAGS`: set build tags for tests
- `FEATURES`: set feature dir, file or scenario to test

## Folders

There are now three types of system folders which Bridge recognises:

|        | Windows                             | Mac                                                 | Linux                               | Linux (XDG)                           |
|--------|-------------------------------------|-----------------------------------------------------|-------------------------------------|---------------------------------------|
| config | %APPDATA%\protonmail\bridge-v3      | ~/Library/Application Support/protonmail/bridge-v3  | ~/.config/protonmail/bridge-v3      | $XDG_CONFIG_HOME/protonmail/bridge-v3 |
| cache  | %LOCALAPPDATA%\protonmail\bridge-v3 | ~/Library/Caches/protonmail/bridge-v3               | ~/.cache/protonmail/bridge-v3       | $XDG_CACHE_HOME/protonmail/bridge-v3  |
| data	  | %APPDATA%\protonmail\bridge-v3      | ~/Library/Application Support/protonmail/bridge-v3  | ~/.local/share/protonmail/bridge-v3 | $XDG_DATA_HOME/protonmail/bridge-v3   |
| temp   | %LOCALAPPDATA%\Temp                 | $TMPDIR if non-empty, else /tmp                     | $TMPDIR if non-empty, else /tmp     | $TMPDIR if non-empty, else /tmp       |



## Files

|                        | Base Dir | Path                       |
|------------------------|----------|----------------------------|
| bridge lock file       | cache    | bridge.lock                |
| bridge-gui lock file   | cache    | bridge-gui.lock            |
| vault                  | config   | vault.enc                  |
| gRPC server json       | config   | grpcServerConfig.json      |
| gRPC client json       | config   | grpcClientConfig_<id>.json |
| gRPC Focus server json | config   | grpcFocusServerConfig.json |
| Logs                   | data     | logs                       |
| gluon DB               | data     | gluon/backend/db           |
| gluon messages         | data     | gluon/backend/store        |
| Update files           | data     | updates                    |
| sentry cache           | data     | sentry_cache               |
| Mac/Linux File Socket  | temp     | bridge{4_DIGITS}           |


## Web Admin API

Bridge supports a web administration frontend.

### Start Bridge with Web API

Run Bridge with `--web` and provide root admin credentials:

```bash
BRIDGE_WEB_ADMIN_USER=root \
BRIDGE_WEB_ADMIN_PASS='change-this-password' \
go run ./cmd/Desktop-Bridge --web --web-addr 127.0.0.1:8081
```

### Authentication

- `GET /healthz` is public.
- All `/api/v1/*` routes require HTTP Basic Auth using:
  - `BRIDGE_WEB_ADMIN_USER`
  - `BRIDGE_WEB_ADMIN_PASS`

### Endpoints

- `GET /api/v1/accounts`
- `POST /api/v1/accounts`
- `GET /api/v1/accounts/{id}`
- `POST /api/v1/accounts/{id}/logout`
- `DELETE /api/v1/accounts/{id}`
- `POST /api/v1/accounts/{id}/sync`
- `GET /api/v1/server/mail`
- `PUT /api/v1/server/mail`
- `POST /api/v1/repair`

### Example Requests

List accounts:

```bash
curl -u root:change-this-password \
  http://127.0.0.1:8081/api/v1/accounts
```

Add/login account:

```bash
curl -u root:change-this-password \
  -H 'Content-Type: application/json' \
  -d '{"username":"you@proton.me","password":"your-login-password"}' \
  http://127.0.0.1:8081/api/v1/accounts
```

Update IMAP/SMTP settings:

```bash
curl -u root:change-this-password \
  -X PUT \
  -H 'Content-Type: application/json' \
  -d '{"imapPort":1143,"smtpPort":1025,"useSSLForImap":true,"useSSLForSmtp":true}' \
  http://127.0.0.1:8081/api/v1/server/mail
```

### Docker Notes

The web frontend enforces loopback bind addresses by default, but Docker image defaults override this for container use:

- `BRIDGE_WEB_ALLOW_NON_LOOPBACK=1`
- `BRIDGE_BIND_HOST=0.0.0.0`

This allows published ports (`-p`) to reach the web API and IMAP/SMTP listeners from the host.
