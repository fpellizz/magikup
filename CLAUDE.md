# CLAUDE.md — MagikUp

Web app per backup, restore e transfer di database PostgreSQL (connessione
diretta o tramite tunnel AWS SSM). Dettagli utente in `README.md` e
`docs/MagikUp_User_Manual.html`.

## Stack
- Python + **FastAPI** / uvicorn, template **Jinja2** (`templates/`), asset in `static/`
- **psycopg2** (accesso DB), **boto3** (AWS/SSM), bcrypt + itsdangerous (auth), Fernet (cifratura password)
- Config in file INI unico; deploy Docker / Kubernetes (`kubernetes/`, kustomize base + overlay)
- Versione in `app/__init__.py` (`__version__`)

## Layout di `app/`
| Modulo | Ruolo |
|---|---|
| `main.py` | App FastAPI: route, API REST, WebSocket (`/ws/backup`, restore, transfer), `_execute_schedule` |
| `backup_restore.py` | Wrapper `pg_dump` / `pg_restore`, opzioni, validazione input |
| `privilege_check.py` | Preflight privilegi backup (catalog query, fix SQL mai eseguito) |
| `db_service.py` | Accesso PostgreSQL (database, schemi, ruoli, query editor) |
| `config.py` | Config unificata, endpoint, schedule, cifratura |
| `auth.py` | Utenti, ruoli (Admin/Operator/Viewer), sessioni, rate limiting |
| `scheduler.py`, `cron.py`, `schedule_state.py` | Backup schedulati: tick, parser cron, stato run |
| `email_service.py` | Invio SMTP e notifiche schedule/recovery password |
| `remote_storage.py`, `progress.py` | Push/pull S3 / WebDAV / filebrowser e progresso |
| `aws_service.py`, `ssm_tunnel.py` | AWS e tunnel SSM |
| `operation_logger.py`, `broadcaster.py` | Storico operazioni e streaming output live |

## Test in locale
`pytest.ini` imposta `pythonpath = .`. Sulla macchina non c'è un venv del
progetto e Python 3.14 non ha wheel per `psycopg2-binary`, quindi:
1. venv usa-e-getta (es. nella scratchpad);
2. `pip install` di `requirements.txt` **senza** la riga `psycopg2-binary` + `requirements-dev.txt`;
3. stub locale di `psycopg2` in site-packages (`__init__`, `sql`, `extensions`, `extras`):
   `app/db_service.py` lo importa a livello di modulo;
4. `python -m pytest` dalla root (nessun test tocca un DB reale; `conftest.py` stubba il privilege check).

**Fallimenti noti, non reali:** 2 test in `tests/test_user_email.py` falliscono
in locale perché `conftest.py` non isola `auth.USERS_FILE` (residui in
`config/users.json`); in CI passano.

**Integration test opzionale** `tests/integration/test_privilege_check_pg.py`
(marker `integration`): confronta il privilege check con PostgreSQL + `pg_dump`
reali. Viene saltato (skip) se manca `PG_TEST_DSN` (DSN libpq di un superuser) o
se `psycopg2` non è quello reale; `PG_DUMP` sceglie il binario (default `pg_dump`
nel PATH, senza binario la parte pg_dump viene saltata). Crea e cancella un DB e
dei ruoli usa-e-getta.

## Convenzioni
- Codice, commenti e messaggi di commit in **inglese**; documentazione in italiano (README e manuale utente in inglese/italiano come da file esistenti).
- **Conventional Commits**; semver; mai lavorare su `main` (branch `feature/…`, `fix/…`, `chore/…`).
- Commit/push/PR/bump di versione solo su richiesta; nessuna password o segreto nei file o nei comandi inline.
- Il PDF del manuale si rigenera con `docs/generate_pdf.mjs` dopo ogni modifica all'HTML.
