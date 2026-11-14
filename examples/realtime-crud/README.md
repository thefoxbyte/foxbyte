# Realtime todos

A small todo list that shows FoxByte's change feed on a machine you run yourself.

One window writes. Another window, already open, updates as the commit happens. Nothing on the page polls, and nothing refreshes. The write goes through the gateway on port 6432 with an account API key, the same way `psql` does. The page subscribes with the official TypeScript client and a realtime key, which can read that one branch's feed and cannot run SQL.

## What you need

An Enterprise install with the change feed turned on, and Node.js 18 or newer. The steps below assume the engine is already up (`fox start` on Linux) and you are on the machine it listens on.

```bash
fox realtime setup --yes
fox user create you@example.com          # the first account, if you have not made one
fox apikey create you@example.com todos  # the gateway password; shown once
```

Build the client, then this app:

```bash
cd clients/typescript
npm install
npm run build
cd ../../examples/realtime-crud
npm install
```

Create the table through the gateway and publish it. The password is the account key from above, not the realtime key.

```bash
psql "postgresql://dbadmin:<API_KEY>@127.0.0.1:6432/main?sslmode=require" <<'SQL'
CREATE TABLE IF NOT EXISTS public.todos (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  title text NOT NULL,
  done boolean NOT NULL DEFAULT false
);
GRANT SELECT ON public.todos TO db_client;
SQL

fox realtime enable todos
fox realtime key create main --name todos
```

`GRANT SELECT` to `db_client` is required. The feed reads as that role, and `fox realtime enable` refuses a table it cannot read. The app creates the same table on startup if it is missing, and grants it, so you can also start the app once and then run `fox realtime enable todos`.

## Run it

```bash
export FOX_API_KEY=key_...          # account key, used only by this process
export FOX_REALTIME_KEY=rtk_...     # stream-only key, handed to the page
export FOX_BRANCH=main              # optional
npm start
```

Open two tabs on <http://127.0.0.1:8787>. Add `?as=A` and `?as=B` if you want the windows labeled. Add a row in one. It shows up in the other, highlighted, with the event in the log.

A default install serves a self-signed certificate. The page talks to this process over plain HTTP on loopback, and this process forwards only `GET /api/branches/<branch>/realtime` to the engine. The account key stays here. The realtime key is in the page, which is what it is for: it cannot do anything but subscribe to that branch.

To point the client straight at the engine instead, trust the engine's certificate in the browser and set `FOX_DEV_CORS=1` before `fox start`, then subscribe to the `fox-realtime://` string `fox realtime key create` printed. This app does not require that.

## The same change from psql

```bash
psql "postgresql://dbadmin:<API_KEY>@127.0.0.1:6432/main?sslmode=require" \
  -c "INSERT INTO todos (title) VALUES ('from psql')"
```

Both windows update. The feed does not care which client committed.

## Resume after a disconnect

**Disconnect** stores the last commit the feed delivered. Make a change from the other window, or from psql. **Resume from saved position** reconnects with `?since=` that commit, and the missed row arrives. Resume from a commit, not from a single change: that is the position the client keeps.

## Another branch

```bash
fox branch create qa
fox admin grant --branch qa you@example.com
fox realtime enable todos --branch qa
fox realtime key create qa --name todos
```

Stop the app and start it again with `FOX_BRANCH=qa` and the new realtime key. The account key is unchanged. `qa` is a copy of `main` at the moment you branched, and from then on its feed is its own.

A branch left idle is suspended. Subscribing wakes it, and so does `fox realtime enable` on a table. That is the point of the feed: a listener is not told the branch is down.

## Latency

**Measure 50 adds** in the page times fifty inserts. It reports how long after the gateway returned the committed row the row appeared in this window, and how long from sending the write, which includes the commit.

The same measurement without a browser, still through the official client:

```bash
N=50 node measure.mjs
```

That trusts the engine's self-signed certificate for this process (`NODE_TLS_REJECT_UNAUTHORIZED=0`). Do not set that on a process that also talks to anything else.
