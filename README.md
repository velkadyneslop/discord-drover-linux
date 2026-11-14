# discord-drover-linux

A Linux port of [Discord Drover](https://github.com/hdrover/discord-drover) for the
Discord Flatpak (`com.discordapp.Discord`).

It is a small library loaded into Discord that:

- **Fixes blocked voice chat without a proxy ("direct mode").** Just before Discord's
  first voice packet on each connection, it sends two 1-byte junk packets and waits
  50 ms. On networks that block Discord voice by inspecting traffic, this is often
  enough for calls and screen sharing to connect.
- **Optionally forces Discord through a proxy** (HTTP or SOCKS5) for everything except
  voice: chat, login, voice signalling.
- **Supports HTTP proxies with a login and password**, which Discord cannot do by itself.

Nothing is installed system-wide and no root is needed. It only affects Discord.

## Requirements

- Discord installed as a Flatpak: `flatpak install flathub com.discordapp.Discord`
- A C compiler and `make` (`sudo dnf install gcc make` on Fedora)

## Install

```sh
./drover install                            # direct mode: voice fix only
./drover install socks5://127.0.0.1:1080    # or: with a proxy
```

Then quit Discord completely (from the tray icon) and start it again.

## Commands

| Command | What it does |
|---|---|
| `./drover install [PROXY]` | Build, install and enable. Run again after changing the source. |
| `./drover proxy PROXY` / `./drover proxy none` | Change or remove the proxy. |
| `./drover debug on` / `off` | Log what the library does to `drover.log`. |
| `./drover status` | Show whether it is enabled and how it is configured. |
| `./drover uninstall` | Disable it and remove its files. |

Changes take effect the next time Discord starts.

Proxy format: `[http|socks5]://[login:password@]host:port`. Logins only work with HTTP
proxies; Discord cannot authenticate to SOCKS5 proxies.

To target another build, set `DROVER_APP`, e.g.
`DROVER_APP=com.discordapp.DiscordCanary ./drover install`.

## Files

Everything lives in `~/.var/app/com.discordapp.Discord/drover/`:

- `libdrover.so`: the library.
- `drover.ini`: settings (same format as upstream).

  ```ini
  [drover]
  proxy = socks5://127.0.0.1:1080
  debug = 0
  ```
- `drover-packet.bin` (optional): if present, its contents are sent before the two junk
  packets on each new voice connection. It is re-read every time, so it can be swapped
  while Discord is running. Try this if direct mode alone stops working; upstream ships
  an example in its `dist` folder.
- `drover.log`: written only when debug is on. A working voice connection logs
  `voice discovery packet seen; sent prelude`.

## Checking that it works

```sh
./drover debug on      # then restart Discord and join a voice channel
tail ~/.var/app/com.discordapp.Discord/drover/drover.log
```

## How it works

- The library is loaded through `ZYPAK_LD_PRELOAD`, set with `flatpak override --user`.
  (The Flatpak's launcher, zypak, replaces a plain `LD_PRELOAD`.)
- zypak also removes the preload variable before Discord starts its child processes, so
  the library hooks `execvp`/`execve` and puts itself back when Discord re-executes
  itself. Voice runs in the renderer process, so this step is essential.
- It hooks `socket`, `send`, `sendto`, `sendmsg` and `sendmmsg` to spot the first packet
  on each UDP socket. If that packet is 74 bytes (Discord's voice IP-discovery packet),
  the prelude is sent first.
- With a proxy set, it adds `--proxy-server=…` to the main Discord process's arguments.
- With an HTTP proxy login, it rewrites the first request on each proxy connection,
  replacing the `User-Agent` header with a `Proxy-Authorization` header of the same length.

## Differences from upstream

- No fake `version.dll`; injection uses the preload mechanism above.
- No conversion of HTTP `CONNECT` to SOCKS5. Upstream needs it for Discord's separate
  updater, which the Flatpak disables.
- `drover.ini` has an extra `debug` setting.

## Limitations

- Only the Flathub Flatpak has been tested. The library itself is not Flatpak-specific,
  but the `drover` script is.
- Proxy mode and proxy logins pass the local tests but have not been tried against a
  real proxy.
- It only helps against blocks that inspect traffic. If Discord's addresses are blocked
  outright, a proxy or VPN is needed.
- It adds no privacy: your network can still see that you are using Discord.
- Vesktop and Discord in a browser handle voice differently and are not supported.

## Tests

```sh
make test
```

Runs entirely on `127.0.0.1`: checks the UDP prelude, the proxy login rewrite and the
argument injection.

## Credits

Based on the behaviour of [hdrover/discord-drover](https://github.com/hdrover/discord-drover)
for Windows.
