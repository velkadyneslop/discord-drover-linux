#!/usr/bin/env python3
"""Local tests for libdrover.so. Everything stays on 127.0.0.1."""
import base64, os, shutil, socket, subprocess, sys, tempfile, textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# LD_PRELOAD splits on spaces, so preload a copy from a space-free temp path
_libdir = tempfile.mkdtemp(prefix="drover-lib-")
LIB = shutil.copy(os.path.join(ROOT, "libdrover.so"), _libdir)
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("ok   " if cond else "FAIL ") + name + (f"  {detail}" if detail and not cond else ""))
    failures += 0 if cond else 1


def run(code, workdir, *args):
    env = dict(os.environ, LD_PRELOAD=LIB, DROVER_DIR=workdir)
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code), *map(str, args)], env=env,
                          capture_output=True, text=True, timeout=20)


def drain(sock):
    out = []
    sock.settimeout(0.5)
    try:
        while True:
            out.append(sock.recv(70000))
    except socket.timeout:
        return out


def write_ini(d, proxy="", debug=False):
    with open(os.path.join(d, "drover.ini"), "w") as f:
        f.write(f"[drover]\nproxy = {proxy}\n" + ("debug = 1\n" if debug else ""))


def test_udp(d):
    write_ini(d, debug=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    disc = bytes(range(74))

    client = """
        import socket, sys
        port = int(sys.argv[1]); mode = sys.argv[2]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        d = bytes(range(74))
        if mode == "sendto":
            s.sendto(d, ("127.0.0.1", port)); s.sendto(d, ("127.0.0.1", port))
        elif mode == "send":
            s.connect(("127.0.0.1", port)); s.send(d)
        elif mode == "sendmsg":
            s.sendmsg([d[:30], d[30:]], [], 0, ("127.0.0.1", port))
        elif mode == "other-first":
            s.sendto(b"hello", ("127.0.0.1", port)); s.sendto(d, ("127.0.0.1", port))
    """
    r = run(client, d, port, "sendto")
    check("udp sendto: prelude then packet, only once per socket", drain(srv) == [b"\0", b"\1", disc, disc], r.stderr)
    run(client, d, port, "send")
    check("udp connected send: prelude then packet", drain(srv) == [b"\0", b"\1", disc])
    run(client, d, port, "sendmsg")
    check("udp sendmsg (split iovec): prelude then packet", drain(srv) == [b"\0", b"\1", disc])
    run(client, d, port, "other-first")
    check("udp: no prelude when first packet is not 74 bytes", drain(srv) == [b"hello", disc])

    extra = os.urandom(300)
    with open(os.path.join(d, "drover-packet.bin"), "wb") as f:
        f.write(extra)
    run(client, d, port, "send")
    check("udp: drover-packet.bin sent first", drain(srv) == [extra, b"\0", b"\1", disc])
    log = open(os.path.join(d, "drover.log")).read()
    check("debug log written", "voice discovery packet seen" in log)
    srv.close()


def test_auth(d):
    client = """
        import socket, sys
        s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
        req = sys.argv[2].encode().decode("unicode_escape").encode()
        s.send(req); s.send(req); s.close()
    """
    ua = "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) discord/0.0.1 Chrome/130 Electron/33 Safari/537.36"
    connect = f"CONNECT discord.com:443 HTTP/1.1\r\nHost: discord.com:443\r\nProxy-Connection: keep-alive\r\n{ua}\r\n\r\n"
    local = f"GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\n{ua}\r\n\r\n"

    def roundtrip(req):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0)); srv.listen(1)
        p = subprocess.Popen([sys.executable, "-c", textwrap.dedent(client), str(srv.getsockname()[1]),
                              req.encode("unicode_escape").decode()],
                             env=dict(os.environ, LD_PRELOAD=LIB, DROVER_DIR=d))
        c, _ = srv.accept()
        data = b""
        while chunk := c.recv(65536):
            data += chunk
        p.wait(); srv.close()
        return data

    write_ini(d, "http://user:s3cret@127.0.0.1:3128")
    got = roundtrip(connect)
    first, second = got[:len(connect)], got[len(connect):]
    token = base64.b64encode(b"user:s3cret")
    check("auth: first CONNECT carries Proxy-Authorization", b"\r\nProxy-Authorization: Basic " + token + b"\r\n" in first, repr(first))
    check("auth: length preserved and request still well formed",
          len(got) == 2 * len(connect) and first.endswith(b"\r\n\r\n") and b"User-Agent" not in first)
    check("auth: only the first send is rewritten", second == connect.encode())
    check("auth: non-proxy request left alone (no credential leak)", roundtrip(local) == local.encode() * 2)

    write_ini(d, "http://127.0.0.1:3128")
    check("no credentials: CONNECT untouched", roundtrip(connect) == connect.encode() * 2)
    write_ini(d, "socks5://user:s3cret@127.0.0.1:1080")
    check("socks5: CONNECT untouched", roundtrip(connect) == connect.encode() * 2)


def test_argv(d):
    src = os.path.join(d, "args.c")
    with open(src, "w") as f:
        f.write('#include <stdio.h>\nint main(int c,char**v){for(int i=1;i<c;i++)puts(v[i]);return 0;}\n')
    exe, other = os.path.join(d, "Discord"), os.path.join(d, "other")
    subprocess.run(["cc", "-o", exe, src], check=True)
    shutil.copy(exe, other)

    def args(binary, *a):
        env = dict(os.environ, LD_PRELOAD=LIB, DROVER_DIR=d)
        return subprocess.run([binary, *a], env=env, capture_output=True, text=True).stdout.split()

    write_ini(d, "socks5://user:pw@10.0.0.1:1080")
    check("argv: flag inserted for Discord (credentials stripped)",
          args(exe, "--foo") == ["--proxy-server=socks5://10.0.0.1:1080", "--foo"])
    check("argv: child processes untouched", args(exe, "--type=renderer") == ["--type=renderer"])
    check("argv: existing --proxy-server respected", args(exe, "--proxy-server=x") == ["--proxy-server=x"])
    check("argv: other programs untouched", args(other, "--foo") == ["--foo"])
    write_ini(d, "127.0.0.1:8080")
    check("argv: scheme defaults to http", args(exe) == ["--proxy-server=http://127.0.0.1:8080"])
    write_ini(d, "")
    check("argv: direct mode adds nothing", args(exe, "--foo") == ["--foo"])


for t in (test_udp, test_auth, test_argv):
    with tempfile.TemporaryDirectory() as d:
        t(d)
shutil.rmtree(_libdir)
print("\nall tests passed" if not failures else f"\n{failures} FAILED")
sys.exit(1 if failures else 0)
