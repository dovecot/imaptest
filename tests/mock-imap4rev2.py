#!/usr/bin/env python3
"""Minimal mock IMAP server for imaptest's IMAP4rev2 short-tagged-reply
coverage. Speaks just enough IMAP for imaptest's stress-mode startup
(banner -> LOGIN -> [ENABLE] -> LIST/SELECT/NOOP/LOGOUT) and emits
short-form tagged replies (tag OK\\r\\n with no resp-text) under one of
two policies:

  compliant   short replies only after ENABLE IMAP4REV2 succeeds.
  rogue       short replies from the first tagged response onward
              (used by the negative test to assert imaptest rejects
              this when IMAP4rev2 is not enabled).

Usage: mock-imap4rev2.py <mode> <port>
"""

import re
import socket
import socketserver
import sys
import threading


CAPABILITY = (
    "IMAP4rev1 IMAP4rev2 ENABLE LITERAL+ AUTH=PLAIN UNSELECT QRESYNC"
)


class Conn(socketserver.BaseRequestHandler):

    def setup(self):
        self.rev2_enabled = False
        self.mode = self.server.mode
        self.rfile = self.request.makefile("rb", buffering=0)
        self.wfile = self.request.makefile("wb", buffering=0)

    def writeln(self, s):
        self.wfile.write(s.encode("latin-1") + b"\r\n")

    def short_allowed(self):
        if self.mode == "rogue":
            return True
        return self.mode == "compliant" and self.rev2_enabled

    def reply_ok(self, tag, code_text=""):
        if self.short_allowed():
            self.writeln(f"{tag} OK")
        elif code_text:
            self.writeln(f"{tag} OK {code_text}")
        else:
            self.writeln(f"{tag} OK done")

    def reply_no(self, tag, text="failed"):
        self.writeln(f"{tag} NO {text}")

    def reply_bad(self, tag, text="bad"):
        self.writeln(f"{tag} BAD {text}")

    def handle(self):
        self.writeln(f"* OK [CAPABILITY {CAPABILITY}] mock ready")
        for raw in self.rfile:
            try:
                line = raw.decode("latin-1").rstrip("\r\n")
            except Exception:
                break
            if not line:
                continue
            m = re.match(r"^(\S+)\s+(\S+)(?:\s+(.*))?$", line)
            if not m:
                continue
            tag, cmd, rest = m.group(1), m.group(2).upper(), (m.group(3) or "")
            if cmd == "CAPABILITY":
                self.writeln(f"* CAPABILITY {CAPABILITY}")
                self.reply_ok(tag, "CAPABILITY done")
            elif cmd == "LOGIN":
                self.reply_ok(tag, "Logged in.")
            elif cmd == "AUTHENTICATE":
                self.reply_no(tag, "AUTHENTICATE not supported by mock")
            elif cmd == "ENABLE":
                up = rest.upper()
                enabled = []
                if "IMAP4REV2" in up:
                    self.rev2_enabled = True
                    enabled.append("IMAP4REV2")
                if "QRESYNC" in up:
                    enabled.append("QRESYNC")
                if enabled:
                    self.writeln("* ENABLED " + " ".join(enabled))
                self.reply_ok(tag, "ENABLE done")
            elif cmd == "LIST":
                self.writeln('* LIST () "/" "INBOX"')
                self.reply_ok(tag, "LIST done")
            elif cmd == "LSUB":
                self.reply_ok(tag, "LSUB done")
            elif cmd in ("SELECT", "EXAMINE"):
                self.writeln("* 0 EXISTS")
                if not self.rev2_enabled:
                    self.writeln("* 0 RECENT")
                self.writeln("* OK [UIDVALIDITY 1] uidvalidity")
                self.writeln("* OK [UIDNEXT 1] uidnext")
                self.writeln(
                    "* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)"
                )
                self.writeln("* OK [PERMANENTFLAGS ()] no permanent flags")
                self.reply_ok(tag, "[READ-WRITE] selected")
            elif cmd in ("UNSELECT", "CLOSE"):
                self.reply_ok(tag, "closed")
            elif cmd in ("NOOP", "CHECK"):
                self.reply_ok(tag, "done")
            elif cmd == "STATUS":
                self.writeln('* STATUS "INBOX" (MESSAGES 0 UIDNEXT 1 UIDVALIDITY 1)')
                self.reply_ok(tag, "STATUS done")
            elif cmd in ("CREATE", "DELETE", "RENAME", "SUBSCRIBE", "UNSUBSCRIBE"):
                self.reply_ok(tag, "done")
            elif cmd in ("FETCH", "SEARCH", "STORE", "COPY", "MOVE", "EXPUNGE",
                         "UID", "APPEND", "REPLACE", "THREAD", "SORT"):
                self.reply_ok(tag, "done")
            elif cmd == "LOGOUT":
                self.writeln("* BYE bye")
                self.reply_ok(tag, "Logout done")
                return
            else:
                self.reply_ok(tag, "done")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: mock-imap4rev2.py <compliant|rogue> <port>\n")
        sys.exit(2)
    mode, port = sys.argv[1], int(sys.argv[2])
    if mode not in ("compliant", "rogue"):
        sys.stderr.write("mode must be compliant or rogue\n")
        sys.exit(2)
    srv = Server(("127.0.0.1", port), Conn)
    srv.mode = mode
    sys.stdout.write(f"mock listening port={port} mode={mode}\n")
    sys.stdout.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
