#!/bin/sh
# Regenerates the Dovecot 2.3 fixtures from a disposable container with a
# synthetic passwd-file userdb. Run from this directory on a workstation:
#   sh capture.sh
# Never point it at a real host. Output: maildir.json, slash.json,
# static.json and v24.json, each a list of {argv, stdout, stderr, exit}.
set -eu
IMAGE=docker.io/dovecot/dovecot:2.3.21@sha256:1c18c756f20d03867077a1b509a6e2e3008ab1eafa56377b6f2eca12dc1ba581
IMAGE24=docker.io/dovecot/dovecot:2.4.1@sha256:1296e0f1029cdd95e6849fb82f5d142a6e2a46218451773316cea678de75254b
RUNTIME=$(command -v container || command -v docker)
raw=$(mktemp -d)
trap 'rm -rf "$raw"' EXIT
cat > "$raw/inner.sh" <<'INNER'
#!/bin/sh
set -u
n=0
rec() {
	set_dir=/out/$1
	shift
	[ -d "$set_dir" ] || mkdir -p "$set_dir"
	n=$((n + 1))
	f=$(printf '%s/%02d' "$set_dir" "$n")
	printf '%s\0' "$@" > "$f.argv"
	"$@" > "$f.stdout" 2> "$f.stderr"
	echo $? > "$f.exit"
}
# The detail template Snapshot builds: fixed fields, then the global
# mail_location, then each private \Junk namespace location.
tmpl() {
	printf '%%u\t%%{uid}\t%%{gid}\t%%h\t%%{userdb:mail}\t%%{userdb:mail_plugins}'
	for loc in "$@"; do printf '\t%s' "$loc"; done
}
if [ "${1:-}" = v24 ]; then
	rec v24 dovecot --version
	exit 0
fi
start() {
	doveadm stop >/dev/null 2>&1
	sleep 1
	cp "/tmp/$1.conf" /etc/dovecot/dovecot.conf
	cp "/tmp/$1.users" /etc/dovecot/users 2>/dev/null || true
	dovecot
	sleep 1
}

# Set 1: inbox namespace with prefix INBOX. and separator ., a shared
# namespace, plugins per protocol, users exercising every per-user branch.
cat > /tmp/maildir.conf <<'EOF'
protocols = imap lmtp
listen = *
ssl = no
mail_location = maildir:~/Maildir
mail_plugins = $mail_plugins quota
first_valid_uid = 1000
passdb {
  driver = passwd-file
  args = /etc/dovecot/users
}
userdb {
  driver = passwd-file
  args = /etc/dovecot/users
}
namespace inbox {
  inbox = yes
  separator = .
  prefix = INBOX.
  mailbox Junk {
    special_use = \Junk
    auto = create
  }
  mailbox "Courrier indésirable" {
    special_use = \Junk
    auto = create
  }
  mailbox "Spam & Co" {
    special_use = \Junk
    auto = create
  }
  mailbox Sent {
    special_use = \Sent
  }
}
namespace shared {
  type = shared
  separator = .
  prefix = shared.%%u.
  location = maildir:%%h/Maildir:INDEX=~/Maildir/shared/%%u
  list = children
  mailbox Junk {
    special_use = \Junk
  }
}
protocol lmtp {
  mail_plugins = $mail_plugins sieve
}
EOF
cat > /tmp/maildir.users <<'EOF'
alice@example.com:{PLAIN}x:1000:1000::/srv/vmail/example.com/alice::
bob@example.com:{PLAIN}x:1000:1000::/srv/vmail/example.com/bob::userdb_mail=maildir:~/Mail
carol@example.net:{PLAIN}x:1001:1001::/srv/vmail/example.net/carol::
dave:{PLAIN}x:1002:1002::/home/dave::
erin@example.net:{PLAIN}x:1001:1001::/srv/vmail/example.net/erin::userdb_mail=mdbox:~/mdbox
frank@example.net:{PLAIN}x:1001:1001::/srv/vmail/example.net/frank::userdb_mail=maildir:~/Maildir:LAYOUT=fs
grace@example.com:{PLAIN}x:1000:1000::/srv/vmail/example.com/grace::userdb_mail_plugins=zlib
Henry@Example.COM:{PLAIN}x:1000:1000::/srv/vmail/example.com/henry::
-x@example.com:{PLAIN}x:1000:1000::/srv/vmail/example.com/x::
st*r@example.com:{PLAIN}x:1000:1000::/srv/vmail/example.com/star::
zero@example.com:{PLAIN}x:0:0::/srv/vmail/example.com/zero::
EOF
mkdir -p /srv/vmail/example.com/alice /srv/vmail/example.com/bob /srv/vmail/example.net/carol
chown -R 1000:1000 /srv/vmail
chown -R 1001:1001 /srv/vmail/example.net
start maildir
T=$(tmpl 'maildir:~/Maildir')
rec maildir dovecot --version
rec maildir doveconf -n
rec maildir doveadm user '*'
# Snapshot looks users up in sorted order and never passes st*r, whose name
# doveadm would read as a mask.
rec maildir doveadm user -e "$T" -- -x@example.com Henry@Example.COM alice@example.com bob@example.com carol@example.net dave erin@example.net frank@example.net grace@example.com zero@example.com
# Ground truth for the Junk paths: where Dovecot itself puts each folder.
for u in alice@example.com bob@example.com carol@example.net; do
	for box in INBOX.Junk 'INBOX.Courrier indésirable' 'INBOX.Spam & Co'; do
		rec maildir doveadm mailbox path -u "$u" "$box"
	done
done

# Set 2: separator /, empty prefix, UTF-8 names, mail_home, and a private
# namespace with its own location.
cat > /tmp/slash.conf <<'EOF'
protocols = imap
listen = *
ssl = no
mail_location = maildir:~/Maildir:UTF-8
mail_home = /srv/vmail/%d/%n
mail_uid = vmail
mail_gid = vmail
first_valid_uid = 1000
passdb {
  driver = passwd-file
  args = /etc/dovecot/users
}
userdb {
  driver = passwd-file
  args = /etc/dovecot/users
}
namespace inbox {
  inbox = yes
  separator = /
  prefix =
  mailbox Spam/Sub {
    special_use = \Junk
    auto = create
  }
  mailbox "Pourriel é" {
    special_use = \Junk
    auto = create
  }
}
namespace archive {
  separator = /
  prefix = Archive/
  location = maildir:/srv/archive/%d/%n
  mailbox Junk {
    special_use = \Junk
    auto = create
  }
}
EOF
cat > /tmp/slash.users <<'EOF'
alice@example.com:{PLAIN}x:::::
bob@example.org:{PLAIN}x:::::
EOF
mkdir -p /srv/vmail/example.com/alice /srv/vmail/example.org/bob /srv/archive
chown -R vmail:vmail /srv/vmail /srv/archive
start slash
T=$(tmpl 'maildir:~/Maildir:UTF-8' 'maildir:/srv/archive/%d/%n')
n=0
rec slash dovecot --version
rec slash doveconf -n
rec slash doveadm user '*'
rec slash doveadm user -e "$T" -- alice@example.com bob@example.org
for u in alice@example.com bob@example.org; do
	for box in Spam/Sub 'Pourriel é' Archive/Junk; do
		rec slash doveadm mailbox path -u "$u" "$box"
	done
done

# Set 3: a userdb that cannot iterate users.
cat > /tmp/static.conf <<'EOF'
protocols = imap
listen = *
ssl = no
mail_location = maildir:~/Maildir
passdb {
  driver = static
  args = password=x
}
userdb {
  driver = static
  args = uid=1000 gid=1000 home=/srv/static/%u
}
EOF
start static
n=0
rec static dovecot --version
rec static doveconf -n
rec static doveadm user '*'
doveadm stop >/dev/null 2>&1
INNER
chmod 755 "$raw/inner.sh"
mkdir -p "$raw/out/v24"
"$RUNTIME" run --rm --platform linux/amd64 -v "$raw:/cap" -v "$raw/out:/out" "$IMAGE" /cap/inner.sh
"$RUNTIME" run --rm --platform linux/amd64 -v "$raw:/cap" -v "$raw/out:/out" "$IMAGE24" /cap/inner.sh v24
python3 -I - "$raw/out" "$PWD" "$IMAGE" "$IMAGE24" <<'PY'
import json, os, re, sys
src, dst, image, image24 = sys.argv[1:5]
for name in sorted(os.listdir(src)):
    d = os.path.join(src, name)
    cmds = []
    for f in sorted(x for x in os.listdir(d) if x.endswith(".argv")):
        base = os.path.join(d, f[:-5])
        argv = open(base + ".argv", "rb").read().split(b"\0")[:-1]
        out = open(base + ".stdout", "rb").read().decode()
        # The container's random hostname is the only host-specific value.
        out = re.sub(r"(?m)^# Hostname: .*$", "# Hostname: mail.example.com", out)
        cmds.append({
            "argv": [a.decode() for a in argv],
            "stdout": out,
            "stderr": open(base + ".stderr", "rb").read().decode(),
            "exit": int(open(base + ".exit").read()),
        })
    with open(os.path.join(dst, name + ".json"), "w") as fh:
        json.dump({"image": image24 if name == "v24" else image, "commands": cmds}, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
PY
