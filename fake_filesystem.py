# fake_filesystem.py

# Fake directory structure
FAKE_FS = {
    "/": ["bin", "etc", "home", "var"],
    "/home": ["admin"],
    "/home/admin": ["notes.txt", ".bash_history"],
    "/etc": ["passwd", "shadow"]
}

# Fake file contents
FILE_CONTENTS = {
    "/home/admin/notes.txt": "TODO: rotate SSH keys",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash",
    "/etc/shadow": "Permission denied"
}