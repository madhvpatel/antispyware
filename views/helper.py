import io
import zipfile
import tarfile
from pathlib import Path

def list_archive_members(path: str) -> dict[str, bytes]:
    """
    Given a filesystem path to an archive, return a mapping:
      member_name -> raw_bytes
    Supports .zip, .tar, .tar.gz, .tgz
    """
    ext = Path(path).suffix.lower()
    members = {}

    # ZIP
    if ext == ".zip":
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                # skip directories
                if info.is_dir():
                    continue
                members[info.filename] = z.read(info)

    # TAR / TAR.GZ / TGZ
    elif ext in (".tar", ".tgz") or path.lower().endswith((".tar.gz",)):
        mode = "r:gz" if path.lower().endswith((".tgz", ".tar.gz")) else "r:"
        with tarfile.open(path, mode) as t:
            for member in t.getmembers():
                if member.isreg():  # regular file
                    f = t.extractfile(member)
                    if f:
                        members[member.name] = f.read()

    return members
