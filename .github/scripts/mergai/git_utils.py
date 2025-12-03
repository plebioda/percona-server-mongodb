from git import Repo
import hashlib
import difflib
import re
import tempfile

def get_path_hash(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8")).hexdigest()

def github_file_compare_url(owner: str, name: str,
                            base_commit: str, head_commit: str,
                            path: str) -> str:
    """
    Build a GitHub compare URL that scrolls to a single file's diff.
    Uses anchor: #diff-<SHA256(path)>
    """
    # path must be repo-relative, no leading slash – same as from unmerged_blobs()
    anchor = hashlib.sha256(path.encode("utf-8")).hexdigest()
    # You can shorten SHAs if you like; full SHA is also fine
    base = base_commit[:12]
    head = head_commit[:12]

    return f"https://github.com/{owner}/{name}/compare/{base}...{head}#diff-{anchor}"

def get_conflict_metadata(repo: Repo = Repo(".")):

    blobs_map = repo.index.unmerged_blobs()
    metadata = {}
    diffs = {}
    ours_commit = repo.head.commit
    theirs_commit = repo.commit("MERGE_HEAD")
    base_commit = repo.merge_base(ours_commit, theirs_commit)[0]
    files = list(blobs_map.keys()) 

    args = [
        "--cc",
        "-U0", # 0 lines of context
        "--no-color",
    ]

    for file_path in files:
        diff = repo.git.diff(*args + [file_path])

        diffs[file_path] = diff
    

    metadata.update({
        "ours_commit": ours_commit,
        "theirs_commit": theirs_commit,
        "base_commit": base_commit,
        "files": files,
        "diffs": diffs,
    })

    return metadata


def apply_patch_to_file(patch_text: str, repo: Repo = Repo("."), check: bool = False) -> str:
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
        suffix=".patch"
    )

    tmp.write(patch_text)
    tmp.close()

    if check:
        # Just check if the patch can be applied cleanly
        try:
            repo.git.apply("--check", tmp.name)
            return True
        except Exception as e:
            return e
    
    repo.git.apply(tmp.name)

    return True