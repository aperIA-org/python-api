from app.infrastructure.git.diff_utils import extract_changed_files


def test_extracts_single_file():
    diff = "+++ b/app/auth.py\n@@ -1 +1 @@\n-old\n+new"
    assert extract_changed_files(diff) == ["app/auth.py"]


def test_extracts_multiple_files():
    diff = (
        "+++ b/app/foo.py\n@@\n+x\n"
        "+++ b/lib/bar.ts\n@@\n+y\n"
    )
    assert extract_changed_files(diff) == ["app/foo.py", "lib/bar.ts"]


def test_returns_empty_when_no_files():
    assert extract_changed_files("") == []
    assert extract_changed_files("just some text without diff markers") == []


def test_blocks_path_traversal_with_double_dots():
    diff = "+++ b/../etc/passwd\n+++ b/normal.py"
    assert extract_changed_files(diff) == ["normal.py"]


def test_blocks_path_traversal_in_middle():
    diff = "+++ b/app/../../../etc/shadow\n+++ b/safe.py"
    assert extract_changed_files(diff) == ["safe.py"]


def test_blocks_absolute_paths():
    diff = "+++ b//etc/passwd\n+++ b/relative/file.py"
    assert extract_changed_files(diff) == ["relative/file.py"]


def test_ignores_devnull():
    diff = "+++ b/dev/null"
    assert extract_changed_files(diff) == ["dev/null"]


def test_strips_whitespace():
    diff = "+++ b/  file_with_leading_spaces.py  "
    assert extract_changed_files(diff) == ["file_with_leading_spaces.py"]
