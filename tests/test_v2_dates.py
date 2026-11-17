"""The optional `dates` sanitizer pack: dates and times in gateway output become <DATE>."""

import pytest

from phiward import sanitize


def san():
    return sanitize.Sanitizer(id_rules=sanitize.load_pack("dates").identifiers)


@pytest.mark.parametrize("line,want", [
    ("-rw-r--r--  1 u  staff  12 Mar  5 14:22 x.txt", "-rw-r--r--  1 u  staff  12 <DATE> x.txt"),
    ("drwxr-xr-x  3 u  staff  96 Mar  5  2024 d", "drwxr-xr-x  3 u  staff  96 <DATE> d"),
    ("dob 1980-02-14", "dob <DATE>"),
    ("seen 03/05/2024 and 3/5/24", "seen <DATE> and <DATE>"),
    ("run 2024-03-05T14:22:01Z ok", "run <DATE> ok"),
    ("on 5 March 2024", "on <DATE>"),
    ("in 2024 we ran 3 jobs", "in 2024 we ran 3 jobs"),
])
def test_dates_are_masked(line, want):
    assert san().clean(line) == want


def test_the_pack_is_off_by_default():
    assert "dates" not in sanitize.DEFAULT_PACKS
