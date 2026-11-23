"""The planted values of the leak test (tests/test_leak_typical.py), and the made-up project they
are planted in. Every value is made up; they live in the tests only.

Each value has a kind, from the label of the rule that masks it:
- identifier: a rule of a pack that masks subjects (msk, dates), the user pattern, the pack file;
- detail: genomics `<BAMFILE>` and `<READ>` (masked in output, sent in a prompt);
- position: genomics positions and numbers (text mode only);
- entry: the name of an entry under the root (masked by the gateway's inventory only).

`needs` names what masks it: a built-in pack, `pattern` (the user's `[sanitize] patterns`) or
`packfile` (the made-up pack file). A value is checked only in a config that has it; a value that
is also an entry name counts as an entry in a config without its rule. A built-in rule needs at
least one value here (`test_each_built_in_rule_masks_a_planted_value`).
"""

from typing import Dict, FrozenSet, NamedTuple, Optional, Tuple

ROOT, PROJECT, PROMPT = "root", "project", "prompt"


class Plant(NamedTuple):
    value: str
    kind: str  # identifier, detail, position
    needs: str  # genomics, msk, dates, pattern, packfile
    places: Tuple[str, ...]  # root, project, prompt
    column: str = ""  # in cohort.csv: "id" (an identifier column) or "other"
    entry: bool = False  # also an entry name under the root

    def kind_in(self, features: FrozenSet[str]) -> Optional[str]:
        """Its kind under a config with `features`, or None when nothing there masks it."""
        if self.needs in features:
            return self.kind
        return "entry" if self.entry else None


def _p(value, kind, needs, *places, column="", entry=False):
    return Plant(value, kind, needs, tuple(places), column, entry)


PLANTS = [
    # genomics <BAMFILE>
    _p("FAKECANARY7.sorted.bam", "detail", "genomics", ROOT),
    _p("lane_9.fastq.gz", "detail", "genomics", ROOT, PROMPT),
    _p("FAKECALLS.VCF.GZ", "detail", "genomics", ROOT),
    _p("fake9.csi", "detail", "genomics", ROOT),
    # genomics <READ>
    _p("A00123:45:HFAKECXX:1:1101:12345:6789", "detail", "genomics", ROOT),
    _p("A00123:45:HFAKECXX:1:1101:12345:6789/1", "detail", "genomics", ROOT),
    _p("A00123:45:HFAKECXX:2:2201:100:200_ACGTACGT", "detail", "genomics", ROOT),
    _p("HWUSI-EAS100R:6:73:941:1973#0/1", "detail", "genomics", ROOT),
    _p("m54012_190101_000000/12345/ccs", "detail", "genomics", ROOT),
    # genomics positions and numbers
    _p("chr7:55249071", "position", "genomics", ROOT, PROMPT),
    _p("chr2:1,234,567-1,300,000", "position", "genomics", ROOT),
    _p("chrX 12345", "position", "genomics", ROOT),
    _p("1_1234_A_C", "position", "genomics", ROOT),
    _p("chr7-55249071-C-T", "position", "genomics", ROOT),
    _p("1\t1234567", "position", "genomics", ROOT),
    _p("12,345,678", "position", "genomics", ROOT),
    _p("9876543", "position", "genomics", ROOT),
    _p("chr12:25398284", "position", "genomics", PROJECT),
    # numbers in cohort.csv: in an identifier column, and in other columns (kept by --table)
    _p("8899001", "position", "genomics", ROOT, column="id"),
    _p("4455667", "position", "genomics", ROOT, column="other"),
    _p("7577120", "position", "genomics", ROOT, column="other"),
    _p("2233445", "position", "genomics", ROOT, column="other"),
    _p("6677889", "position", "genomics", ROOT, column="other"),
    # msk
    _p("P-9990001-T01-IM6", "identifier", "msk", PROMPT),
    _p("P-9990002", "identifier", "msk", ROOT, column="id"),
    _p("C-FAKE01-L001-d", "identifier", "msk", ROOT, column="id"),
    _p("s_C_FAKE01_P001_d", "identifier", "msk", ROOT),
    _p("ZZ999999-T", "identifier", "msk", ROOT),
    _p("DonorFake-7", "identifier", "msk", ROOT),
    # dates
    _p("2024-03-05", "identifier", "dates", ROOT),
    _p("2024-03-05T14:22:01Z", "identifier", "dates", ROOT),
    _p("20240305T1422", "identifier", "dates", ROOT),
    _p("03/05/2024", "identifier", "dates", ROOT),
    _p("05.03.2024", "identifier", "dates", ROOT),
    _p("5 March 2024", "identifier", "dates", ROOT),
    _p("Mar 5, 2024", "identifier", "dates", ROOT),
    _p("Mar  5 14:22", "identifier", "dates", ROOT),
    # the user pattern; each is also the name of a patient's folder under the root
    _p("FAKE-PT-0001", "identifier", "pattern", ROOT, column="id", entry=True),
    _p("FAKE-PT-0002", "identifier", "pattern", ROOT, column="id", entry=True),
    _p("FAKE-PT-0003", "identifier", "pattern", ROOT, PROMPT, entry=True),
    _p("FAKE-PT-0004", "identifier", "pattern", ROOT, column="id", entry=True),
    _p("FAKE-PT-0005", "identifier", "pattern", ROOT, column="id", entry=True),
    # the pack file; ZQ-777001 sits in the project (the step-3 plant)
    _p("ZQ-777001", "identifier", "packfile", PROJECT),
    _p("ZQ-777002", "identifier", "packfile", ROOT, PROMPT, column="id"),
    _p("ZQ-777003", "identifier", "packfile", ROOT),
]
BY_VALUE: Dict[str, Plant] = {p.value: p for p in PLANTS}

# what stands in a value's place in the control project (no plant left): a CSV cell keeps its
# kind, so the table still reads as one
NEUTRAL = {"FAKE-PT-0001": "case-a", "FAKE-PT-0002": "case-b", "FAKE-PT-0003": "case-c",
           "FAKE-PT-0004": "case-d", "FAKE-PT-0005": "case-e",
           "4455667": "42", "7577120": "43", "2233445": "44", "6677889": "45"}


def neutral(value: str) -> str:
    return NEUTRAL.get(value, "plain")


# the files of the made-up project; «VALUE» marks a plant
COHORT = """patient_id,sample_id,age,chrom,pos,gene,vaf
«FAKE-PT-0001»,«P-9990002»,61,7,«4455667»,EGFR,0.31
«FAKE-PT-0002»,«C-FAKE01-L001-d»,55,12,«7577120»,KRAS,0.12
«FAKE-PT-0004»,«ZQ-777002»,47,17,«2233445»,TP53,0.40
«FAKE-PT-0005»,«8899001»,39,2,«6677889»,ALK,0.05
"""
RUN_LOG = """start «FAKE-PT-0001» on «2024-03-05»
ERROR read «A00123:45:HFAKECXX:1:1101:12345:6789» failed
mate «A00123:45:HFAKECXX:1:1101:12345:6789/1»
umi «A00123:45:HFAKECXX:2:2201:100:200_ACGTACGT»
old «HWUSI-EAS100R:6:73:941:1973#0/1»
movie «m54012_190101_000000/12345/ccs»
wrote «FAKECANARY7.sorted.bam» and «lane_9.fastq.gz»
index «fake9.csi» for «FAKECALLS.VCF.GZ»
region «chr7:55249071»
range «chr2:1,234,567-1,300,000»
low «chrX 12345»
variants «1_1234_A_C» and «chr7-55249071-C-T»
«1\t1234567»\tlow
total «12,345,678» reads, «9876543» kept
dates «2024-03-05T14:22:01Z» «20240305T1422» «03/05/2024»
dates «05.03.2024» «5 March 2024» «Mar 5, 2024»
listed «Mar  5 14:22»
samples «s_C_FAKE01_P001_d» «ZZ999999-T» «DonorFake-7»
study «ZQ-777003»
done
"""
CALLS = "##fileformat=VCFv4.2\n#CHROM\tPOS\tID\tREF\tALT\n"
NOTES = "# Notes\n\nStudy «ZQ-777001» looks at «chr12:25398284» (KRAS) first.\n"
README = "# Cohort analysis\n\nCounts per gene, from the cohort table.\n"
ANALYSIS = '''import csv
import sys

rows = list(csv.DictReader(open(sys.argv[1])))
print("rows:", len(rows))
print("genes:", len({r["gene"] for r in rows}))
print("first:", ",".join(rows[0].values()))
'''
# the user's own rules, and their made-up examples (not planted values: the agent can read the
# config)
PATTERN = r"FAKE-PT-\d{4} => <SUBJECT>"
PACK_RULE = r"ZQ-\d{6} => <STUDYID>"
EXAMPLES = ("FAKE-PT-0009", "ZQ-777009")
FULL = frozenset({"genomics", "msk", "dates", "pattern", "packfile", "table"})
DEFAULT = frozenset({"genomics"})  # the gateway's default pack; no table mode
