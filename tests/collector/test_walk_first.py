"""The web roots' walk visits a pack's version folders first (plan A.2,
decision 7): a walk cut short by its entry limit, by a busy upload folder,
still has every version folder it found, and says so."""

import gzip
import io
import json
import os
from pathlib import Path

from test_modules import FixtureRoot, load_collector, records_named, settings


def web_settings(first=None):
    value = json.loads(settings(["unusual_files"]))
    value["web_roots"] = ["/var/www"]
    if first is not None:
        value["web_first"] = first
    return json.dumps(value)


class WalkFirstTests(FixtureRoot):
    def site(self, uploads=60):
        # Uploads first, in both name and creation order, so a plain walk meets them first.
        for n in range(uploads):
            self.write(f"var/www/html/redcap/edocs/{n % 6}/upload{n}.pdf", b"%PDF")
        for version in ("17.3.9", "17.3.10"):
            for n in range(3):
                self.write(f"var/www/html/redcap/redcap_v{version}/Classes/F{n}.php", b"<?php")
        self.write("var/www/html/redcap/index.php", b"<?php")

    def run_walk(self, first=None, limit=None):
        collector = load_collector(self.root)
        collector.file_capabilities = lambda absolute: ({}, None)
        if limit is not None:
            collector.MAX_WEB_ENTRIES = limit
        out = io.BytesIO()
        collector.main(web_settings(first), out=out)
        records = [json.loads(x) for x in gzip.decompress(out.getvalue()).splitlines()]
        (summary,) = [s for s in records_named(records, "walk_summary") if s["place"] == "/var/www"]
        sent = {r["path"] for r in records_named(records, "web_file")}
        return summary, sent

    def version_files(self, sent):
        return sorted(p for p in sent if "/redcap_v" in p)

    def test_without_patterns_the_walk_and_its_summary_are_as_before(self):
        self.site()
        summary, sent = self.run_walk()
        self.assertTrue(summary["whole"])
        self.assertNotIn("first", summary)
        self.assertEqual(len(self.version_files(sent)), 6)

    def test_a_cut_short_walk_still_has_every_version_folder(self):
        self.site()
        _, plain = self.run_walk(limit=30)
        self.assertEqual(self.version_files(plain), [])  # the uploads used up the walk
        summary, sent = self.run_walk(first=["redcap_v*"], limit=30)
        self.assertFalse(summary["whole"])
        self.assertEqual(summary["truncated_reason"], "entries")
        self.assertEqual(len(self.version_files(sent)), 6)
        self.assertEqual(
            {k: summary["first"][k] for k in ("patterns", "found", "whole")},
            {"patterns": ["redcap_v*"], "found": 2, "whole": True},
        )

    def test_a_walk_cut_short_inside_the_version_folders_says_so(self):
        self.site()
        summary, sent = self.run_walk(first=["redcap_v*"], limit=12)
        self.assertFalse(summary["whole"])
        self.assertFalse(summary["first"]["whole"])

    def test_a_whole_walk_with_patterns_is_whole_both_ways(self):
        self.site(uploads=5)
        summary, sent = self.run_walk(first=["redcap_v*"])
        self.assertTrue(summary["whole"] and summary["first"]["whole"])
        self.assertEqual(len(self.version_files(sent)), 6)

    def test_every_limit_that_lets_the_version_files_through_says_whole(self):
        self.site(uploads=12)
        for limit in range(1, 40):
            summary, sent = self.run_walk(first=["redcap_v*"], limit=limit)
            if summary["first"]["whole"]:
                # Whole: none found yet (the analysis then can't judge), or all of them.
                self.assertIn(summary["first"]["found"], (0, 2), limit)
                if summary["first"]["found"] == 2:
                    self.assertEqual(len(self.version_files(sent)), 6, limit)
            elif len(self.version_files(sent)) == 6 and summary["first"]["found"] == 2:
                # Everything was walked: the summary must not say otherwise.
                self.fail(f"limit {limit}: every version file sent, but not whole")

    def test_an_unreadable_version_folder_isnt_whole(self):
        if os.geteuid() == 0:
            self.skipTest("root reads any folder")
        self.site(uploads=0)
        locked = Path(self.root, "var/www/html/redcap/redcap_v17.3.10")
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o755)
        summary, sent = self.run_walk(first=["redcap_v*"])
        self.assertFalse(summary["first"]["whole"])

    def test_a_second_install_is_found_before_the_uploads_use_up_the_walk(self):
        self.site()
        for n in range(2):
            self.write(f"var/www/html/redcap-uat/redcap_v17.3.9/Classes/F{n}.php", b"<?php")
        _, plain = self.run_walk(limit=80)
        self.assertFalse(any("/redcap-uat/" in p for p in plain))  # missed by a plain walk
        summary, sent = self.run_walk(first=["redcap_v*"], limit=30)
        self.assertFalse(summary["whole"])
        self.assertEqual(sum("/redcap-uat/redcap_v" in p for p in sent), 2)
        self.assertEqual(len(self.version_files(sent)), 8)
        self.assertTrue(summary["first"]["whole"])
        self.assertEqual(summary["first"]["levels_whole"], 3)  # every install near the top

    def test_levels_whole_counts_an_unreadable_folder_near_the_top(self):
        if os.geteuid() == 0:
            self.skipTest("root reads any folder")
        self.site(uploads=0)
        locked = Path(self.root, "var/www/html/other")
        locked.mkdir(parents=True)
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o755)
        summary, _ = self.run_walk(first=["redcap_v*"])
        self.assertEqual(summary["first"]["levels_whole"], 1)  # html/other (level 2) unlisted
        self.assertTrue(summary["whole"])  # the walk's own meaning, unchanged
        self.assertFalse(summary["seen_whole"])  # but an error on the way: not for applications

    def test_web_root_walks_say_their_phase(self):
        self.site(uploads=0)
        summary, _ = self.run_walk(first=["redcap_v*"])
        self.assertEqual(summary["phase"], "web_roots")

    def test_bad_patterns_are_refused(self):
        collector = load_collector(self.root)
        bad_ones = (["../x*"], ["redcap_v"], ["a*b*"], ["x*"] * 21, "redcap_v*", ["redcap_v*\n"])
        for bad in bad_ones:
            value = json.loads(web_settings())
            value["web_first"] = bad
            self.assertTrue(any("web_first" in p for p in collector.settings_problems(value)), bad)
        value = json.loads(web_settings(["redcap_v*"]))
        self.assertEqual(collector.settings_problems(value), [])
