import csv
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import urlscout  # noqa: E402

SHA = "a" * 64
QUIET = dict(log=lambda *a, **k: None)


class InputTests(unittest.TestCase):
    def test_parses_comments_blanks_duplicates_and_invalid(self):
        lines = ["# header\n", "\n", "https://example.com/  # note\n", "example.org\n",
                 "https://example.com/\n", "ftp://x.example/\n", "not a url\n"]
        urls, invalid = urlscout.load_urls(lines)
        self.assertEqual(urls, ["https://example.com/", "http://example.org"])
        self.assertEqual([n for n, _ in invalid], [6, 7])

    def test_fragment_kept(self):
        urls, _ = urlscout.load_urls(["http://example.com/a#frag"])
        self.assertEqual(urls, ["http://example.com/a#frag"])

    def test_refang(self):
        self.assertEqual(urlscout.normalise_url("hxxps://evil[.]example(.)com/x"),
                         "https://evil.example.com/x")
        self.assertEqual(urlscout.normalise_url("hXXp[:]//a[dot]example/"), "http://a.example/")
        self.assertEqual(urlscout.normalise_url("<http://example.com>"), "http://example.com")

    def test_defang_round_trip(self):
        url = "https://login.example.com/path?q=1"
        self.assertEqual(urlscout.defang(url), "hxxps://login[.]example[.]com/path?q=1")
        self.assertEqual(urlscout.normalise_url(urlscout.defang(url)), url)

    def test_internal_detection(self):
        for url in ["http://10.0.0.1/", "http://localhost:8080/", "http://intranet/",
                    "http://wiki.corp/", "http://[::1]/", "http://printer.local/"]:
            self.assertTrue(urlscout.is_internal(url), url)
        for url in ["http://8.8.8.8/", "https://example.com/"]:
            self.assertFalse(urlscout.is_internal(url), url)

    def test_internal_bypass_forms(self):
        for url in ["http://localhost./", "http://intranet./x", "http://wiki.corp./",
                    "http://127.1/", "http://10.0.1/", "http://0177.0.0.1/",
                    "http://0x7f000001/", "http://3232235777/"]:
            self.assertTrue(urlscout.is_internal(url), url)
        # numeric forms of public IPs and hex-looking real domains still count as public
        self.assertFalse(urlscout.is_internal("http://134744072/"))  # 8.8.8.8
        self.assertFalse(urlscout.is_internal("http://deadbeef.cafe/"))

    def test_idn_shown_as_punycode(self):
        self.assertEqual(urlscout.ascii_host("http://g\u043e\u043egle.com/"), "xn--ggle-55da.com")
        self.assertEqual(urlscout.ascii_host("http://example.com/"), "example.com")

    def test_vt_url_id(self):
        self.assertEqual(urlscout.vt_url_id("http://example.com"), "aHR0cDovL2V4YW1wbGUuY29t")


class LookupTests(unittest.TestCase):
    def test_internal_url_makes_no_external_call(self):
        with mock.patch.object(urlscout, "http_json") as http:
            row = urlscout.scan("http://192.168.1.1/", "key", urlscout.Throttle(0), **QUIET)
        http.assert_not_called()
        self.assertEqual(row["scope"], "internal")

    def test_report_mapped(self):
        data = {"data": {"id": SHA, "attributes": {
            "reputation": -7,
            "categories": {"A": "Phishing", "B": "phishing", "C": "malicious"},
            "last_final_url": "https://evil.example/landing",
            "title": "Sign in",
            "last_analysis_date": 1760000000,
            "last_analysis_stats": {"malicious": 5, "suspicious": 1,
                                    "harmless": 50, "undetected": 30}}}}
        with mock.patch.object(urlscout, "http_json", return_value=(200, data)):
            row = urlscout.vt_lookup("https://evil.example/", "key")
        self.assertEqual(row["vt_verdict"], "MALICIOUS")
        self.assertEqual(row["vt_malicious"], 5)
        self.assertEqual(row["vt_reputation"], -7)
        self.assertEqual(row["vt_categories"], "malicious, phishing")
        self.assertEqual(row["vt_link"], urlscout.VT_GUI_URL.format(id=SHA))
        self.assertEqual(row["vt_last_analysis"], "2025-10-09 08:53")

    def test_not_found(self):
        with mock.patch.object(urlscout, "http_json", return_value=(404, None)):
            self.assertEqual(urlscout.vt_lookup("https://new.example/", "key"),
                             {"vt_verdict": "not found"})

    def test_bad_key_stops_run(self):
        with mock.patch.object(urlscout, "http_json", return_value=(401, None)):
            with self.assertRaises(SystemExit):
                urlscout.vt_lookup("https://example.com/", "bad")

    def test_not_found_is_not_submitted_without_flag(self):
        with mock.patch.object(urlscout, "http_json", return_value=(404, None)) as http:
            row = urlscout.scan("https://new.example/", "key", urlscout.Throttle(0), **QUIET)
        self.assertEqual(http.call_count, 1)
        self.assertEqual(row["vt_verdict"], "not found")

    def test_submit_and_poll(self):
        responses = [
            (404, None),
            (200, {"data": {"type": "analysis", "id": "u-abc-123"}}),
            (200, {"data": {"attributes": {"status": "queued"}}}),
            (200, {"data": {"attributes": {"status": "completed",
                                           "stats": {"malicious": 0, "suspicious": 2}}},
                   "meta": {"url_info": {"id": SHA}}}),
        ]
        with mock.patch.object(urlscout, "http_json", side_effect=responses) as http, \
             mock.patch.object(urlscout.time, "sleep"):
            row = urlscout.scan("https://new.example/", "key", urlscout.Throttle(0),
                                submit=True, **QUIET)
        self.assertEqual(http.call_args_list[1].kwargs["form"], {"url": "https://new.example/"})
        self.assertEqual(row["vt_verdict"], "SUSPICIOUS")
        self.assertEqual(row["vt_link"], urlscout.VT_GUI_URL.format(id=SHA))
        self.assertNotIn("status", row)

    def test_rate_limit_retries_once(self):
        calls = []

        def flaky(x):
            calls.append(x)
            if len(calls) == 1:
                raise urlscout.RateLimited()
            return {"ok": True}

        with mock.patch.object(urlscout.time, "sleep"):
            self.assertEqual(urlscout.with_retry(flaky, "x", **QUIET), {"ok": True})
        self.assertEqual(len(calls), 2)

    def test_throttle_spaces_calls(self):
        t = urlscout.Throttle(15)
        with mock.patch.object(urlscout.time, "monotonic", side_effect=[100, 100, 100]), \
             mock.patch.object(urlscout.time, "sleep") as sleep:
            t.wait()
            t.wait()
        sleep.assert_called_once_with(15)


class SecurityTests(unittest.TestCase):
    def test_csv_formula_injection_neutralised(self):
        row = {"url": "https://example.com/", "scope": "public",
               "vt_title": '=HYPERLINK("http://evil","x")', "vt_categories": "@SUM(1)",
               "vt_reputation": -5}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.csv")
            urlscout.write_csv([row], path)
            with open(path, newline="") as f:
                out = next(csv.DictReader(f))
        self.assertTrue(out["vt_title"].startswith("'="))
        self.assertTrue(out["vt_categories"].startswith("'@"))
        self.assertEqual(out["vt_reputation"], "-5")  # numbers left alone

    def test_control_characters_stripped(self):
        data = {"data": {"attributes": {"title": "Evil\x1b[31mPage\x07",
                                        "last_final_url": "http://a\x1b]0;x\x07b/"}}}
        with mock.patch.object(urlscout, "http_json", return_value=(200, data)):
            row = urlscout.vt_lookup("https://example.com/", "key")
        self.assertNotIn("\x1b", row["vt_title"] + row["vt_final_url"])
        self.assertNotIn("\x07", row["vt_title"] + row["vt_final_url"])

    def test_control_characters_in_input_rejected(self):
        self.assertIsNone(urlscout.normalise_url("http://example.com/\x1b[2J"))

    def test_untrusted_id_not_put_in_link(self):
        data = {"data": {"id": "javascript:alert(1)", "attributes": {}}}
        with mock.patch.object(urlscout, "http_json", return_value=(200, data)):
            row = urlscout.vt_lookup("https://example.com/", "key")
        self.assertNotIn("vt_link", row)

    def test_bad_timestamp_does_not_crash(self):
        data = {"data": {"attributes": {"last_analysis_date": 10 ** 20}}}
        with mock.patch.object(urlscout, "http_json", return_value=(200, data)):
            self.assertIn("error", urlscout.with_retry(urlscout.vt_lookup, "http://a.example/", "k"))

    def test_api_key_with_control_characters_rejected(self):
        with mock.patch.dict(os.environ, {"VT_API_KEY": "abc\ndef"}), \
             mock.patch.object(urlscout, "http_json") as http:
            with self.assertRaises(SystemExit) as cm:
                urlscout.main(["-u", "https://example.com/"])
        http.assert_not_called()
        self.assertNotIn("abc", str(cm.exception))

    def test_unexpected_errors_do_not_crash(self):
        import http.client

        def boom():
            raise http.client.RemoteDisconnected("gone")

        self.assertIn("error", urlscout.with_retry(boom))


class OutputTests(unittest.TestCase):
    def test_table_marks_internal(self):
        rows = [{"url": "http://10.0.0.1/", "scope": "internal"}]
        out = io.StringIO()
        urlscout.print_table(rows, out=out)
        self.assertIn("(internal, skipped)", out.getvalue())

    def test_defang_row(self):
        row = urlscout.defang_row({"url": "http://evil.example/", "vt_final_url": "https://x.example/"})
        self.assertEqual(row["url"], "hxxp://evil[.]example/")
        self.assertEqual(row["vt_final_url"], "hxxps://x[.]example/")


if __name__ == "__main__":
    unittest.main()
