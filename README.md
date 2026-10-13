# urlscout

Quick triage for a list of URLs against [VirusTotal](https://www.virustotal.com). For each URL, `urlscout` shows:

- **Verdict**: how many VirusTotal engines flag it as malicious or suspicious
- **Categories**: what vendors classify the site as, such as `phishing`, `malware` or `search engines`
- **Page title and final URL**: where the URL ended up after redirects, as of the last scan
- **Reputation** and the date of the last analysis

It's useful when you've pulled links out of a phishing email, proxy logs or an alert and want a quick idea of whether they're known to be bad. It is a sibling of [ipscout](../ipscout).

Python 3.11+, standard library only. Nothing to `pip install`.

## Usage

```bash
export VT_API_KEY=...            # your VirusTotal API key
./urlscout.py examples/urls.txt
```

```
URL                              VirusTotal                Categories                Title
-------------------------------  ------------------------  ------------------------  ------------
https://www.google.com/          clean (0 mal, 0 sus)      search engines            Google
https://example.com/login        not found
http://192.168.1.10/admin        (internal, skipped)
```

Single URLs, defanged output and saved results:

```bash
./urlscout.py -u 'hxxps://login-micros0ft[.]com/auth' --defang --csv results.csv --json results.json
```

Reading from a pipe, for example URLs pulled from an email:

```bash
grep -oE 'https?://[^" <>]+' message.eml | sort -u | ./urlscout.py -
```

### Input format

One URL per line, from a file, stdin (`-`), or `-u URL` (repeatable, and combinable with a file).

- **Defanged URLs are accepted**: `hxxp://`, `hxxps://`, `[.]`, `(.)`, `[dot]` and `[:]` are converted back automatically.
- No scheme means `http://` is assumed (`example.com` becomes `http://example.com`).
- Blank lines and lines starting with `#` are ignored. A comment after a URL needs a space before the `#`, because `#` without a space is part of the URL (a fragment).
- Duplicates are removed. Anything that isn't an `http`/`https` URL is reported as a warning without stopping the run.

**Internal URLs are never sent to VirusTotal.** That covers private and reserved IPs, `localhost`, single-label hosts (`http://intranet/`) and names ending in `.local`, `.lan`, `.internal`, `.corp` or `.home.arpa`. Shorthand IP forms like `http://127.1/` or `http://0177.0.0.1/` and trailing dots (`http://localhost./`) are caught too. This stops internal hostnames leaking to a public service. It can't recognise internal names under a public domain (`jira.internal.yourcompany.com`), so remove those from the input yourself.

**Look-alike domains:** the `domain` field always holds the real (punycode) form of the host, and a note is printed when it differs from what's displayed. For example, `gооgle.com` written with Cyrillic `о`s shows up as `xn--ggle-55da.com`.

### Options

| Option | Description |
|---|---|
| `-u URL` | Check this URL. Can be repeated. |
| `--submit` | Submit URLs VirusTotal has never seen for a fresh scan and wait for the result. See the privacy note below. |
| `--defang` | Defang URLs in the table, CSV and JSON (`hxxps://evil[.]com`), so they're safe to paste into tickets or chat |
| `--vt-delay N` | Seconds between VirusTotal calls. Default 15, to stay within the free tier's 4 requests/minute. Use `0` with a premium key. |
| `--csv PATH` / `--json PATH` | Also save results to a file |
| `-q` | Hide progress messages |

### API key

| Variable | Notes |
|---|---|
| `VT_API_KEY` | Required. Free key at [virustotal.com](https://www.virustotal.com/gui/join-us): 4 lookups/min, 500/day |

The key is read from the environment only, so it doesn't end up in your shell history or in `ps` output.

## Output fields (CSV/JSON)

`url, scope, domain, vt_verdict, vt_malicious, vt_suspicious, vt_harmless, vt_undetected, vt_reputation, vt_categories, vt_final_url, vt_title, vt_last_analysis, vt_link, error`

`vt_verdict` is one of:
- `MALICIOUS`: at least one engine flags the URL as malicious
- `SUSPICIOUS`: no malicious flags, but at least one suspicious flag
- `clean`
- `not found`: VirusTotal has no record of the URL (rerun with `--submit` to scan it)
- `queued`: submitted with `--submit`, but the scan hadn't finished after ~80 seconds. Run again later.
- `not analysed`: VirusTotal knows the URL but has no analysis stats for it

The exit code is `1` if any lookup failed, so the script can be used in pipelines.

## Things to keep in mind

- **A clean result doesn't mean safe.** It only means no engine has flagged the URL *yet*. Fresh phishing links are often clean for the first hours.
- **Lookups are by exact URL.** `https://evil.com/a` and `https://evil.com/b` are different entries on VirusTotal, so a clean path on a bad domain can still come back `not found` or clean.
- **Privacy.** Every public URL you check is sent to VirusTotal. **With `--submit`, unknown URLs are scanned and become visible to other VirusTotal users**, including whoever runs the site. Don't submit URLs that contain tokens, personal data or anything you're not allowed to share (password-reset links, invoice links with IDs, internal tracking links). Result files are git-ignored by default because they may contain investigation data.
- **urlscout never visits the URLs itself.** Titles and final URLs come from VirusTotal's last scan.

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests mock all network calls, so they run offline. GitHub Actions runs them on Python 3.11, 3.12 and 3.14.

## Roadmap ideas

- [ ] Fall back to a domain report when the exact URL isn't known
- [ ] urlscan.io and Google Safe Browsing as extra sources
- [ ] Cache results locally so repeat lookups don't use up API quota
- [ ] Extract URLs directly from `.eml` files

## License

MIT
