# GKXSS — XSS Context Reflection Scanner

A concurrent command-line tool written in Go that scans URLs for reflected XSS
parameter vulnerabilities. It identifies which query parameters are reflected in
HTML responses, tests which special characters pass through unfiltered, and
classifies the reflection context (JavaScript block, event handler, HTML
attribute, etc.) to inform exploit construction.

---

## How It Works

The scanner runs a three-stage concurrent pipeline:

```
stdin (URLs)
    |
    v
[Stage 1] checkInitialReflection
    - Sends the URL as-is
    - Checks which query parameters appear verbatim in the response body
    - Drops non-HTML responses and 3xx redirects
    |
    v
[Stage 2] checkCharacterFilters
    - For each reflected parameter, appends 15 special characters one at a time
      (each wrapped in a unique marker: xPrE<char>xSuF)
    - Records which characters survive into the response unescaped/unfiltered
    |
    v
[Stage 3] analyzeAndReport
    - Replaces the parameter value with the configured payload
    - Finds every occurrence of the payload in the response
    - Classifies each occurrence by its HTML context
    - Prints results and optionally writes to a file
```

Each stage runs with its own worker pool (default 40 goroutines each).

---

## Installation

Requires Go 1.18+.

```bash
go build -o boom boom.go
```

---

## Usage

```
cat urls.txt | ./boom [flags]
```

URLs are read one per line from **stdin**. Each URL should include query
parameters whose values you want to test for reflection.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c` | `40` | Concurrency level (goroutines per pipeline stage) |
| `-v` | `false` | Verbose mode — prints banner, per-URL status, and context snippets |
| `-p` | `xss9z8y7x6w5v` | Unique string injected to detect reflection context |
| `-o` | _(none)_ | Output file path; results are appended in plain text |
| `-d` | _(none)_ | Request body data (reserved; not yet wired to POST requests) |
| `-x` | _(none)_ | HTTP proxy URL (e.g. `http://127.0.0.1:8080`) |
| `-u` | Chrome 120 UA | Custom User-Agent string |
| `-h` | _(none)_ | Extra request header, repeatable (format: `Header: Value`) |

### Examples

Basic scan:
```bash
cat urls.txt | ./boom
```

Verbose output with proxy and custom header:
```bash
cat urls.txt | ./boom -v -x http://127.0.0.1:8080 -h "Cookie: session=abc123"
```

Save findings to a file with custom payload:
```bash
cat urls.txt | ./boom -p myuniqtoken -o results.txt
```

---

## Output

When a vulnerable parameter is found, the tool prints:

```
[+] Vulnerable Parameter Found!
    URL: https://example.com/search?q=hello
    Param: q
    Contexts: [HTML Body]
    Unfiltered Chars: [" ' < > ( )]
```

With `-v`, an additional context detail line shows the surrounding HTML snippet
for each unique context type.

Output file format (one line per finding):
```
URL: <url> | Param: <param> | Contexts: [<ctx1> <ctx2>] | Chars: [<char1> <char2>]
```

---

## Reflection Context Classification

`analyzeContext` inspects the 500-character window around each payload
occurrence and assigns one of the following context types (checked in priority
order):

| Context Type | Detection Method |
|---|---|
| `JavaScript Context` | Payload sits between `<script>` and `</script>` |
| `Event Handler (<name>)` | Payload follows an `on*=` attribute value |
| `Dangerous Attribute (<name>)` | Payload is in `href`, `src`, `action`, `formaction`, `srcdoc`, `style`, `poster`, `code`, `codebase`, `content`, or `data-` |
| `HTML Attribute (<name>)` | Payload is in any other tag attribute value |
| `Inside HTML Tag` | Payload sits between `<` and `>` but not in an attribute |
| `HTML Body` | Fallback — payload appears in raw text content |

---

## Special Characters Tested

The following 15 characters are probed for filter bypass:

```
"  '  <  >  $  |  (  )  `  :  ;  {  }  /  \
```

Each is tested by appending `xPrE<char>xSuF` to the parameter value and
checking whether the full string appears in the response.

---

## HTTP Client Behavior

- TLS certificate verification is **disabled** (`InsecureSkipVerify: true`)
- Redirects are **not followed** (stops at the first response)
- Dial timeout: 30 seconds; keep-alive: 1 second
- Only HTML responses are processed; all other `Content-Type` values are skipped
- 3xx responses are silently skipped at every stage

---

## Limitations

- **GET only** — the `-d` flag is parsed but POST request support is not
  implemented; all requests use `GET`.
- **No WAF evasion** — payloads are sent as plain URL-encoded strings.
- **Regex-based context detection** — may misclassify reflection in heavily
  dynamic or template-generated HTML.
- **No deduplication across URLs** — the same parameter on the same URL will be
  tested once per line in stdin.
- **ioutil.ReadAll** — full response bodies are buffered in memory; very large
  responses may consume significant RAM.
