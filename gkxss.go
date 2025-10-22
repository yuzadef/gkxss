package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	concurrency int
	verbose     bool
	outputFile  string
	payload     string
	useragent   string
	proxy       string
	requestData string
	method      string
)

type customh []string

func (m *customh) String() string {
	return "Custom headers flag"
}

func (m *customh) Set(value string) error {
	*m = append(*m, value)
	return nil
}

var custhead customh

type paramCheck struct {
	url     string
	param   string
	context []string
	chars   []string
}

type reflectionContext struct {
	contextType string
	snippet     string
}

var transport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: time.Second,
		DualStack: true,
	}).DialContext,
}

var httpClient = &http.Client{
	Transport: transport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func banner() {
	fmt.Println(`
 ╔═══════════════════════════════════════╗
 ║   XSS Context Reflection Scanner      ║
 ║   Enhanced Edition v1.0               ║
 ╚═══════════════════════════════════════╝
	`)
}

func main() {
	flag.IntVar(&concurrency, "c", 40, "Set the concurrency level")
	flag.BoolVar(&verbose, "v", false, "Verbose mode")
	flag.StringVar(&payload, "p", "xss9z8y7x6w5v", "Unique payload for reflection testing")
	flag.StringVar(&outputFile, "o", "", "Save results to output file")
	flag.StringVar(&requestData, "d", "", "Request data for POST reflection testing")
	flag.StringVar(&proxy, "x", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	flag.StringVar(&useragent, "u", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Custom User-Agent")
	flag.Var(&custhead, "h", "Custom headers (format: 'Header: Value')")

	flag.Parse()

	if verbose {
		banner()
	}

	// Setup proxy if specified
	if proxy != "" {
		proxyUrl, err := url.Parse(proxy)
		if err != nil {
			log.Fatal("Invalid proxy URL:", err)
		}
		transport.Proxy = http.ProxyURL(proxyUrl)
	}

	// Setup output file
	if outputFile != "" {
		emptyFile, err := os.Create(outputFile)
		if err != nil {
			log.Fatal(err)
		}
		emptyFile.Close()
		if verbose {
			log.Println("Created output file:", outputFile)
		}
	}

	// Create pipeline channels
	initialChecks := make(chan paramCheck, concurrency)
	appendChecks := makePool(initialChecks, concurrency, checkInitialReflection)
	charChecks := makePool(appendChecks, concurrency, checkCharacterFilters)
	done := makePool(charChecks, concurrency, analyzeAndReport)

	// Read URLs from stdin
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		initialChecks <- paramCheck{url: sc.Text()}
	}

	close(initialChecks)
	<-done

	if verbose {
		fmt.Println("\n[✓] Scan completed!")
	}
}

func checkInitialReflection(c paramCheck, output chan paramCheck) {
	reflected, err := getReflectedParams(c.url)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "[!] Error checking %s: %s\n", c.url, err)
		}
		return
	}

	if len(reflected) == 0 {
		if verbose {
			fmt.Printf("[-] No reflection found: %s\n", c.url)
		}
		return
	}

	for _, param := range reflected {
		output <- paramCheck{url: c.url, param: param}
	}
}

func checkCharacterFilters(c paramCheck, output chan paramCheck) {
	// Test special characters with unique markers
	testChars := []string{"\"", "'", "<", ">", "$", "|", "(", ")", "`", ":", ";", "{", "}", "/", "\\"}
	unfilteredChars := []string{}

	// Use a channel to collect results
	type charResult struct {
		char      string
		reflected bool
	}
	results := make(chan charResult, len(testChars))

	// Test characters concurrently
	var wg sync.WaitGroup
	for _, char := range testChars {
		wg.Add(1)
		go func(ch string) {
			defer wg.Done()
			// Use unique prefix/suffix to avoid false positives
			wasReflected, err := checkAppendReflection(c.url, c.param, "xPrE"+ch+"xSuF")
			if err == nil && wasReflected {
				results <- charResult{ch, true}
			}
		}(char)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for result := range results {
		if result.reflected {
			unfilteredChars = append(unfilteredChars, result.char)
		}
	}

	c.chars = unfilteredChars
	output <- c
}

func analyzeAndReport(c paramCheck, output chan paramCheck) {
	// Get reflection contexts
	contexts := detectReflectionContext(c.url, c.param, payload)

	if len(contexts) == 0 {
		return
	}

	// Build context list
	contextTypes := []string{}
	for _, ctx := range contexts {
		contextTypes = append(contextTypes, ctx.contextType)
	}

	// Print results
	fmt.Printf("\n[+] Vulnerable Parameter Found!\n")
	fmt.Printf("    URL: %s\n", c.url)
	fmt.Printf("    Param: %s\n", c.param)
	fmt.Printf("    Contexts: %v\n", contextTypes)

	if len(c.chars) > 0 {
		fmt.Printf("    Unfiltered Chars: %v\n", c.chars)
	}

	if verbose {
		fmt.Println("    Context Details:")
		for _, ctx := range contexts {
			fmt.Printf("      - %s: %s\n", ctx.contextType, ctx.snippet)
		}
	}

	// Save to file
	if outputFile != "" {
		result := fmt.Sprintf("URL: %s | Param: %s | Contexts: %v | Chars: %v\n",
			c.url, c.param, contextTypes, c.chars)

		f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Println("Error writing to file:", err)
			return
		}
		defer f.Close()
		f.WriteString(result)
	}
}

func getReflectedParams(targetURL string) ([]string, error) {
	out := []string{}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return out, err
	}

	req.Header.Add("User-Agent", useragent)
	for _, v := range custhead {
		parts := strings.SplitN(v, ":", 2)
		if len(parts) == 2 {
			req.Header.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return out, err
	}
	if resp.Body == nil {
		return out, fmt.Errorf("empty response body")
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return out, err
	}

	// Skip redirects and non-HTML
	if strings.HasPrefix(resp.Status, "3") {
		return out, nil
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "html") {
		return out, nil
	}

	body := string(b)
	u, err := url.Parse(targetURL)
	if err != nil {
		return out, err
	}

	for key, vv := range u.Query() {
		for _, v := range vv {
			if v != "" && strings.Contains(body, v) {
				out = append(out, key)
				break
			}
		}
	}

	return out, nil
}

func checkAppendReflection(targetURL, param, suffix string) (bool, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false, err
	}

	qs := u.Query()
	val := qs.Get(param)
	qs.Set(param, val+suffix)
	u.RawQuery = qs.Encode()

	reflected, err := getReflectedParams(u.String())
	if err != nil {
		return false, err
	}

	for _, r := range reflected {
		if r == param {
			return true, nil
		}
	}

	return false, nil
}

func detectReflectionContext(targetURL, param, testPayload string) []reflectionContext {
	contexts := []reflectionContext{}

	u, err := url.Parse(targetURL)
	if err != nil {
		return contexts
	}

	qs := u.Query()
	originalVal := qs.Get(param)
	qs.Set(param, testPayload)
	u.RawQuery = qs.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return contexts
	}

	req.Header.Add("User-Agent", useragent)
	for _, v := range custhead {
		parts := strings.SplitN(v, ":", 2)
		if len(parts) == 2 {
			req.Header.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return contexts
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return contexts
	}

	bodyStr := string(body)

	// Find all occurrences of the payload
	payloadPositions := findAllOccurrences(bodyStr, testPayload)

	for _, pos := range payloadPositions {
		context := analyzeContext(bodyStr, pos, testPayload)
		if context.contextType != "" {
			contexts = append(contexts, context)
		}
	}

	// Restore original value
	qs.Set(param, originalVal)

	return contexts
}

func findAllOccurrences(text, substr string) []int {
	positions := []int{}
	start := 0
	for {
		idx := strings.Index(text[start:], substr)
		if idx == -1 {
			break
		}
		positions = append(positions, start+idx)
		start += idx + len(substr)
	}
	return positions
}

func analyzeContext(body string, pos int, payload string) reflectionContext {
	snippetStart := pos - 50
	if snippetStart < 0 {
		snippetStart = 0
	}
	snippetEnd := pos + len(payload) + 50
	if snippetEnd > len(body) {
		snippetEnd = len(body)
	}
	snippet := body[snippetStart:snippetEnd]

	// Get context window around payload
	contextStart := maxInt(0, pos-500)
	contextEnd := minInt(len(body), pos+500)
	contextWindow := body[contextStart:contextEnd]

	// Check if inside <script> tag
	scriptPattern := regexp.MustCompile(`(?i)<script[^>]*>[\s\S]*?` + regexp.QuoteMeta(payload) + `[\s\S]*?</script>`)
	if scriptPattern.MatchString(contextWindow) {
		return reflectionContext{"JavaScript Context", snippet}
	}

	// Check if inside event handler (on*)
	eventHandlerPattern := regexp.MustCompile(`(?i)<[^>]*\s+on\w+\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta(payload))
	if eventHandlerPattern.MatchString(body[maxInt(0, pos-200):minInt(len(body), pos+len(payload)+10)]) {
		// Extract specific event handler name
		beforeContext := body[maxInt(0, pos-200):pos]
		eventMatch := regexp.MustCompile(`(?i)on\w+\s*=\s*["']?[^"'>]*$`).FindString(beforeContext)
		if eventMatch != "" {
			handlerName := regexp.MustCompile(`(?i)on\w+`).FindString(eventMatch)
			return reflectionContext{"Event Handler (" + strings.ToLower(handlerName) + ")", snippet}
		}
		return reflectionContext{"Event Handler", snippet}
	}

	// Check if inside specific dangerous HTML attributes
	dangerousAttrs := []string{
		"href", "src", "action", "formaction", "srcdoc", "style",
		"poster", "code", "codebase", "content", "data-",
	}

	for _, attr := range dangerousAttrs {
		attrPattern := regexp.MustCompile(`(?i)<[^>]*\s+` + attr + `[^=]*=\s*["']?[^"'>]*` + regexp.QuoteMeta(payload))
		if attrPattern.MatchString(body[maxInt(0, pos-200):minInt(len(body), pos+len(payload)+10)]) {
			return reflectionContext{"Dangerous Attribute (" + attr + ")", snippet}
		}
	}

	// Check if inside any other HTML attribute
	attrPattern := regexp.MustCompile(`(?i)<[^>]*\s+\w+\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta(payload))
	if attrPattern.MatchString(body[maxInt(0, pos-200):minInt(len(body), pos+len(payload)+10)]) {
		// Try to extract attribute name
		beforeContext := body[maxInt(0, pos-200):pos]
		attrMatch := regexp.MustCompile(`(?i)\w+\s*=\s*["']?[^"'>]*$`).FindString(beforeContext)
		if attrMatch != "" {
			attrName := regexp.MustCompile(`(?i)\w+`).FindString(attrMatch)
			return reflectionContext{"HTML Attribute (" + strings.ToLower(attrName) + ")", snippet}
		}
		return reflectionContext{"HTML Attribute", snippet}
	}

	// Check if inside HTML tag (between < and >)
	beforePayload := body[maxInt(0, pos-100):pos]
	afterPayload := body[pos+len(payload):minInt(len(body), pos+len(payload)+100)]

	lastOpenBracket := strings.LastIndex(beforePayload, "<")
	lastCloseBracket := strings.LastIndex(beforePayload, ">")
	nextCloseBracket := strings.Index(afterPayload, ">")

	if lastOpenBracket > lastCloseBracket && nextCloseBracket != -1 {
		return reflectionContext{"Inside HTML Tag", snippet}
	}

	// Default: HTML Body
	return reflectionContext{"HTML Body", snippet}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type workerFunc func(paramCheck, chan paramCheck)

func makePool(input chan paramCheck, workers int, fn workerFunc) chan paramCheck {
	var wg sync.WaitGroup
	output := make(chan paramCheck)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range input {
				fn(c, output)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(output)
	}()

	return output
}