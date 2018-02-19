package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/gin-gonic/gin/json"
	"github.com/pkg/errors"

	"github.com/asaskevich/govalidator"
	"github.com/fatih/color"
	flag "github.com/spf13/pflag"

	"github.com/bbrks/wrap"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/mreiferson/go-httpclient"
)

var (
	version   string // version set by ldflags
	buildDate string // build date set by ldflags
)

// Config contains all configuration options
type Config struct {
	url       string // the URL to request
	insecure  bool   // whether to verify ssl certs
	userAgent string // user agent to use for the request
	checkAll  bool   // enable to check for all headers, otherwise only headers in the default scan are checked
	verbose   bool   // enable to display verbose verbose on headers
}

// AppInfo stores the config and all data used by the application
type AppInfo struct {
	config Config

	rawHeader []byte       // raw headers with status code and preserved order
	headers   http.Header  // map of headers
	debugLog  bytes.Buffer // raw request log for debugging
	finalURL  string       // the final request URL after any redirection
	body      []byte       // the response body
}

// set up colorized symbols for printing
var (
	errorSymbol   = color.RedString("[!]")
	warnSymbol    = color.YellowString("[!]")
	infoSymbol    = color.CyanString("[*]")
	successSymbol = color.HiGreenString("[*]")
)

func main() {

	var shcheck AppInfo

	flag.BoolVarP(&shcheck.config.insecure, "insecure", "i", false, "disable SSL certificate validation")
	flag.BoolVarP(&shcheck.config.verbose, "verbose", "v", false, "display full info about headers")
	flag.StringVarP(&shcheck.config.userAgent, "agent", "A", fmt.Sprintf("shcheck/%s", version), "user agent to use for requests")
	displayHelp := flag.BoolP("help", "h", false, "display help")
	displayVersion := flag.BoolP("version", "V", false, "display version")

	flag.Parse()

	// override the default usage display
	if *displayHelp {
		displayUsage()
		os.Exit(0)
	}

	if *displayVersion {
		fmt.Printf("Version: \t%s\n", version)
		fmt.Printf("Build Date: \t%s\n", buildDate)
		os.Exit(0)
	}

	url := flag.Arg(0)
	if !govalidator.IsURL(url) {
		fmt.Printf("%s ERROR: invalid url provided: '%s'\n\n", errorSymbol, url)

		displayUsage()
		os.Exit(1)
	}
	shcheck.config.url = url

	fmt.Printf("%s Analyzing headers of %s\n", infoSymbol, color.HiBlueString(shcheck.config.url))

	err := shcheck.getHeaders()
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		fmt.Println(shcheck.debugLog.String())
		os.Exit(1)
	}

	// print the final URL after any redirections
	fmt.Printf("%s Effective URL: %s\n", infoSymbol, color.HiBlueString(shcheck.finalURL))

	if shcheck.config.verbose { // print raw returned headers
		headers := strings.Replace(string(shcheck.rawHeader), "\n", "\n\t", -1)
		fmt.Printf("%s Headers: \n\t%s\n", infoSymbol, headers)
	}

	// check the server headers for any issues
	err = shcheck.checkHeaders()
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

	// check the HTML body for any issues
	err = shcheck.checkBody()
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

}

func (shcheck *AppInfo) getHeaders() error {

	// set up a custom transport
	tr := &httpclient.Transport{
		// toggle setting for whether to verify SSL certs
		TLSClientConfig: &tls.Config{InsecureSkipVerify: shcheck.config.insecure},

		// set timeouts to prime numbers
		ConnectTimeout:        7 * time.Second,
		RequestTimeout:        9 * time.Second,
		ResponseHeaderTimeout: 11 * time.Second,
	}

	// set up a buffer to store the request log
	logWriter := bufio.NewWriter(&shcheck.debugLog)

	client := retryablehttp.NewClient()
	client.HTTPClient = &http.Client{
		Transport: tr,
		Timeout:   19 * time.Second,
	}
	client.RetryWaitMax = 47 * time.Second
	client.RetryWaitMin = 2 * time.Second
	client.RetryMax = 2 // total of 3 attempts
	client.Logger.SetOutput(logWriter)

	url := shcheck.config.url

	// if the user only provided a domain name, append the http protocol scheme for them
	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}

	req, err := retryablehttp.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", shcheck.config.userAgent)

	resp, err := client.Do(req)
	_ = logWriter.Flush()
	if err != nil {
		return err
	}

	// dump the raw response so that the status code and header order is preserved
	headerDump, _ := httputil.DumpResponse(resp, false)
	shcheck.rawHeader = headerDump

	shcheck.headers = resp.Header

	respBody, _ := ioutil.ReadAll(resp.Body)
	shcheck.body = respBody

	// record the final URL in the event the server redirected from initial URL
	shcheck.finalURL = resp.Request.URL.String()

	return nil
}
func (shcheck AppInfo) checkHeaders() error {

	if !shcheck.config.checkAll { // check only the default headers

		for _, h := range DefaultScanHeaders {

			headerValue := shcheck.headers.Get(h)
			if headerValue == "" { // header is missing
				shcheck.printMissingHeader(h)
			} else { // header is found
				shcheck.printFoundHeader(h, headerValue)
			}

		}
	}

	return nil
}

func (shcheck AppInfo) checkBody() error {

	err := shcheck.checkScriptSubresourceIntegrity()

	return err
}

func (shcheck AppInfo) checkScriptSubresourceIntegrity() error {

	doc, goqueryerr := goquery.NewDocumentFromReader(bytes.NewReader(shcheck.body))
	if goqueryerr != nil {
		return goqueryerr
	}

	var (
		scriptsWithIntegrity   int // counter of scripts using subresource integrity
		scriptsWithNoIntegrity int
	)
	externalScriptsWithoutIntegrity := make([]string, 0)

	// search for all script elements, if the element has a src attribute, verify that it has an integrity attribute as well
	doc.Find("script").Each(func(i int, s *goquery.Selection) {

		srcVal, srcExists := s.Attr("src")
		if srcExists {
			_, intExists := s.Attr("integrity")

			if intExists {
				scriptsWithIntegrity++
			} else if strings.HasPrefix(srcVal, "http") || strings.HasPrefix(srcVal, "//") {
				// verify the script is not using an absolute path on same domain
				u, _ := url.Parse(shcheck.finalURL)
				if !strings.HasPrefix(srcVal, fmt.Sprintf("%s://%s", u.Scheme, u.Host)) {
					scriptsWithNoIntegrity++
					externalScriptsWithoutIntegrity = append(externalScriptsWithoutIntegrity, srcVal)
				}
			}
		}
	})

	if scriptsWithIntegrity > 0 {
		fmt.Printf("%s %d scripts found using subresource integrity!\n", successSymbol, scriptsWithIntegrity)
	} else if scriptsWithNoIntegrity > 0 {
		fmt.Printf("%s %d scripts found not using subresource integrity.\n", warnSymbol, scriptsWithNoIntegrity)
	}

	if shcheck.config.verbose {
		w := wrap.NewWrapper()
		w.Newline = "\n\t\t"
		w.StripTrailingNewline = true

		fmt.Printf("\t%s: %s\n", color.CyanString("Reference"), "https://www.w3.org/TR/SRI/")
		fmt.Printf("\t%s: %s\n", color.CyanString("Security Description"), w.Wrap("Subresource Integrity will ensure that only the code that has been reviewed is executed. In the event the upstream vendor is hijacked, the malicious code will not be executed.", 150))
		fmt.Printf("\t%s: %s\n", color.CyanString("Security Reference"), "https://scotthelme.co.uk/subresource-integrity/")
		fmt.Printf("\t%s: %s\n", color.CyanString("Recommendation"), "It is recommended to use this integrity metadata for all third party scripts.")
		fmt.Printf("\t%s: %s\n", color.CyanString("CWE"), "CWE-353: Missing Support for Integrity Check")
		fmt.Printf("\t%s: %s\n", color.CyanString("CWE URL"), "https://cwe.mitre.org/data/definitions/353.html")
		fmt.Printf("\t%s:\n", color.CyanString("Unsafe scripts found"))
		for _, scriptURL := range externalScriptsWithoutIntegrity {
			fmt.Printf("\t\t%s\n", scriptURL)
		}
	}

	// check for inline scripts
	inlineScripts := findInlineScripts(doc)
	numOfInlineScripts := len(inlineScripts)
	if numOfInlineScripts > 0 {
		filePath := path.Join(os.TempDir(), "shcheck.json")
		fmt.Printf("\t%s %d inline scripts found; they were not evaluated for subresource integrity. (written to %s)\n", infoSymbol, numOfInlineScripts, filePath)

		scripts, _ := json.MarshalIndent(inlineScripts, "", "    ")
		err := ioutil.WriteFile(filePath, []byte(scripts), 0666)
		if err != nil {
			return errors.Wrap(err, "write failed")
		}
	}

	return nil
}

func (shcheck AppInfo) printMissingHeader(header string) {

	fmt.Printf("%s Missing security header: %s\n", warnSymbol, color.YellowString(header))

	if shcheck.config.verbose {
		h := SecurityHeaders[header]
		w := wrap.NewWrapper()
		w.Newline = "\n\t\t"
		w.StripTrailingNewline = true

		fmt.Printf("\t%s: %s\n", color.CyanString("Reference"), h.Reference)
		fmt.Printf("\t%s: %s\n", color.CyanString("Security Description"), w.Wrap(h.SecurityDescription, 150))
		fmt.Printf("\t%s: %s\n", color.CyanString("Security Reference"), h.SecurityReference)
		fmt.Printf("\t%s: %s\n", color.CyanString("Recommendations"), w.Wrap(h.Recommendations, 150))
		fmt.Printf("\t%s: %s\n", color.CyanString("CWE"), h.CWEDescription)
		fmt.Printf("\t%s: %s\n", color.CyanString("CWE URL"), h.CWEURL)
	}
}

func (shcheck AppInfo) printFoundHeader(header string, headerValue string) {
	w := wrap.NewWrapper()
	w.Newline = "\n\t"
	w.StripTrailingNewline = true
	fmt.Printf("%s Header %s is present! (Value: %s)\n", successSymbol, color.HiMagentaString(header), color.YellowString(w.Wrap(headerValue, 120)))
}

// print custom usage instead of the default provided by pflag
func displayUsage() {

	fmt.Printf("Usage: shcheck [<flags>] <URL to scan>\n\n")
	fmt.Printf("Optional flags:\n\n")
	flag.PrintDefaults()
}

func findInlineScripts(doc *goquery.Document) []string {
	var inlineJS []string

	doc.Find("script").Each(func(_ int, tag *goquery.Selection) {
		// no `src` tag, then shit's prob in-lined
		if _, exists := tag.Attr("src"); !exists {
			inlineJS = append(inlineJS, tag.Text())
		}
	})

	return inlineJS
}
