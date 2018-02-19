package main

//SecurityHeaders maps a header name string to a securityHeader struct
var SecurityHeaders map[string]securityHeader

//DefaultScanHeaders is a list of default headers we want to be required
var DefaultScanHeaders []string

type securityHeader struct {
	Name                string
	Reference           string
	SecurityDescription string
	SecurityReference   string
	Recommendations     string
	CWEDescription      string
	CWEURL              string
}

func init() {
	DefaultScanHeaders = make([]string, 0)
	SecurityHeaders = make(map[string]securityHeader, 0)

	DefaultScanHeaders = append(DefaultScanHeaders, "X-XSS-Protection")
	DefaultScanHeaders = append(DefaultScanHeaders, "Content-Security-Policy")
	DefaultScanHeaders = append(DefaultScanHeaders, "Strict-Transport-Security")
	DefaultScanHeaders = append(DefaultScanHeaders, "X-Frame-Options")
	DefaultScanHeaders = append(DefaultScanHeaders, "Referrer-Policy")
	DefaultScanHeaders = append(DefaultScanHeaders, "X-Content-Type-Options")

	SecurityHeaders["X-XSS-Protection"] = securityHeader{
		Name:                "X-XSS-Protection",
		Reference:           "http://blogs.msdn.com/b/ie/archive/2008/07/02/ie8-security-part-iv-the-xss-filter.aspx",
		SecurityDescription: `This header enables the Cross-site scripting (XSS) filter built into most recent web browsers. It's usually enabled by default anyway, so the role of this header is to re-enable the filter for this particular website if it was disabled by the user. This header is supported in IE 8+, and in Chrome (not sure which versions). The anti-XSS filter was added in Chrome 4. Its unknown if that version honored this header.`,
		SecurityReference:   "https://www.owasp.org/index.php/List_of_useful_HTTP_headers",
		Recommendations:     `Use "X-XSS-Protection: 1; mode=block" whenever possible (ref. http://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx).`,
		CWEDescription:      `CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')`,
		CWEURL:              "https://cwe.mitre.org/data/definitions/79.html",
	}

	SecurityHeaders["Content-Security-Policy"] = securityHeader{
		Name:                `Content-Security-Policy`,
		Reference:           `http://www.w3.org/TR/CSP/`,
		SecurityDescription: `Content Security Policy requires careful tuning and precise definition of the policy. If enabled, CSP has significant impact on the way browser renders pages (e.g., inline JavaScript disabled by default and must be explicitly allowed in policy). CSP prevents a wide range of attacks, including Cross-site scripting and other cross-site injections.`,
		SecurityReference:   `https://www.owasp.org/index.php/List_of_useful_HTTP_headers`,
		Recommendations:     `Read the reference http://www.w3.org/TR/CSP/ and set according to your case. This is not a easy job.`,
		CWEDescription:      `CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')`,
		CWEURL:              `https://cwe.mitre.org/data/definitions/79.html`,
	}

	SecurityHeaders["Strict-Transport-Security"] = securityHeader{
		Name:                `Strict-Transport-Security`,
		Reference:           `https://tools.ietf.org/html/rfc6797`,
		SecurityDescription: `HTTP Strict Transport Security (HSTS) is a web security policy mechanism which helps to protect secure HTTPS websites against downgrade attacks and cookie hijacking. It allows web servers to declare that web browsers (or other complying user agents) should only interact with it using secure HTTPS connections, and never via the insecure HTTP protocol. HSTS is an IETF standards track protocol and is specified in RFC 6797.`,
		SecurityReference:   `https://tools.ietf.org/html/rfc6797`,
		Recommendations:     `Please at least read this reference: https://www.owasp.org/index.php/HTTP_Strict_Transport_Security.`,
		CWEDescription:      `CWE-311: Missing Encryption of Sensitive Data`,
		CWEURL:              `https://cwe.mitre.org/data/definitions/311.html`,
	}

	SecurityHeaders["X-Frame-Options"] = securityHeader{
		Name:                `X-Frame-Options`,
		Reference:           `https://tools.ietf.org/html/rfc7034`,
		SecurityDescription: `The use of "X-Frame-Options" allows a web page from host B to declare that its content (for example, a button, links, text, etc.) must not be displayed in a frame (<frame> or <iframe>) of another page (e.g., from host A). This is done by a policy declared in the HTTP header and enforced by browser implementations.`,
		SecurityReference:   `https://tools.ietf.org/html/rfc7034`,
		Recommendations:     `In 2009 and 2010, many browser vendors ([Microsoft-X-Frame-Options] and [Mozilla-X-Frame-Options]) introduced the use of a non-standard HTTP [RFC2616] header field "X-Frame-Options" to protect against clickjacking. Please check here https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet what's the best option for your case.`,
		CWEDescription:      `CWE-693: Protection Mechanism Failure`,
		CWEURL:              `https://cwe.mitre.org/data/definitions/693.html`,
	}

	SecurityHeaders["Referrer-Policy"] = securityHeader{
		Name:                `Referrer-Policy`,
		Reference:           `https://scotthelme.co.uk/a-new-security-header-referrer-policy/`,
		SecurityDescription: `Referrer Policy is a new header that allows a site to control how much information the browser includes with navigations away from a document and should be set by all sites.`,
		SecurityReference:   `https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#rp`,
		Recommendations:     `Which header you will want or need to use will depend on your requirements but there are some that you should probably stay away from. The unsafe-url value kind of gives you a hint in the name and I wouldn't really advise anyone use it. Likewise if you're thinking of using origin or origin-when-cross-origin then I'd recommend looking at strict-origin and strict-origin-when-cross-origin instead. This will at least plug the little hole of leaking referrer data over an insecure connection. I don't have anything sensitive in the URL for my site so I will probably look at a value like no-referrer-when-downgrade just to keep referrer data off HTTP connections.`,
		CWEDescription:      `CWE-201: Information Exposure Through Sent Data`,
		CWEURL:              `https://cwe.mitre.org/data/definitions/201.html`,
	}

	SecurityHeaders["X-Content-Type-Options"] = securityHeader{
		Name:                `X-Content-Type-Options`,
		Reference:           `http://blogs.msdn.com/b/ie/archive/2008/09/02/ie8-security-part-vi-beta-2-update.aspx`,
		SecurityDescription: `The only defined value, "nosniff", prevents Internet Explorer and Google Chrome from MIME-sniffing a response away from the declared content-type. This also applies to Google Chrome, when downloading extensions. This reduces exposure to drive-by download attacks and sites serving user uploaded content that, by clever naming, could be treated by MSIE as executable or dynamic HTML files.`,
		SecurityReference:   `https://www.owasp.org/index.php/List_of_useful_HTTP_headers`,
		Recommendations:     `Always use the only defined value, "nosniff".`,
		CWEDescription:      `CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')`,
		CWEURL:              `https://cwe.mitre.org/data/definitions/79.html`,
	}

	/*
		SecurityHeaders[""] = securityHeader{
			Name:                ``,
			Reference:           ``,
			SecurityDescription: ``,
			SecurityReference:   ``,
			Recommendations:     ``,
			CWEDescription:      ``,
			CWEURL:              ``,
		}
		DefaultScanHeaders = append(DefaultScanHeaders, "")
	*/
}
