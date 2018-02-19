// +build mage

// nolint: deadcode
package main

import (
	"fmt"
	"time"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var (
	binary      = "shcheck"
	packageName = "github.com/jakewarren/shcheck"
	LDFLAGS     = "-w -s -X main.version=$VERSION -X main.buildDate=$BUILD_DATE"
	LDFLAGS_DEV = "-X main.version=$VERSION -X main.buildDate=$BUILD_DATE"
)

// Proves a flag environment for LDFLAGS
func flagEnv() map[string]string {
	return map[string]string{
		"PACKAGE":    packageName,
		"BUILD_DATE": time.Now().Format("2006-01-02T15:04:05Z0700"),
		"VERSION":    version(),
	}
}

// Build Build a development binary
func Build() error {
	return sh.RunWith(flagEnv(), "go", "build", "-ldflags", LDFLAGS_DEV, "-o", fmt.Sprintf("bin/%s", binary), packageName)
}

// Run "go fmt" on all files
func Format() error {
	return sh.Run("go", "fmt")
}

// Install Install a development binary on your local system
func Install() error {
	return sh.RunWith(flagEnv(), "go", "install", "-ldflags", LDFLAGS_DEV)
}

// Release Build cross platform binaries for release
func Release() error {
	mg.Deps(checkGox)
	return sh.RunWith(flagEnv(), "gox", `-osarch`, `darwin/386 darwin/amd64 linux/386 linux/amd64 windows/386 windows/amd64`, "-ldflags", LDFLAGS, `-output`, `bin/{{.Dir}}_{{.OS}}_{{.Arch}}`)
}

// check that gox is installed
func checkGox() error {
	verboseLog("checking that gox is installed")
	return sh.Run("bash", "-c", `command -v gox`)
}

// get the latest tag
func version() string {
	//versionString, err := sh.Output("bash", "-c", `git describe --tags --abbrev=0 2>/dev/null || (git describe --always --long --dirty 2>/dev/null |tr '\n' '-';date +%Y.%m.%d)`)
	versionString, err := sh.Output("bash", "-c", `git describe --always --dirty 2>/dev/null |tr '\n' '-';date +%Y.%m.%d`)
	if err != nil {
		mg.Fatal(1, "error getting the version information")
	}

	verboseLog("determined version: ", versionString)

	return versionString
}

// verboseLog logs only if the user enables mage's verbose option
func verboseLog(msg ...string) {
	if mg.Verbose() {
		fmt.Println(msg)
	}
}
