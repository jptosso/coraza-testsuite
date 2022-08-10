package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/seclang"
	"github.com/corazawaf/coraza/v3/testing"
	"github.com/corazawaf/coraza/v3/testing/profile"
	"gopkg.in/yaml.v3"
)

var files []string
var filedir string
var output string
var pattern string
var ignoreFile string
var profiles []profile.Profile
var tests []*test
var waf = coraza.NewWaf()
var directives arrayFlags
var ignoredTests []string

type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join(*i, ",")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	flag.StringVar(&filedir, "input", "", ".yaml profile files path")
	flag.StringVar(&output, "output", "", "output path")
	flag.StringVar(&pattern, "i", "", "test name regex")
	flag.StringVar(&ignoreFile, "ignore", "", "path to ignore file")
	flag.Var(&directives, "d", "List of directives")
	flag.Parse()
	if err := validate(); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
	if err := loadIgnoredFiles(); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Will ignore %d tests\n", len(ignoredTests))
	if err := loadDirectives(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Got %d rules\n", waf.Rules.Count())
	if err := getFileList(); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Got %d files\n", len(files))
	if err := openProfiles(); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Opened %d profiles\n", len(profiles))
	if err := openTests(); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Opened %d tests\n", len(tests))
	runTests()
}

func validate() error {
	if output == "" {
		return fmt.Errorf("output is required")
	}
	return nil
}

func loadIgnoredFiles() error {
	if ignoreFile == "" {
		return nil
	}
	bts, err := os.ReadFile(ignoreFile)
	if err != nil {
		return err
	}
	data := make(map[string]string)
	if err := yaml.Unmarshal(bts, &data); err != nil {
		return err
	}
	for k := range data {
		ignoredTests = append(ignoredTests, k)
	}
	return nil
}

func runTests() {
	fail := 0
	ignored := 0
main:
	for _, t := range tests {
		// fmt.Printf("Running test %s\n", t.Test.Name)
		for _, i := range ignoredTests {
			if t.Test.Name == i {
				fmt.Printf("Ignoring test %s\n", t.Test.Name)
				ignored++
				continue main
			}
		}
		t.Transaction = t.Test.Transaction()
		if err := t.Test.RunPhases(); err != nil {
			fmt.Printf("Error: %s\n", err)
		}
		errs := t.Test.OutputErrors()
		if len(errs) > 0 {
			t.Errors = errs
			fmt.Printf("Failed to run test %s: %s\n", t.Test.Name, strings.Join(errs, ", "))
			filename := filepath.Join(output, t.Test.Name+".html")
			fmt.Printf("Writing report %s\n", filename)
			if err := t.Write(filename); err != nil {
				fmt.Printf("Error: %s\n", err)
				os.Exit(1)
			}
			fail++
		}
	}
	fmt.Printf("%d/%d (%.2f%% passed) tests passed\n", len(tests)-ignored-fail, len(tests)-ignored, 100*(1-float64(fail)/float64(len(tests)-ignored)))
}

func loadDirectives() error {
	// waf.Logger.SetOutput(os.Stdout)
	waf.Logger.SetLevel(coraza.LogLevelDebug)
	parser, _ := seclang.NewParser(waf)
	for _, d := range directives {
		if err := parser.FromFile(d); err != nil {
			return err
		}
	}
	return nil
}

func openTests() error {
	re := regexp.MustCompile(pattern)
	for _, p := range profiles {
		for _, t := range p.Tests {
			name := t.Title
			for _, stage := range t.Stages {
				if !re.MatchString(t.Title) {
					continue
				}
				test := testing.NewTest(name, waf)
				test.ExpectedOutput = stage.Stage.Output
				// test.RequestAddress =
				// test.RequestPort =
				if stage.Stage.Input.URI != "" {
					test.RequestURI = stage.Stage.Input.URI
				}
				if stage.Stage.Input.Method != "" {
					test.RequestMethod = stage.Stage.Input.Method
				}
				if stage.Stage.Input.Version != "" {
					test.RequestProtocol = stage.Stage.Input.Version
				}
				if stage.Stage.Input.Headers != nil {
					test.RequestHeaders = stage.Stage.Input.Headers
				}
				if stage.Stage.Output.Headers != nil {
					test.ResponseHeaders = stage.Stage.Output.Headers
				}
				// test.ResponseHeaders = stage.Output.Headers
				test.ResponseCode = 200
				test.ResponseProtocol = "HTTP/1.1"
				test.ServerAddress = stage.Stage.Input.DestAddr
				test.ServerPort = stage.Stage.Input.Port
				if stage.Stage.Input.StopMagic {
					test.DisableMagic()
				}
				if err := test.SetEncodedRequest(stage.Stage.Input.EncodedRequest); err != nil {
					return err
				}
				if err := test.SetRawRequest(stage.Stage.Input.RawRequest); err != nil {
					return err
				}
				if err := test.SetRequestBody(stage.Stage.Input.Data); err != nil {
					return err
				}
				if err := test.SetResponseBody(stage.Stage.Output.Data); err != nil {
					return err
				}
				tests = append(tests, newTest(p, test))
			}
		}
	}
	return nil
}

func getFileList() error {
	if err := filepath.Walk(filedir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".yaml") {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func openProfiles() error {
	for _, f := range files {
		bts, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var profile profile.Profile
		if err := yaml.Unmarshal(bts, &profile); err != nil {
			return err
		}
		profiles = append(profiles, profile)
	}
	return nil
}
