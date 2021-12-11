package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	_ "github.com/jptosso/coraza-libinjection"
	_ "github.com/jptosso/coraza-pcre"
	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/seclang"
	"github.com/jptosso/coraza-waf/v2/testing"
	"github.com/spf13/cobra"
)

var exceptions = []string{
	//INVALID URL
	"920181-1",
	"942490-17",
	"942260-17",
	"942260-6",
	"942150-6",
	"920240-1",
	"920240-5",
	"920240-6",
	"941130-11",
	"941130-2",
	"941130-4",
	"941130-6",
	"941130-9",
	"941130-10",
	"941130-12",
	"941130-14",
	"941130-16",
	"921150-1",
	"921160-1",
	"941110-6",
	"942100-10",
	"932140-3",
	"941280-2",
	"942100-13",
	//INVALID
	"920120-4", // this is not right, that rule should match
	"920120-6",
	"920120-7",
	// INVALID QUADRUPLE BACKSLASH
	"920460-1",
	"941330-1",
	"920460-2",
	"920460-3",
	"920460-4",
	// WONT FIX
/*	"920450-1",
	"920450-2",
	"920450-3",
	"920450-5",
	"921180-4", // this case is indirect, its because of 921170
	"921180-6", // same as 4 */
	// BAD FORMAT MULTIPART
	"932180-2",
}
var (
	cfgFile string
	debug   bool
	trace   bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ftw run",
	Short: "Framework for Testing WAFs - Coraza Versions\nBased on https://github.com/fzipi/go-ftw",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string) {
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "override config file (default is $PWD/.ftw.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "", false, "debug output")
	rootCmd.PersistentFlags().BoolVarP(&trace, "trace", "", false, "trace output: really, really verbose")
}

func initConfig() {
	//config.Init(cfgFile)
	//zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if debug {
		//zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	if trace {
		//zerolog.SetGlobalLevel(zerolog.TraceLevel)
	}
}

type test struct {
	Name string
}

// cleanCmd represents the clean command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run Tests",
	Long:  `Run all tests below a certain subdirectory. The command will search all y[a]ml files recursively and pass it to the test engine.`,
	Run: func(cmd *cobra.Command, args []string) {
		exclude, _ := cmd.Flags().GetString("exclude")
		include, _ := cmd.Flags().GetString("include")
		dir, _ := cmd.Flags().GetString("dir")
		quiet, _ := cmd.Flags().GetBool("quiet")
		crs, _ := cmd.Flags().GetBool("crs")
		rules, _ := cmd.Flags().GetString("rules")
		var ipattern *regexp.Regexp
		if include != "" {
			ipattern = regexp.MustCompile(include)
		}
		if !quiet {
			//log.Info().Msgf(emoji.Sprintf(":hammer_and_wrench: Starting tests!\n"))
		} else {
			//zerolog.SetGlobalLevel(zerolog.Disabled)
		}
		if exclude != "" && include != "" {
			//log.Fatal().Msgf("You need to choose one: use --include (%s) or --exclude (%s)", include, exclude)
		}
		if rules == "" {
			fmt.Println("rules [-r] path is required.")
			os.Exit(1)
		}
		rs := []string{}
		spl := strings.Split(rules, ",")
		for _, r := range spl {
			matches, err := filepath.Glob(r)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			rs = append(rs, matches...)
		}
		fmt.Printf("Got %d files\n", len(rs))
		for _, f := range rs {
			fmt.Println("Included: " + f)
		}
		files := fmt.Sprintf("%s/**/**/*.yaml", dir)
		var tests []string
		var err error
		if strings.HasSuffix(dir, ".yaml") {
			tests = []string{dir}
		} else {
			tests, err = filepath.Glob(files)

			if err != nil {
				panic(err)
				//log.Fatal().Err(err)
			}
		}

		waf := coraza.NewWaf()
		if debug {
			waf.SetLogLevel(5)
		}
		fmt.Printf("%d profiles were loaded\n", len(tests))
		parser, _ := seclang.NewParser(waf)
		if crs {
			err := parser.FromString(`SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  setvar:tx.paranoia_level=4,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400,\
  setvar:tx.total_arg_length=64000,\
  setvar:tx.max_num_args=255,\
  setvar:tx.combined_file_sizes=65535"`)
			if err != nil {
				panic(err)
			}
		}
		for _, r := range rs {
			err = parser.FromFile(r)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		testlist := []*testing.Test{}
		for _, t := range tests {
			p, err := testing.NewProfile(t)
			if err != nil {
				fmt.Println(err)
			}
			tl, err := p.TestList(waf)
			if err != nil {
				fmt.Println(err)
			}
			testlist = append(testlist, tl...)
		}
		failed := 0
		tlen := len(testlist)
		fname := []string{}
	testLoop:
		for _, t := range testlist {
			if ipattern != nil {
				if !ipattern.MatchString(t.Name) {
					tlen--
					continue
				}
			}
			for _, e := range exceptions {
				if t.Name == e {
					fmt.Println("Skipping " + e)
					tlen--
					continue testLoop
				}
			}
			if err := t.RunPhases(); err != nil {
				fmt.Println(err)
			}
			for _, err := range t.OutputErrors() {
				fname = append(fname, fmt.Sprintf("%q", t.Name))
				if debug {
					fmt.Println("================")
					fmt.Printf("%s\n", t.String())
					fmt.Println(getRuleFromLog(waf, err))
					fmt.Printf("----\n%s\n----\n", t.Request())
					fmt.Printf("%s: %s\n", t.Name, err)
					fmt.Println("================")
				} else {
					fmt.Printf("%s: %s\n", t.Name, err)
				}

				failed++
			}
		}
		fmt.Printf("Failed: [%s]\n", strings.Join(fname, ","))
		fmt.Printf("Passed %d/%d (%.2f%% passed)\n", tlen-failed, tlen, (float64(tlen-failed)/float64(tlen))*100)
	},
}

func getRuleFromLog(waf *coraza.Waf, log string) string {
	re := regexp.MustCompile(`(\d+)`)
	all := re.FindAllString(log, -1)
	if len(all) == 0 {
		fmt.Println("Error finding rule from " + log)
		return ""
	}
	// get last match
	last := all[len(all)-1]
	id, err := strconv.Atoi(last)
	if err != nil {
		fmt.Println("Error converting rule id " + last)
		return ""
	}
	r := waf.Rules.FindByID(id)
	if r == nil {
		fmt.Println("Error finding rule " + last)
		return ""
	}
	raw := ""
	for r != nil {
		raw += r.Raw + "\n"
		r = r.Chain
	}
	return raw
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringP("exclude", "e", "", "exclude tests matching this Go regexp (e.g. to exclude all tests beginning with \"91\", use \"91.*\"). \nIf you want more permanent exclusion, check the 'testmodify' option in the config file.")
	runCmd.Flags().StringP("include", "i", "", "include only tests matching this Go regexp (e.g. to include only tests beginning with \"91\", use \"91.*\").")
	runCmd.Flags().StringP("rules", "r", "", "path to SecLang rules file.")
	runCmd.Flags().StringP("dir", "d", ".", "recursively find yaml tests in this directory")
	runCmd.Flags().BoolP("quiet", "q", false, "do not show test by test, only results")
	runCmd.Flags().BoolP("time", "t", false, "show time spent per test")
	runCmd.Flags().BoolP("crs", "c", false, "Use CRS default variables.")
}

func main() {
	Execute(
		"version",
	)
}
