package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cheggaaa/pb/v3"
	coraza "github.com/jptosso/coraza-waf"
	"github.com/jptosso/coraza-waf/seclang"
	"github.com/jptosso/coraza-waf/testing"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

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
	Name   string
	Stages []testing.ProfileTestStage
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
		rules, _ := cmd.Flags().GetString("rules")
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
		files := fmt.Sprintf("%s/**/**/*.yaml", dir)
		tests, err := filepath.Glob(files)

		if err != nil {
			panic(err)
			//log.Fatal().Err(err)
		}
		waf := coraza.NewWaf()
		waf.Logger.Info(fmt.Sprintf("%d profiles were loaded", len(tests)), zap.String("path", dir))
		parser, _ := seclang.NewParser(waf)
		err = parser.FromFile(rules)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		testcount := 0
		testlist := []test{}
		for _, t := range tests {
			p, err := testing.NewProfile(t)
			if err != nil {
				panic(err)
			}
			//first we count tests
			for _, tt := range p.Tests {
				testlist = append(testlist, test{tt.Title, tt.Stages})
				testcount += len(tt.Stages)
			}
		}
		bar := pb.Full.Start(testcount)
		failed := []string{}
		for _, t := range testlist {
			for _, s := range t.Stages {
				err := s.Start(waf)
				if err != nil {
					failed = append(failed, t.Name)
				}
				bar.Increment()
			}
		}
		bar.Finish()
		fmt.Printf("failed: [%s]\n", strings.Join(failed, ", "))
		fmt.Printf("Result: passed %d/%d\n", testcount-len(failed), testcount)
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringP("exclude", "e", "", "exclude tests matching this Go regexp (e.g. to exclude all tests beginning with \"91\", use \"91.*\"). \nIf you want more permanent exclusion, check the 'testmodify' option in the config file.")
	runCmd.Flags().StringP("include", "i", "", "include only tests matching this Go regexp (e.g. to include only tests beginning with \"91\", use \"91.*\").")
	runCmd.Flags().StringP("rules", "r", "", "path to SecLang rules file.")
	runCmd.Flags().StringP("dir", "d", ".", "recursively find yaml tests in this directory")
	runCmd.Flags().BoolP("quiet", "q", false, "do not show test by test, only results")
	runCmd.Flags().BoolP("time", "t", false, "show time spent per test")
}

func main() {
	Execute(
		"version",
	)
}
