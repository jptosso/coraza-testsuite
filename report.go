package main

import (
	"fmt"
	"html/template"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/testing"
	"github.com/corazawaf/coraza/v3/testing/profile"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
	"gopkg.in/yaml.v3"
)

type test struct {
	Profile     profile.Profile
	Test        *testing.Test
	Waf         *coraza.Waf
	Transaction *coraza.Transaction
	Logs        []string
	Errors      []string
	Debug       *debugLogger
}

func (t *test) Variables() []types.MatchData {
	res := make([]types.MatchData, 0)
	for i := 1; i < types.VariablesCount; i++ {
		if t.Transaction.Collections[i] == nil {
			fmt.Printf("BUG: collection %s is nil\n", variables.RuleVariable(i).Name())
			continue
		}

		md := t.Transaction.Collections[i].FindAll()
		res = append(res, md...)
	}
	return res
}

func (t *test) Write(filename string) error {
	// we use the template.html file to create an html template and we send t
	tmpl, err := template.New("main").ParseFiles("template.html")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if err := tmpl.ExecuteTemplate(file, "template.html", t); err != nil {
		return err
	}
	return nil
}

func (t *test) Yaml() string {
	for _, test := range t.Profile.Tests {
		if test.Title == t.Test.Name {
			out, err := yaml.Marshal(test)
			if err != nil {
				fmt.Println("Error:", err)
				return ""
			}
			return string(out)
		}
	}
	return ""
}

func (t *test) PrettyLogs() string {
	if len(t.Logs) == 0 {
		return "No logs..."
	}
	return strings.Join(t.Logs, "\n")
}

func (t *test) Args() string {
	return strings.Join(os.Args, " ")
}

func (t *test) FindRule(rule string) string {
	re := regexp.MustCompile(`[0-9]{4,}`)
	idMatch := re.FindString(rule)
	if idMatch == "" {
		return ""
	}
	id, _ := strconv.Atoi(idMatch)
	for _, r := range t.Transaction.Waf.Rules.GetRules() {
		if r.ID == id {
			data := r.Raw
			for r.Chain != nil {
				data += "\n" + r.Chain.Raw
				r = r.Chain
			}
			return data
		}
	}
	return ""
}

type debugLogger struct {
	Logs []string
}

// implement io.Writer
func (d *debugLogger) Write(p []byte) (n int, err error) {
	d.Logs = append(d.Logs, string(p))
	return len(p), nil
}

func newTest(profile profile.Profile, t *testing.Test) *test {
	dl := &debugLogger{}
	logs := make([]string, 0)
	waf.Logger.SetOutput(dl)
	waf.SetErrorLogCb(func(mr types.MatchedRule) {
		logs = append(logs, mr.ErrorLog(500))
	})
	return &test{
		Profile: profile,
		Test:    t,
		Debug:   dl,
		Logs:    logs,
	}
}
