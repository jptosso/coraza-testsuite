module github.com/jptosso/coraza-testsuite

go 1.16

replace github.com/corazawaf/coraza/v3 => ../coraza-waf

require (
	github.com/corazawaf/coraza/v3 v3.0.0-20220809214813-b7f266dc7231
	gopkg.in/yaml.v3 v3.0.1
)
