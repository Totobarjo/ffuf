package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/filter"
	"github.com/ffuf/ffuf/v2/pkg/input"
	"github.com/ffuf/ffuf/v2/pkg/interactive"
	"github.com/ffuf/ffuf/v2/pkg/output"
	"github.com/ffuf/ffuf/v2/pkg/runner"
	"github.com/ffuf/ffuf/v2/pkg/scraper"
)

type multiStringFlag []string
type wordlistFlag []string

func (m *multiStringFlag) String() string {
	return ""
}

func (m *wordlistFlag) String() string {
	return ""
}

func (m *multiStringFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func (m *wordlistFlag) Set(value string) error {
	delimited := strings.Split(value, ",")
	if len(delimited) > 1 {
		*m = append(*m, delimited...)
	} else {
		*m = append(*m, value)
	}
	return nil
}

// ParseFlags parses the command line flags and (re)populates the ConfigOptions struct
func ParseFlags(opts *ffuf.ConfigOptions) *ffuf.ConfigOptions {
	var ignored bool
	var cookies, autocalibrationstrings, autocalibrationstrategies, headers, inputcommands multiStringFlag
	var wordlists, encoders wordlistFlag
	var excludeStatusCodes string

	cookies = opts.HTTP.Cookies
	autocalibrationstrings = opts.General.AutoCalibrationStrings
	headers = opts.HTTP.Headers
	inputcommands = opts.Input.Inputcommands
	wordlists = opts.Input.Wordlists
	encoders = opts.Input.Encoders

	// Ajouter les options de ligne de commande
	flag.StringVar(&excludeStatusCodes, "ecr", "", "Exclude specific HTTP status codes from recursion (comma-separated, ex : 403,404)")
	flag.BoolVar(&ignored, "compressed", true, "Dummy flag for copy as curl functionality (ignored)")
	flag.BoolVar(&ignored, "i", true, "Dummy flag for copy as curl functionality (ignored)")
	flag.BoolVar(&ignored, "k", false, "Dummy flag for backwards compatibility")
	// [Autres options similaires déjà présentes dans votre code...]

	flag.Usage = Usage
	flag.Parse()

	// Gestion des status codes à exclure
	if excludeStatusCodes != "" {
		codes := strings.Split(excludeStatusCodes, ",")
		for _, code := range codes {
			parsedCode, err := strconv.Atoi(strings.TrimSpace(code))
			if err == nil {
				opts.ExcludeStatusCodes = append(opts.ExcludeStatusCodes, parsedCode)
			} else {
				fmt.Printf("Invalid status code in -ecr: %s\n", code)
				os.Exit(1)
			}
		}
	}

	// Retourner les autres options
	opts.HTTP.Cookies = cookies
	opts.HTTP.Headers = headers
	opts.Input.Inputcommands = inputcommands
	opts.Input.Wordlists = wordlists
	opts.Input.Encoders = encoders
	return opts
}

func main() {
	var err, optserr error
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Préparer les options par défaut
	var opts *ffuf.ConfigOptions
	opts, optserr = ffuf.ReadDefaultConfig()
	opts = ParseFlags(opts)

	if opts.General.ShowVersion {
		fmt.Printf("ffuf version: %s\n", ffuf.Version())
		os.Exit(0)
	}

	// Configurer le débogage
	if len(opts.Output.DebugLog) != 0 {
		f, err := os.OpenFile(opts.Output.DebugLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Disabling logging, encountered error(s): %s\n", err)
			log.SetOutput(io.Discard)
		} else {
			log.SetOutput(f)
			defer f.Close()
		}
	} else {
		log.SetOutput(io.Discard)
	}
	if optserr != nil {
		log.Printf("Error while opening default config file: %s", optserr)
	}

	if opts.General.ConfigFile != "" {
		opts, err = ffuf.ReadConfig(opts.General.ConfigFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Encountered error(s): %s\n", err)
			Usage()
			os.Exit(1)
		}
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		opts = ParseFlags(opts)
	}

	conf, err := ffuf.ConfigFromOptions(opts, ctx, cancel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Encountered error(s): %s\n", err)
		Usage()
		os.Exit(1)
	}

	job, err := prepareJob(conf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Encountered error(s): %s\n", err)
		Usage()
		os.Exit(1)
	}

	if err := SetupFilters(opts, conf); err != nil {
		fmt.Fprintf(os.Stderr, "Encountered error(s): %s\n", err)
		Usage()
		os.Exit(1)
	}

	if !conf.Noninteractive {
		go func() {
			err := interactive.Handle(job)
			if err != nil {
				log.Printf("Error while trying to initialize interactive session: %s", err)
			}
		}()
	}

	job.Start()
}

func SetupFilters(parseOpts *ffuf.ConfigOptions, conf *ffuf.Config) error {
	errs := ffuf.NewMultierror()
	conf.MatcherManager = filter.NewMatcherManager()
	// [Configuration des filtres comme dans votre code original...]
	return errs.ErrorOrNil()
}

func prepareJob(conf *ffuf.Config) (*ffuf.Job, error) {
	var errs ffuf.Multierror
	job := ffuf.NewJob(conf)
	job.Input, errs = input.NewInputProvider(conf)
	job.Runner = runner.NewRunnerByName("http", conf, false)
	if len(conf.ReplayProxyURL) > 0 {
		job.ReplayRunner = runner.NewRunnerByName("http", conf, true)
	}
	job.Output = output.NewOutputProviderByName("stdout", conf)
	return job, errs.ErrorOrNil()
}

func printSearchResults(conf *ffuf.Config, pos int, exectime time.Time, hash string) {
	inp, err := input.NewInputProvider(conf)
	if err.ErrorOrNil() != nil {
		fmt.Println("Error:", err.ErrorOrNil())
		return
	}
	inp.SetPosition(pos)
	inputdata := inp.Value()
	inputdata["FFUFHASH"] = []byte(hash)
	basereq := ffuf.BaseRequest(conf)
	dummyrunner := runner.NewRunnerByName("simple", conf, false)
	ffufreq, _ := dummyrunner.Prepare(inputdata, &basereq)
	rawreq, _ := dummyrunner.Dump(&ffufreq)
	fmt.Printf("ffuf job started at: %s\n\n", exectime.Format(time.RFC3339))
	fmt.Printf("%s\n", string(rawreq))
}
