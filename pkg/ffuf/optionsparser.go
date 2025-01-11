package ffuf

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml"
)

// ConfigOptions est déjà défini en détail dans ton code (HTTPOptions, GeneralOptions, etc.).
// Ici, on suppose que c'est importé du même package ou que c'est juste au-dessus.
//
// Idem pour:
//   func ReadConfig(...)
//   func ReadDefaultConfig(...)
//   etc.
//
// Le plus important: on ne re-déclare pas NewConfig ni templatePresent, keywordPresent ici.


// ConfigFromOptions : parse la config, appelle NewConfig pour construire *Config, 
// puis fait les vérifications / compléments nécessaires avant de renvoyer (*Config, error).
func ConfigFromOptions(parseOpts *ConfigOptions, ctx context.Context, cancel context.CancelFunc) (*Config, error) {
	// On suppose que tu as un type Multierror et une fonction NewMultierror() quelque part dans pkg/ffuf.
	errs := NewMultierror()

	// On appelle NewConfig (déjà définie dans config.go)
	conf, err := NewConfig(parseOpts, ctx, cancel)
	if err != nil {
		// gérer l’erreur au besoin
		return nil, err
	}

	var err2 error
	if len(parseOpts.HTTP.URL) == 0 && parseOpts.Input.Request == "" {
		errs.Add(fmt.Errorf("-u flag or -request flag is required"))
	}

	// prepare extensions
	if parseOpts.Input.Extensions != "" {
		extensions := strings.Split(parseOpts.Input.Extensions, ",")
		conf.Extensions = extensions
	}

	// Convert cookies to a header
	if len(parseOpts.HTTP.Cookies) > 0 {
		parseOpts.HTTP.Headers = append(parseOpts.HTTP.Headers, "Cookie: "+strings.Join(parseOpts.HTTP.Cookies, "; "))
	}

	// Prepare inputproviders
	conf.InputMode = parseOpts.Input.InputMode

	validmode := false
	for _, mode := range []string{"clusterbomb", "pitchfork", "sniper"} {
		if conf.InputMode == mode {
			validmode = true
		}
	}
	if !validmode {
		errs.Add(fmt.Errorf("Input mode (-mode) %s not recognized", conf.InputMode))
	}

	template := ""
	// sniper mode needs some additional checking
	if conf.InputMode == "sniper" {
		template = "§"

		if len(parseOpts.Input.Wordlists) > 1 {
			errs.Add(fmt.Errorf("sniper mode only supports one wordlist"))
		}

		if len(parseOpts.Input.Inputcommands) > 1 {
			errs.Add(fmt.Errorf("sniper mode only supports one input command"))
		}
	}

	// On gère les encoders
	tmpEncoders := make(map[string]string)
	for _, e := range parseOpts.Input.Encoders {
		if strings.Contains(e, ":") {
			key := strings.Split(e, ":")[0]
			val := strings.Split(e, ":")[1]
			tmpEncoders[key] = val
		}
	}

	// On gère les wordlists
	tmpWordlists := make([]string, 0)
	for _, v := range parseOpts.Input.Wordlists {
		var wl []string
		if runtime.GOOS == "windows" {
			// Gérer le cas de chemins Windows
			if FileExists(v) {
				// Le wordlist a été fourni sans mot-clé
				wl = []string{v}
			} else {
				filepart := v
				if strings.Contains(filepart, ":") {
					filepart = v[:strings.LastIndex(filepart, ":")]
				}

				if FileExists(filepart) {
					wl = []string{filepart, v[strings.LastIndex(v, ":")+1:]}
				} else {
					wl = []string{v}
				}
			}
		} else {
			wl = strings.SplitN(v, ":", 2)
		}
		// Essayer d'avoir un chemin absolu
		fullpath := ""
		var err error
		if wl[0] != "-" {
			fullpath, err = filepath.Abs(wl[0])
		} else {
			fullpath = wl[0]
		}

		if err == nil {
			wl[0] = fullpath
		}
		if len(wl) == 2 {
			if conf.InputMode == "sniper" {
				errs.Add(fmt.Errorf("sniper mode does not support wordlist keywords"))
			} else {
				newp := InputProviderConfig{
					Name:    "wordlist",
					Value:   wl[0],
					Keyword: wl[1],
				}
				// Add encoders if set
				enc, ok := tmpEncoders[wl[1]]
				if ok {
					newp.Encoders = enc
				}
				conf.InputProviders = append(conf.InputProviders, newp)
			}
		} else {
			newp := InputProviderConfig{
				Name:     "wordlist",
				Value:    wl[0],
				Keyword:  "FUZZ",
				Template: template,
			}
			enc, ok := tmpEncoders["FUZZ"]
			if ok {
				newp.Encoders = enc
			}
			conf.InputProviders = append(conf.InputProviders, newp)
		}
		tmpWordlists = append(tmpWordlists, strings.Join(wl, ":"))
	}
	conf.Wordlists = tmpWordlists

	// On gère les inputcommands
	for _, v := range parseOpts.Input.Inputcommands {
		ic := strings.SplitN(v, ":", 2)
		if len(ic) == 2 {
			if conf.InputMode == "sniper" {
				errs.Add(fmt.Errorf("sniper mode does not support command keywords"))
			} else {
				newp := InputProviderConfig{
					Name:    "command",
					Value:   ic[0],
					Keyword: ic[1],
				}
				enc, ok := tmpEncoders[ic[1]]
				if ok {
					newp.Encoders = enc
				}
				conf.InputProviders = append(conf.InputProviders, newp)
				conf.CommandKeywords = append(conf.CommandKeywords, ic[0])
			}
		} else {
			newp := InputProviderConfig{
				Name:     "command",
				Value:    ic[0],
				Keyword:  "FUZZ",
				Template: template,
			}
			enc, ok := tmpEncoders["FUZZ"]
			if ok {
				newp.Encoders = enc
			}
			conf.InputProviders = append(conf.InputProviders, newp)
			conf.CommandKeywords = append(conf.CommandKeywords, "FUZZ")
		}
	}
	if len(conf.InputProviders) == 0 {
		errs.Add(fmt.Errorf("Either -w or --input-cmd flag is required"))
	}

	// Préparation du request via body brut
	if parseOpts.Input.Request != "" {
		err := parseRawRequest(parseOpts, conf)
		if err != nil {
			errmsg := fmt.Sprintf("Could not parse raw request: %s", err)
			errs.Add(fmt.Errorf(errmsg))
		}
	}

	// Préparation de l'URL
	if parseOpts.HTTP.URL != "" {
		conf.Url = parseOpts.HTTP.URL
	}
	// SNI
	if parseOpts.HTTP.SNI != "" {
		conf.SNI = parseOpts.HTTP.SNI
	}
	// Cert
	if parseOpts.HTTP.ClientCert != "" {
		conf.ClientCert = parseOpts.HTTP.ClientCert
	}
	if parseOpts.HTTP.ClientKey != "" {
		conf.ClientKey = parseOpts.HTTP.ClientKey
	}

	// Préparation des headers (Make canonical)
	for _, v := range parseOpts.HTTP.Headers {
		hs := strings.SplitN(v, ":", 2)
		if len(hs) == 2 {
			var CanonicalNeeded = true
			// Vérifier s'il y a des keywords dans la clé
			for _, a := range conf.CommandKeywords {
				if strings.Contains(hs[0], a) {
					CanonicalNeeded = false
				}
			}
			for _, b := range conf.InputProviders {
				if strings.Contains(hs[0], b.Keyword) {
					CanonicalNeeded = false
				}
			}
			if CanonicalNeeded {
				var CanonicalHeader = textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(hs[0]))
				conf.Headers[CanonicalHeader] = strings.TrimSpace(hs[1])
			} else {
				conf.Headers[strings.TrimSpace(hs[0])] = strings.TrimSpace(hs[1])
			}
		} else {
			errs.Add(fmt.Errorf("Header defined by -H needs to have a value. \":\" should be used as a separator"))
		}
	}

	// Préparation du delay
	d := strings.Split(parseOpts.General.Delay, "-")
	if len(d) > 2 {
		errs.Add(fmt.Errorf("Delay needs to be either a single float: \"0.1\" or a range of floats, delimited by dash: \"0.1-0.8\""))
	} else if len(d) == 2 {
		conf.Delay.IsRange = true
		conf.Delay.HasDelay = true
		conf.Delay.Min, err = strconv.ParseFloat(d[0], 64)
		conf.Delay.Max, err2 = strconv.ParseFloat(d[1], 64)
		if err != nil || err2 != nil {
			errs.Add(fmt.Errorf("Delay range min and max values need to be valid floats. For example: 0.1-0.5"))
		}
	} else if len(parseOpts.General.Delay) > 0 {
		conf.Delay.IsRange = false
		conf.Delay.HasDelay = true
		conf.Delay.Min, err = strconv.ParseFloat(parseOpts.General.Delay, 64)
		if err != nil {
			errs.Add(fmt.Errorf("Delay needs to be either a single float: \"0.1\" or a range of floats, delimited by dash: \"0.1-0.8\""))
		}
	}

	// Proxy
	if len(parseOpts.HTTP.ProxyURL) > 0 {
		u, err := url.Parse(parseOpts.HTTP.ProxyURL)
		if err != nil || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
			errs.Add(fmt.Errorf("Bad proxy url (-x) format. Expected http, https or socks5 url"))
		} else {
			conf.ProxyURL = parseOpts.HTTP.ProxyURL
		}
	}

	// Replay proxy
	if len(parseOpts.HTTP.ReplayProxyURL) > 0 {
		u, err := url.Parse(parseOpts.HTTP.ReplayProxyURL)
		if err != nil || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" && u.Scheme != "socks5h") {
			errs.Add(fmt.Errorf("Bad replay-proxy url (-replay-proxy) format. Expected http, https or socks5 url"))
		} else {
			conf.ReplayProxyURL = parseOpts.HTTP.ReplayProxyURL
		}
	}

	// Sortie
	if parseOpts.Output.OutputFile != "" {
		outputFormats := []string{"all", "json", "ejson", "html", "md", "csv", "ecsv"}
		found := false
		for _, f := range outputFormats {
			if f == parseOpts.Output.OutputFormat {
				conf.OutputFormat = f
				found = true
			}
		}
		if !found {
			errs.Add(fmt.Errorf("Unknown output file format (-of): %s", parseOpts.Output.OutputFormat))
		}
	}

	// Auto-calibration strings / strategies
	if len(parseOpts.General.AutoCalibrationStrings) > 0 {
		conf.AutoCalibrationStrings = parseOpts.General.AutoCalibrationStrings
	}
	if len(parseOpts.General.AutoCalibrationStrategies) > 0 {
		conf.AutoCalibrationStrategies = parseOpts.General.AutoCalibrationStrategies
	}
	if len(parseOpts.General.AutoCalibrationStrings) > 0 {
		conf.AutoCalibration = true
	}
	if len(parseOpts.General.AutoCalibrationStrategies) > 0 {
		conf.AutoCalibration = true
	}

	if parseOpts.General.Rate < 0 {
		conf.Rate = 0
	} else {
		conf.Rate = int64(parseOpts.General.Rate)
	}

	if conf.Method == "" {
		if parseOpts.HTTP.Method == "" {
			conf.Method = "GET"
		} else {
			conf.Method = parseOpts.HTTP.Method
		}
	} else {
		if parseOpts.HTTP.Method != "" {
			conf.Method = parseOpts.HTTP.Method
		}
	}

	if parseOpts.HTTP.Data != "" {
		conf.Data = parseOpts.HTTP.Data
	}

	// Divers
	conf.IgnoreWordlistComments = parseOpts.Input.IgnoreWordlistComments
	conf.DirSearchCompat = parseOpts.Input.DirSearchCompat
	conf.Colors = parseOpts.General.Colors
	conf.InputNum = parseOpts.Input.InputNum
	conf.InputShell = parseOpts.Input.InputShell
	conf.OutputFile = parseOpts.Output.OutputFile
	conf.OutputDirectory = parseOpts.Output.OutputDirectory
	conf.OutputSkipEmptyFile = parseOpts.Output.OutputSkipEmptyFile
	conf.IgnoreBody = parseOpts.HTTP.IgnoreBody
	conf.Quiet = parseOpts.General.Quiet
	conf.ScraperFile = parseOpts.General.ScraperFile
	conf.Scrapers = parseOpts.General.Scrapers
	conf.StopOn403 = parseOpts.General.StopOn403
	conf.StopOnAll = parseOpts.General.StopOnAll
	conf.StopOnErrors = parseOpts.General.StopOnErrors
	conf.FollowRedirects = parseOpts.HTTP.FollowRedirects
	conf.Raw = parseOpts.HTTP.Raw
	conf.Recursion = parseOpts.HTTP.Recursion
	conf.RecursionDepth = parseOpts.HTTP.RecursionDepth
	conf.RecursionStrategy = parseOpts.HTTP.RecursionStrategy
	conf.AutoCalibration = parseOpts.General.AutoCalibration
	conf.AutoCalibrationPerHost = parseOpts.General.AutoCalibrationPerHost
	conf.AutoCalibrationStrategies = parseOpts.General.AutoCalibrationStrategies
	conf.Threads = parseOpts.General.Threads
	conf.Timeout = parseOpts.HTTP.Timeout
	conf.MaxTime = parseOpts.General.MaxTime
	conf.MaxTimeJob = parseOpts.General.MaxTimeJob
	conf.Noninteractive = parseOpts.General.Noninteractive
	conf.Verbose = parseOpts.General.Verbose
	conf.Json = parseOpts.General.Json
	conf.Http2 = parseOpts.HTTP.Http2

	// Check fmode et mmode
	valid_opmodes := []string{"and", "or"}
	fmode_found := false
	mmode_found := false
	for _, v := range valid_opmodes {
		if v == parseOpts.Filter.Mode {
			fmode_found = true
		}
		if v == parseOpts.Matcher.Mode {
			mmode_found = true
		}
	}
	if !fmode_found {
		errmsg := fmt.Sprintf("Unrecognized value for parameter fmode: %s, valid values are: and, or", parseOpts.Filter.Mode)
		errs.Add(fmt.Errorf(errmsg))
	}
	if !mmode_found {
		errmsg := fmt.Sprintf("Unrecognized value for parameter mmode: %s, valid values are: and, or", parseOpts.Matcher.Mode)
		errs.Add(fmt.Errorf(errmsg))
	}
	conf.FilterMode = parseOpts.Filter.Mode
	conf.MatcherMode = parseOpts.Matcher.Mode

	if conf.AutoCalibrationPerHost {
		conf.AutoCalibration = true
	}

	// Gérer data + GET
	if len(conf.Data) > 0 &&
		conf.Method == "GET" &&
		len(parseOpts.Input.Request) == 0 {
		conf.Method = "POST"
	}

	conf.CommandLine = strings.Join(os.Args, " ")

	// Filtrage final des inputProviders si le template ou le keyword n'est pas trouvé
	newInputProviders := []InputProviderConfig{}
	for _, provider := range conf.InputProviders {
		if provider.Template != "" {
			// templatePresent(...) doit exister dans config.go (même package)
			if !templatePresent(provider.Template, conf) {
				errmsg := fmt.Sprintf("Template %s defined, but not found in pairs in headers, method, URL or POST data.", provider.Template)
				errs.Add(fmt.Errorf(errmsg))
			} else {
				newInputProviders = append(newInputProviders, provider)
			}
		} else {
			// keywordPresent(...) doit exister dans config.go (même package)
			if !keywordPresent(provider.Keyword, conf) {
				errmsg := fmt.Sprintf("Keyword %s defined, but not found in headers, method, URL or POST data.", provider.Keyword)
				_, _ = fmt.Fprintf(os.Stderr, "%s\n", fmt.Errorf(errmsg))
			} else {
				newInputProviders = append(newInputProviders, provider)
			}
		}
	}
	conf.InputProviders = newInputProviders

	// sniper + FUZZ
	if conf.InputMode == "sniper" {
		if keywordPresent("FUZZ", conf) {
			errs.Add(fmt.Errorf("FUZZ keyword defined, but we are using sniper mode."))
		}
	}

	// Recursion + URL
	if parseOpts.HTTP.Recursion {
		if !strings.HasSuffix(conf.Url, "FUZZ") {
			errmsg := "When using -recursion the URL (-u) must end with FUZZ keyword."
			errs.Add(fmt.Errorf(errmsg))
		}
	}

	// -json et -v sont mutuellement exclusifs
	if parseOpts.General.Verbose && parseOpts.General.Json {
		errs.Add(fmt.Errorf("Cannot have -json and -v"))
	}

	// On renvoie le conf final et la MultiError potentielle
	return conf, errs.ErrorOrNil()
}

// parseRawRequest : lit une requête brute depuis parseOpts.Input.Request 
// et remplit conf (URL, Headers, Data, etc.)
func parseRawRequest(parseOpts *ConfigOptions, conf *Config) error {
	conf.RequestFile = parseOpts.Input.Request
	conf.RequestProto = parseOpts.Input.RequestProto
	file, err := os.Open(parseOpts.Input.Request)
	if err != nil {
		return fmt.Errorf("could not open request file: %s", err)
	}
	defer file.Close()

	r := bufio.NewReader(file)

	s, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("could not read request: %s", err)
	}
	parts := strings.Split(s, " ")
	if len(parts) < 3 {
		return fmt.Errorf("malformed request supplied")
	}
	// Set the request Method
	conf.Method = parts[0]

	for {
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)

		if err != nil || line == "" {
			break
		}

		p := strings.SplitN(line, ":", 2)
		if len(p) != 2 {
			continue
		}

		// On ignore content-length
		if strings.EqualFold(p[0], "content-length") {
			continue
		}
		conf.Headers[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
	}

	// Gérer le cas où la 2e partie (parts[1]) commence par http...
	if strings.HasPrefix(parts[1], "http") {
		parsed, err := url.Parse(parts[1])
		if err != nil {
			return fmt.Errorf("could not parse request URL: %s", err)
		}
		conf.Url = parts[1]
		conf.Headers["Host"] = parsed.Host
	} else {
		conf.Url = parseOpts.Input.RequestProto + "://" + conf.Headers["Host"] + parts[1]
	}

	b, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("could not read request body: %s", err)
	}
	conf.Data = string(b)

	if strings.HasSuffix(conf.Data, "\r\n") {
		conf.Data = conf.Data[:len(conf.Data)-2]
	} else if strings.HasSuffix(conf.Data, "\n") {
		conf.Data = conf.Data[:len(conf.Data)-1]
	}
	return nil
}

// ReadConfig / ReadDefaultConfig : inchangés si tu les utilises pareil.
func ReadConfig(configFile string) (*ConfigOptions, error) {
	conf := NewConfigOptions()
	configData, err := os.ReadFile(configFile)
	if err == nil {
		err = toml.Unmarshal(configData, conf)
	}
	return conf, err
}

func ReadDefaultConfig() (*ConfigOptions, error) {
	_ = CheckOrCreateConfigDir()
	conffile := filepath.Join(CONFIGDIR, "ffufrc")
	if !FileExists(conffile) {
		userhome, err := os.UserHomeDir()
		if err == nil {
			conffile = filepath.Join(userhome, ".ffufrc")
		}
	}
	return ReadConfig(conffile)
}
