// Copyright 2016 The rkt Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/coreos/rkt/rkt/image/fetchers"
	"github.com/hashicorp/errwrap"
)

func errAndExit(config *fetchers.Config, format string, args ...interface{}) {
	if config != nil && config.Debug {
		for i, arg := range args {
			if wrappedErr, ok := arg.(errwrap.Wrapper); ok {
				var errStr string
				for _, err := range wrappedErr.WrappedErrors() {
					if errStr == "" {
						errStr = err.Error()
					} else {
						errStr += ": " + err.Error()
					}
				}
				args[i] = fmt.Errorf(errStr)
			}
		}
	}
	stderr(format, args...)
	os.Exit(1)
}

func stderr(format string, a ...interface{}) {
	out := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, strings.TrimSuffix(out, "\n"))
}

func main() {
	config, err := fetchers.ConfigFromStdin()
	if err != nil {
		errAndExit(config, "error reading config: %v", err)
	}

	if config.Version != 1 {
		errAndExit(config, "unsupported plugin schema version")
	}

	if !config.InsecureOpts.AllowHTTP && config.Scheme == "http" {
		errAndExit(config, "error: http URLs not allowed")
	}

	err = fetch(config)
	if err != nil {
		errAndExit(config, "error fetching http(s) image: %v", err)
	}
}

func fetch(config *fetchers.Config) error {
	if config.InsecureOpts.SkipTLSCheck {
		stderr("warning: TLS verification has been disabled")
	}
	if config.InsecureOpts.SkipImageCheck {
		stderr("warning: image signature verification has been disabled")
	}
	if config.InsecureOpts.AllowHTTP {
		stderr("warning: image allowed to be fetched without encryption")
	}
	o := &httpOps{*config}
	retry := false
	if !config.InsecureOpts.SkipImageCheck {
		var err error
		retry, err = o.DownloadSignature()
		if err != nil {
			return err
		}
	}
	cd, err := o.DownloadImage()
	if err != nil {
		return err
	}
	res := &fetchers.Result{
		Latest:    false,
		ETag:      cd.ETag,
		MaxAge:    cd.MaxAge,
		UseCached: cd.UseCached,
	}
	if retry {
		err = o.DownloadSignatureAgain()
		if err != nil {
			return err
		}
	}
	return fetchers.ResultToStdout(res)
}
