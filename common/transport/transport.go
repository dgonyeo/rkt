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

package transport

import (
	"bytes"
	//"crypto/sha512"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	//"time"

	"github.com/coreos/rkt/common/transport/plugins"
	//"github.com/coreos/rkt/pkg/keystore"
	"github.com/coreos/rkt/rkt/config"
	rktflag "github.com/coreos/rkt/rkt/flag"
	"github.com/coreos/rkt/store/imagestore"
)

const (
	pluginTemplate = "rkt-transport-%s"
)

type Transport struct {
	InsecureFlags *rktflag.SecFlags
	Auth          map[string]config.Headerer
	Rem           *imagestore.Remote
	Debug         bool
}

func (t *Transport) Fetch(aciUrl, ascUrl *url.URL, aciPath, ascPath string) (*plugins.Result, error) {
	//ensureLogger(f.Debug)

	res, err := t.FetchToPath(aciUrl, ascUrl, aciPath, ascPath)
	if err != nil {
		return nil, err
	}

	if t.Rem != nil && res.UseCached {
		res.UseCached = true
		return res, nil
	}

	return res, nil
}

func (t *Transport) FetchToPath(aciUrl, ascUrl *url.URL, aciPath, ascPath string) (*plugins.Result, error) {
	//ensureLogger(f.Debug)

	if t.Debug {
		fmt.Printf("fetching image from %s", aciUrl.String())
	}

	pluginName := fmt.Sprintf(pluginTemplate, aciUrl.Scheme)

	var pluginPath string
	var err error
	tmpPath := path.Join(path.Dir(os.Args[0]), pluginName)
	if _, err := os.Stat(tmpPath); err == nil {
		pluginPath = tmpPath
	} else {
		pluginPath, err = exec.LookPath(pluginName)
		if err != nil {
			return nil, fmt.Errorf("unable to find a plugin for the scheme %q", aciUrl.Scheme)
		}
	}

	auth := make(map[string]plugins.Headers)
	for host, headerer := range t.Auth {
		headers := make(plugins.Headers)
		for k, v := range headerer.GetHeader() {
			headers[k] = v
		}
		auth[host] = headers
	}

	conf := &plugins.Config{
		Version: 1,
		Scheme:  aciUrl.Scheme,
		AciName: path.Join(aciUrl.Host, aciUrl.Path),
		AscName: path.Join(ascUrl.Host, ascUrl.Path),
		InsecureOpts: plugins.InsecureOpts{
			AllowHTTP:      t.InsecureFlags.AllowHTTP(),
			SkipTLSCheck:   t.InsecureFlags.SkipTLSCheck(),
			SkipImageCheck: t.InsecureFlags.SkipImageCheck(),
		},
		Debug:         t.Debug,
		Headers:       auth,
		OutputACIPath: aciPath,
		OutputASCPath: ascPath,
	}
	confBlob, err := json.Marshal(conf)
	stdinBuffer := bytes.NewBuffer(confBlob)

	stdoutBuf := &bytes.Buffer{}

	cmd := exec.Command(pluginPath)
	cmd.Stdin = stdinBuffer
	cmd.Stderr = os.Stderr
	cmd.Stdout = stdoutBuf
	err = cmd.Run()
	if err != nil {
		return nil, err
	}

	resBlob := stdoutBuf.Bytes()
	res := &plugins.Result{}
	err = json.Unmarshal(resBlob, res)
	if err != nil {
		return nil, err
	}
	return res, nil
}
