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

package fetchers

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

type Headers map[string][]string

type InsecureOpts struct {
	AllowHTTP      bool `json:"allow_http"`
	SkipTLSCheck   bool `json:"skip_tls_check"`
	SkipImageCheck bool `json:"skip_image_check"`
}

type Config struct {
	Version       int                `json:"version"`
	Scheme        string             `json:"scheme"`
	AciName       string             `json:"aci_name"`
	AscName       string             `json:"asc_name"`
	InsecureOpts  InsecureOpts       `json:"insecure"`
	Debug         bool               `json:"debug"`
	Headers       map[string]Headers `json:"headers"`
	OutputACIPath string             `json:"output_aci_path"`
	OutputASCPath string             `json:"output_asc_path"`
}

type Result struct {
	Latest    bool   `json:"latest"`
	ETag      string `json:"etag"`
	MaxAge    int    `json:"max_age"`
	UseCached bool   `json:"use_cached"`
}

func ConfigFromStdin() (*Config, error) {
	confblob, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	config := &Config{}
	err = json.Unmarshal(confblob, config)
	return config, err
}

func ResultToStdout(res *Result) error {
	resBlob, err := json.Marshal(res)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(resBlob)
	return err
}
