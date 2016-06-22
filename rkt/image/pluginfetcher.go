// Copyright 2015 The rkt Authors
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

package image

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"time"

	"github.com/coreos/rkt/pkg/keystore"
	"github.com/coreos/rkt/rkt/config"
	rktflag "github.com/coreos/rkt/rkt/flag"
	"github.com/coreos/rkt/rkt/image/fetchers"
	"github.com/coreos/rkt/store/imagestore"
)

const (
	pluginTemplate = "rkt-fetcher-%s"
)

type pluginFetcher struct {
	InsecureFlags *rktflag.SecFlags
	Auth          map[string]config.Headerer
	S             *imagestore.Store
	Ks            *keystore.Keystore
	Debug         bool
	Rem           *imagestore.Remote
}

func (f *pluginFetcher) Hash(aciUrl *url.URL) (string, error) {
	ensureLogger(f.Debug)

	tmpDir, err := f.GetHashedTmpDir(aciUrl)
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	aciFilePath := path.Join(tmpDir, "aci")
	ascFilePath := path.Join(tmpDir, "asc")

	ascUrl := ascURLFromImgURL(aciUrl)

	res, err := f.FetchToPath(aciUrl, ascUrl, aciFilePath, ascFilePath)
	if err != nil {
		return "", err
	}

	if f.Rem != nil && (res.UseCached || useCached(f.Rem.DownloadTime, res.MaxAge)) {
		return f.Rem.BlobKey, nil
	}

	if !f.InsecureFlags.SkipImageCheck() {
		err := f.validate(aciFilePath, ascFilePath)
		if err != nil {
			return "", err
		}
	}

	return f.ImportFetchedImage(aciUrl, ascUrl, aciFilePath, res)
}

func (f *pluginFetcher) validate(aciFilePath, ascFilePath string) error {
	aciFile, err := os.Open(aciFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("plugin didn't fetch an image")
		}
		return err
	}
	defer aciFile.Close()
	ascFile, err := os.Open(ascFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("plugin didn't fetch a signature")
		}
		return err
	}
	defer ascFile.Close()

	v, err := newValidator(aciFile)
	if err != nil {
		return err
	}
	entity, err := v.ValidateWithSignature(f.Ks, ascFile)
	if err != nil {
		return err
	}

	printIdentities(entity)
	return nil
}

func (f *pluginFetcher) ImportFetchedImage(aciUrl, ascUrl *url.URL, aciFilePath string, res *fetchers.Result) (string, error) {
	aciFile, err := os.Open(aciFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("plugin didn't fetch an image")
		}
		return "", err
	}
	defer aciFile.Close()

	key, err := f.S.WriteACI(aciFile, imagestore.ACIFetchInfo{
		Latest:          res.Latest,
		InsecureOptions: int64(f.InsecureFlags.Value()),
	})
	if err != nil {
		return "", err
	}

	newRem := imagestore.NewRemote(aciUrl.String(), ascUrl.String())
	newRem.BlobKey = key
	newRem.DownloadTime = time.Now()
	if res.ETag != "" {
		newRem.ETag = res.ETag
	}
	if res.MaxAge != 0 {
		newRem.CacheMaxAge = res.MaxAge
	}
	err = f.S.WriteRemote(newRem)
	if err != nil {
		return "", err
	}

	return key, nil
}

func (f *pluginFetcher) GetHashedTmpDir(u *url.URL) (string, error) {
	h := sha512.New()
	h.Write([]byte(u.String()))
	pathHash := f.S.HashToKey(h)
	tmpDir, err := f.S.TmpNamedDir(pathHash)
	if err != nil {
		return "", err
	}
	return tmpDir, nil
}

func (f *pluginFetcher) FetchToPath(aciUrl, ascUrl *url.URL, aciPath, ascPath string) (*fetchers.Result, error) {
	ensureLogger(f.Debug)

	if f.Debug {
		log.Printf("fetching image from %s", aciUrl.String())
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

	auth := make(map[string]fetchers.Headers)
	for host, headerer := range f.Auth {
		headers := make(fetchers.Headers)
		for k, v := range headerer.GetHeader() {
			headers[k] = v
		}
		auth[host] = headers
	}

	conf := &fetchers.Config{
		Version: 1,
		Scheme:  aciUrl.Scheme,
		AciName: path.Join(aciUrl.Host, aciUrl.Path),
		AscName: path.Join(ascUrl.Host, ascUrl.Path),
		InsecureOpts: fetchers.InsecureOpts{
			AllowHTTP:      f.InsecureFlags.AllowHTTP(),
			SkipTLSCheck:   f.InsecureFlags.SkipTLSCheck(),
			SkipImageCheck: f.InsecureFlags.SkipImageCheck(),
		},
		Debug:         f.Debug,
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
	res := &fetchers.Result{}
	err = json.Unmarshal(resBlob, res)
	if err != nil {
		return nil, err
	}
	return res, nil
}
