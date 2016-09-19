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

package distribution

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	docker2aci "github.com/appc/docker2aci/lib"
	d2acommon "github.com/appc/docker2aci/lib/common"
	"github.com/coreos/rkt/store/imagestore"
	"github.com/hashicorp/errwrap"
)

const (
	DistDockerVersion = 0

	DistTypeDocker DistType = "docker"

	defaultIndexURL   = "registry-1.docker.io"
	defaultTag        = "latest"
	defaultRepoPrefix = "library/"
)

func init() {
	Register(DistTypeDocker, NewDocker)
}

// Docker defines a distribution using a docker registry
// The format is the same as the docker image string format (man docker-pull)
// with the "docker" distribution type:
// cimd:docker:v=0:[REGISTRY_HOST[:REGISTRY_PORT]/]NAME[:TAG|@DIGEST]
// Examples:
// cimd:docker:v=0:busybox
// cimd:docker:v=0:busybox:latest
// cimd:docker:v=0:registry-1.docker.io/library/busybox@sha256:a59906e33509d14c036c8678d687bd4eec81ed7c4b8ce907b888c607f6a1e0e6
type Docker struct {
	ds string
}

// NewDocker creates a new docker distribution from the provided distribution uri string
func NewDocker(u *url.URL) (Distribution, error) {
	dp, err := parseDist(u)
	if err != nil {
		return nil, fmt.Errorf("cannot parse URI: %q: %v", u.String(), err)
	}
	if dp.DistType != DistTypeDocker {
		return nil, fmt.Errorf("wrong distribution type: %q", dp.DistType)
	}

	if _, err = d2acommon.ParseDockerURL(dp.DistString); err != nil {
		return nil, fmt.Errorf("bad docker string %q: %v", dp.DistString, err)
	}
	return &Docker{ds: dp.DistString}, nil
}

// NewDocker creates a new docker distribution from the provided docker string
// (like "busybox", "busybox:1.0", "myregistry.example.com:4000/busybox"
// etc...)
func NewDockerFromDockerString(ds string) (Distribution, error) {
	urlStr := DistBase(DistTypeDocker, DistDockerVersion) + ds
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	return NewDocker(u)
}

// URI returns a copy of the Distribution URI
func (d *Docker) URI() *url.URL {
	uriStr := DistBase(DistTypeDocker, DistDockerVersion) + d.ds
	// Create a copy of the URL
	u, err := url.Parse(uriStr)
	if err != nil {
		panic(err)
	}
	return u
}

// Compare compares with another Distribution
func (d *Docker) Compare(dist Distribution) bool {
	d2, ok := dist.(*Docker)
	if !ok {
		return false
	}
	fds1, err := FullDockerString(d.ds)
	if err != nil {
		panic(err)
	}
	fds2, err := FullDockerString(d2.ds)
	if err != nil {
		panic(err)
	}
	return fds1 == fds2
}

func (d *Docker) dockerString() string {
	return d.ds
}

func (d *Docker) Fetch(ft FetchTask) (string, error) {
	u := d.URI()

	dockerURL, err := d2acommon.ParseDockerURL(path.Join(u.Host, u.Path))
	if err != nil {
		return "", fmt.Errorf(`invalid docker URL %q; expected syntax is "docker://[REGISTRY_HOST[:REGISTRY_PORT]/]IMAGE_NAME[:TAG]"`, u)
	}
	latest := dockerURL.Tag == "latest"

	if !ft.InsecureFlags.SkipImageCheck() {
		return "", fmt.Errorf("signature verification for docker images is not supported (try --insecure-options=image)")
	}

	if ft.Debug {
		fmt.Printf("fetching image from %s", u.String())
	}

	aciFile, err := d.fetch(ft, u)
	if err != nil {
		return "", err
	}
	// At this point, the ACI file is removed, but it is kept
	// alive, because we have an fd to it opened.
	defer aciFile.Close()

	key, err := ft.Store.WriteACI(aciFile, imagestore.ACIFetchInfo{
		Latest: latest,
	})
	if err != nil {
		return "", err
	}

	// docker images don't have signature URL
	newRem := imagestore.NewRemote(u.String(), "")
	newRem.BlobKey = key
	newRem.DownloadTime = time.Now()
	err = ft.Store.WriteRemote(newRem)
	if err != nil {
		return "", err
	}

	return key, nil
}

func (d *Docker) fetch(ft FetchTask, u *url.URL) (*os.File, error) {
	tmpDir, err := d.getTmpDir(ft)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	registryURL := strings.TrimPrefix(u.String(), "docker://")
	user, password := d.getCreds(ft, registryURL)
	config := docker2aci.RemoteConfig{
		Username: user,
		Password: password,
		Insecure: d2acommon.InsecureConfig{
			SkipVerify: ft.InsecureFlags.SkipTLSCheck(),
			AllowHTTP:  ft.InsecureFlags.AllowHTTP(),
		},
		CommonConfig: docker2aci.CommonConfig{
			Squash:      true,
			OutputDir:   tmpDir,
			TmpDir:      tmpDir,
			Compression: d2acommon.NoCompression,
		},
	}
	acis, err := docker2aci.ConvertRemoteRepo(registryURL, config)
	if err != nil {
		return nil, errwrap.Wrap(errors.New("error converting docker image to ACI"), err)
	}

	aciFile, err := os.Open(acis[0])
	if err != nil {
		return nil, errwrap.Wrap(errors.New("error opening squashed ACI file"), err)
	}

	return aciFile, nil
}

func (d *Docker) getTmpDir(ft FetchTask) (string, error) {
	storeTmpDir, err := ft.Store.TmpDir()
	if err != nil {
		return "", errwrap.Wrap(errors.New("error creating temporary dir for docker to ACI conversion"), err)
	}
	return ioutil.TempDir(storeTmpDir, "docker2aci-")
}

func (d *Docker) getCreds(ft FetchTask, registryURL string) (string, string) {
	indexName := docker2aci.GetIndexName(registryURL)
	if creds, ok := ft.DockerAuth[indexName]; ok {
		return creds.User, creds.Password
	}
	return "", ""
}
