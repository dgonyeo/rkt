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
	"fmt"
	"net/url"
	"path"
	"strings"

	d2acommon "github.com/appc/docker2aci/lib/common"
	"github.com/appc/spec/discovery"
	"github.com/appc/spec/schema/types"
)

// AppDiscovery returns the discovery.App for an Appc distribution. It'll fail
// if the distribution is not of type Appc.
func AppDiscovery(d Distribution) (*discovery.App, error) {
	if _, ok := d.(*Appc); !ok {
		return nil, fmt.Errorf("distribution not of Appc type")
	}
	u := d.URI()
	dp, err := parseDist(u)
	if err != nil {
		return nil, fmt.Errorf("cannot parse URI: %q: %v", u, err)
	}
	labels := map[types.ACIdentifier]string{}
	for n, v := range u.Query() {
		name, err := types.NewACIdentifier(n)
		if err != nil {
			return nil, fmt.Errorf("cannot parse label name %s: %v", n, err)
		}
		labels[*name] = v[0]
	}
	name := dp.DistString
	app, err := discovery.NewApp(name, labels)
	if err != nil {
		return nil, fmt.Errorf("failed to convert Appc distribution %q to a discovery.App: %v", u.String(), err)
	}
	return app, nil
}

// TransportURL returns a copy of the transport URL for an ACIArchive
// distribution. It'll fail if the distribution is not of type ACIArchive.
func TransportURL(d Distribution) (*url.URL, error) {
	a, ok := d.(*ACIArchive)
	if !ok {
		return nil, fmt.Errorf("distribution not of ACIArchive type")
	}
	// Create a copy of the transport URL
	tu, err := url.Parse(a.tu.String())
	if err != nil {
		return nil, fmt.Errorf("invalid transport URL: %v", err)
	}
	return tu, nil
}

// DockerString returns the docker string for a Docker distribution. It'll fail
// if the distribution is not of type Docker.
func DockerString(dist Distribution) (string, error) {
	d, ok := dist.(*Docker)
	if !ok {
		return "", fmt.Errorf("distribution not of Docker type")
	}
	return d.dockerString(), nil
}

// SimpleDockerString returns a simplyfied docker string. This means removing
// the index url if it's the default docker registry (registry-1.docker.io),
// removing the default repo (library) when using the default docker registry
// and removing the tag if it's "latest"
func SimpleDockerString(ds string) (string, error) {
	p, err := d2acommon.ParseDockerURL(ds)
	if err != nil {
		return "", fmt.Errorf("bad docker string %q: %v", ds, err)
	}

	var sds string
	if p.IndexURL != defaultIndexURL {
		sds += p.IndexURL
	}

	imageName := p.ImageName
	if p.IndexURL == defaultIndexURL && strings.HasPrefix(p.ImageName, defaultRepoPrefix) {
		imageName = strings.TrimPrefix(p.ImageName, defaultRepoPrefix)
	}

	if sds == "" {
		sds = imageName
	} else {
		sds = path.Join(sds, imageName)
	}

	digest := p.Digest
	tag := p.Tag
	if digest != "" {
		sds += "@" + digest
	} else {
		if tag != defaultTag {
			sds += ":" + tag
		}
	}
	return sds, nil
}

// FullDockerString return the docker uri populated with all the default values
// docker strings like "busybox" or
// "registry-1.docker.io/library/busybox:latest" will become the same docker
// string "registry-1.docker.io/library/busybox:latest"
func FullDockerString(ds string) (string, error) {
	p, err := d2acommon.ParseDockerURL(ds)
	if err != nil {
		return "", fmt.Errorf("bad docker string %q: %v", ds, err)
	}
	fds := path.Join(p.IndexURL, p.ImageName)
	digest := p.Digest
	tag := p.Tag
	if digest != "" {
		fds += "@" + digest
	} else {
		fds += ":" + tag
	}
	return fds, nil
}
