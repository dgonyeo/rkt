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
	"strings"

	"github.com/appc/spec/discovery"
	"github.com/appc/spec/schema/types"
	"github.com/coreos/rkt/rkt/config"
	"github.com/hashicorp/errwrap"
)

const (
	DistAppcVersion = 0

	DistTypeAppc DistType = "appc"
)

func init() {
	Register(DistTypeAppc, NewAppc)
}

// Appc defines a distribution using appc image discovery
// Its format is cimd:appc:v=0:name?label01=....&label02=....
// The distribution type is "appc"
// The labels values must be Query escaped
// Example appc:coreos.com/etcd?version=v3.0.3&os=linux&arch=amd64
type Appc struct {
	u *url.URL
}

func NewAppc(u *url.URL) (Distribution, error) {
	dp, err := parseDist(u)
	if err != nil {
		return nil, fmt.Errorf("cannot parse URI: %q: %v", u.String(), err)
	}
	if dp.DistType != DistTypeAppc {
		return nil, fmt.Errorf("wrong distribution type: %q", dp.DistType)
	}

	appcStr := dp.DistString
	for n, v := range u.Query() {
		appcStr += fmt.Sprintf(",%s=%s", n, v[0])
	}
	app, err := discovery.NewAppFromString(appcStr)
	if err != nil {
		return nil, fmt.Errorf("wrong appc image string %q: %v", u.String(), err)
	}

	return NewAppcFromApp(app), nil
}

func NewAppcFromApp(app *discovery.App) *Appc {
	rawuri := DistBase(DistTypeAppc, DistAppcVersion) + app.Name.String()

	labels := types.Labels{}
	for n, v := range app.Labels {
		labels = append(labels, types.Label{Name: n, Value: v})
	}

	if len(labels) > 0 {
		queries := make([]string, len(labels))
		rawuri += "?"
		for i, l := range labels {
			queries[i] = fmt.Sprintf("%s=%s", l.Name, url.QueryEscape(l.Value))
		}
		rawuri += strings.Join(queries, "&")
	}

	u, err := url.Parse(rawuri)
	if err != nil {
		panic(fmt.Errorf("cannot parse URI %q: %v", rawuri, err))
	}

	// save the URI as sorted to make it ready for comparison
	sortQuery(u)
	return &Appc{u: u}
}

// URI returns a copy of the Distribution URI
func (a *Appc) URI() *url.URL {
	// Create a copy of the URL
	u, err := url.Parse(a.u.String())
	if err != nil {
		panic(err)
	}
	return u
}

// Compare compares with another Distribution
func (a *Appc) Compare(d Distribution) bool {
	a2, ok := d.(*Appc)
	if !ok {
		return false
	}
	return a.u.String() == a2.u.String()
}

func (a *Appc) Fetch(ft FetchTask) (string, error) {
	app, err := AppDiscovery(a)
	if err != nil {
		return "", errwrap.Wrap(fmt.Errorf("invalid Appc distribution"), err)
	}
	name := app.Name.String()
	fmt.Printf("searching for app image %s", name)
	ep, err := a.discoverApp(ft, app)
	if err != nil {
		return "", errwrap.Wrap(fmt.Errorf("discovery failed for %q", name), err)
	}
	//latest := false
	//// No specified version label, mark it as latest
	//if _, ok := app.Labels["version"]; !ok {
	//	latest = true
	//}

	aciUrlStr := ep[0].ACI
	//ascUrlStr := ep[0].ASC

	fmt.Printf("remote fetching from URL %q", aciUrlStr)

	aciUrl, err := url.Parse(aciUrlStr)
	if err != nil {
		return "", err
	}

	archiveDist, err := NewACIArchiveFromTransportURL(aciUrl)
	if err != nil {
		return "", err
	}
	return archiveDist.Fetch(ft)
}

func (a *Appc) discoverApp(ft FetchTask, app *discovery.App) (discovery.ACIEndpoints, error) {
	insecure := discovery.InsecureNone
	if ft.InsecureFlags.SkipTLSCheck() {
		insecure = insecure | discovery.InsecureTLS
	}
	if ft.InsecureFlags.AllowHTTP() {
		insecure = insecure | discovery.InsecureHTTP
	}
	hostHeaders := config.ResolveAuthPerHost(ft.Headers)
	ep, attempts, err := discovery.DiscoverACIEndpoints(*app, hostHeaders, insecure, 0)
	if ft.Debug {
		for _, a := range attempts {
			fmt.Println(fmt.Sprintf("meta tag 'ac-discovery' not found on %s", a.Prefix), a.Error)
		}
	}
	if err != nil {
		return nil, err
	}
	if len(ep) == 0 {
		return nil, fmt.Errorf("no endpoints discovered")
	}
	return ep, nil
}
