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
	"net/url"
	"reflect"
	"testing"

	"github.com/appc/spec/discovery"
)

func TestAppDiscovery(t *testing.T) {
	tests := []struct {
		uriStr string
		out    string
	}{
		{
			"cimd:appc:v=0:example.com/app01",
			"example.com/app01",
		},
		{
			"cimd:appc:v=0:example.com/app01?version=v1.0.0",
			"example.com/app01:v1.0.0",
		},
		{
			"cimd:appc:v=0:example.com/app01?version=v1.0.0",
			"example.com/app01,version=v1.0.0",
		},
		{
			"cimd:appc:v=0:example.com/app01?label01=%3F%26%2A%2F&version=v1.0.0",
			"example.com/app01,version=v1.0.0,label01=?&*/",
		},
	}

	for _, tt := range tests {
		u, err := url.Parse(tt.uriStr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		appc, err := NewAppc(u)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		app, err := AppDiscovery(appc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expectedApp, err := discovery.NewAppFromString(tt.out)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(app, expectedApp) {
			t.Fatalf("expected app %s, but got %q", expectedApp.String(), app.String())
		}
	}
}

func TestTransportURL(t *testing.T) {
	tests := []struct {
		transportURL string
		uriString    string
		err          error
	}{
		{
			"file:///full/path/to/aci/file.aci",
			"cimd:aci-archive:v=0:file%3A%2F%2F%2Ffull%2Fpath%2Fto%2Faci%2Ffile.aci",
			nil,
		},
	}

	for _, tt := range tests {
		u, err := url.Parse(tt.transportURL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		d, err := NewACIArchiveFromTransportURL(u)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		transportURL, err := TransportURL(d)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tt.transportURL != transportURL.String() {
			t.Fatalf("expected transport url %q, but got %q", tt.transportURL, transportURL.String())
		}
	}
}

func TestSimpleDockerString(t *testing.T) {
	tests := []struct {
		inDs     string
		simpleDs string
		err      error
	}{
		{
			"busybox",
			"busybox",
			nil,
		},
		{
			"busybox:latest",
			"busybox",
			nil,
		},
		{
			"registry-1.docker.io/library/busybox:latest",
			"busybox",
			nil,
		},
		{
			"busybox:1.0",
			"busybox:1.0",
			nil,
		},
		{
			"repo/image",
			"repo/image",
			nil,
		},
		{
			"repo/image:latest",
			"repo/image",
			nil,
		},
		{
			"repo/image:1.0",
			"repo/image:1.0",
			nil,
		},
		{
			"busybox@sha256:a59906e33509d14c036c8678d687bd4eec81ed7c4b8ce907b888c607f6a1e0e6",
			"busybox@sha256:a59906e33509d14c036c8678d687bd4eec81ed7c4b8ce907b888c607f6a1e0e6",
			nil,
		},
		{
			"myregistry.example.com:4000/busybox",
			"myregistry.example.com:4000/busybox",
			nil,
		},
		{
			"myregistry.example.com:4000/busybox:latest",
			"myregistry.example.com:4000/busybox",
			nil,
		},
		{
			"myregistry.example.com:4000/busybox:1.0",
			"myregistry.example.com:4000/busybox:1.0",
			nil,
		},
	}

	for _, tt := range tests {
		// Test NewDockerFromDockerString
		d, err := NewDockerFromDockerString(tt.inDs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		ds, err := DockerString(d)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		simpleDs, err := SimpleDockerString(ds)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tt.simpleDs != simpleDs {
			t.Fatalf("expected simple string %q, but got %q", tt.simpleDs, simpleDs)
		}
	}

}
