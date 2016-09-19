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
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/appc/spec/aci"
	"github.com/appc/spec/schema"
	"github.com/appc/spec/schema/types"
	"github.com/coreos/rkt/common/transport"
	"github.com/coreos/rkt/common/transport/plugins"
	"github.com/coreos/rkt/pkg/keystore"
	"github.com/coreos/rkt/store/imagestore"
	"github.com/hashicorp/errwrap"
	"golang.org/x/crypto/openpgp"
	pgperrors "golang.org/x/crypto/openpgp/errors"
)

const (
	DistACIArchiveVersion = 0

	DistTypeACIArchive DistType = "aci-archive"
)

func init() {
	Register(DistTypeACIArchive, NewACIArchive)
}

// ACIArchive defines a distribution using an ACI file
// The format is:
// cmd:aci-archive:v=0:ArchiveURL?query...
// The distribution type is "archive"
// ArchiveURL must be query escaped
// Examples:
// cimd:aci-archive:v=0:file%3A%2F%2Fabsolute%2Fpath%2Fto%2Ffile
// cimd:aci-archive:v=0:https%3A%2F%2Fexample.com%2Fapp.aci
type ACIArchive struct {
	u *url.URL
	// The transport url
	tu *url.URL
	// The transport url for the ASC
	atu *url.URL
}

// NewACIArchive creates a new aci-archive distribution from the provided distribution uri
// string
func NewACIArchive(u *url.URL) (Distribution, error) {
	dp, err := parseDist(u)
	if err != nil {
		return nil, fmt.Errorf("cannot parse URI: %q: %v", u.String(), err)
	}
	if dp.DistType != DistTypeACIArchive {
		return nil, fmt.Errorf("wrong distribution type: %q", dp.DistType)
	}
	// This should be a valid URL
	tus, err := url.QueryUnescape(dp.DistString)
	if err != nil {
		return nil, fmt.Errorf("wrong archive transport url %q: %v", dp.DistString, err)
	}
	tu, err := url.Parse(tus)
	if err != nil {
		return nil, fmt.Errorf("wrong archive transport url %q: %v", dp.DistString, err)
	}
	atu, err := url.Parse(tus + ".asc")
	if err != nil {
		return nil, fmt.Errorf("wrong archive transport url %q: %v", dp.DistString, err)
	}

	// save the URI as sorted to make it ready for comparison
	sortQuery(u)

	return &ACIArchive{u: u, tu: tu, atu: atu}, nil
}

// NewACIArchiveFromTransportURL creates a new aci-archive distribution from the provided transport URL
// Example: file:///full/path/to/aci/file.aci -> archive:aci:file%3A%2F%2F%2Ffull%2Fpath%2Fto%2Faci%2Ffile.aci
func NewACIArchiveFromTransportURL(u *url.URL) (Distribution, error) {
	urlStr := DistBase(DistTypeACIArchive, DistACIArchiveVersion) + url.QueryEscape(u.String())
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	return NewACIArchive(u)
}

// URI returns a copy of the Distribution URI
func (a *ACIArchive) URI() *url.URL {
	// Create a copy of the URL
	u, err := url.Parse(a.u.String())
	if err != nil {
		panic(err)
	}
	return u
}

// Compare compares with another Distribution
func (a *ACIArchive) Compare(d Distribution) bool {
	a2, ok := d.(*ACIArchive)
	if !ok {
		return false
	}
	return a.URI().String() == a2.URI().String()
}

// Performs the distribution, resulting in the image being imported into rkt's
// store
func (a *ACIArchive) Fetch(ft FetchTask) (string, error) {
	rem, err := remoteForURL(ft.Store, a.tu)
	if err != nil {
		return "", err
	}

	if !ft.NoCache && rem != nil {
		if useCached(rem.DownloadTime, rem.CacheMaxAge) {
			if ft.Debug {
				fmt.Printf("image for %s isn't expired, not fetching.", a.tu.String())
			}
			return rem.BlobKey, nil
		}
	}

	dest, err := ioutil.TempDir("", "rkt-distribution")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dest)

	aciDest := path.Join(dest, "aci")
	ascDest := path.Join(dest, "asc")

	var res *plugins.Result
	if a.tu.Scheme == "file" {
		aciDest = path.Join(a.tu.Host, a.tu.Path)
		ascDest = path.Join(a.atu.Host, a.atu.Path)
	} else {
		t := &transport.Transport{
			InsecureFlags: ft.InsecureFlags,
			Auth:          ft.Headers,
			Debug:         ft.Debug,
			Rem:           rem,
		}
		res, err = t.Fetch(a.tu, a.atu, aciDest, ascDest)
		if err != nil {
			return "", err
		}
	}

	if res != nil && res.UseCached {
		return rem.BlobKey, nil
	}

	aciFile, err := os.Open(aciDest)
	if err != nil {
		return "", err
	}
	defer aciFile.Close()

	if !ft.InsecureFlags.SkipImageCheck() {
		ascFile, err := os.Open(ascDest)
		if err != nil {
			return "", err
		}
		defer ascFile.Close()

		err = a.validate(ft, aciFile, ascFile)
		if err != nil {
			return "", err
		}
	}

	latest := false
	if res != nil {
		latest = res.Latest
	}

	key, err := ft.Store.WriteACI(aciFile, imagestore.ACIFetchInfo{
		Latest: latest,
	})

	newRem := imagestore.NewRemote(a.tu.String(), "") // TODO: SIGNATURE URL!!!
	newRem.BlobKey = key
	newRem.DownloadTime = time.Now()
	if res != nil {
		newRem.ETag = res.ETag
		newRem.CacheMaxAge = res.MaxAge
	}
	err = ft.Store.WriteRemote(newRem)
	if err != nil {
		return "", err
	}

	return key, nil
}

func (a *ACIArchive) validate(ft FetchTask, aciFile, ascFile io.ReadSeeker) error {
	v, err := newValidator(aciFile)
	if err != nil {
		return err
	}
	entity, err := v.ValidateWithSignature(ft.KeyStore, ascFile)
	if err != nil {
		return err
	}
	if _, err := aciFile.Seek(0, 0); err != nil {
		return errwrap.Wrap(errors.New("error seeking ACI file"), err)
	}

	printIdentities(entity)
	return nil
}

// validator is a general image checker
type validator struct {
	image    io.ReadSeeker
	manifest *schema.ImageManifest
}

// newValidator returns a validator instance if passed image is indeed
// an ACI.
func newValidator(image io.ReadSeeker) (*validator, error) {
	manifest, err := aci.ManifestFromImage(image)
	if err != nil {
		return nil, err
	}
	v := &validator{
		image:    image,
		manifest: manifest,
	}
	return v, nil
}

// ImageName returns image name as it is in the image manifest.
func (v *validator) ImageName() string {
	return v.manifest.Name.String()
}

// ValidateName checks if desired image name is actually the same as
// the one in the image manifest.
func (v *validator) ValidateName(imageName string) error {
	name := v.ImageName()
	if name != imageName {
		return fmt.Errorf("error when reading the app name: %q expected but %q found",
			imageName, name)
	}
	return nil
}

// ValidateLabels checks if desired image labels are actually the same as
// the ones in the image manifest.
func (v *validator) ValidateLabels(labels map[types.ACIdentifier]string) error {
	for n, rv := range labels {
		if av, ok := v.manifest.GetLabel(n.String()); ok {
			if rv != av {
				return fmt.Errorf("requested value for label %q: %q differs from fetched aci label value: %q", n, rv, av)
			}
		} else {
			return fmt.Errorf("requested label %q not provided by the image manifest", n)
		}
	}
	return nil
}

// ValidateWithSignature verifies the image against a given signature
// file.
func (v *validator) ValidateWithSignature(ks *keystore.Keystore, sig io.ReadSeeker) (*openpgp.Entity, error) {
	if ks == nil {
		return nil, nil
	}
	if _, err := v.image.Seek(0, 0); err != nil {
		return nil, errwrap.Wrap(errors.New("error seeking ACI file"), err)
	}
	if _, err := sig.Seek(0, 0); err != nil {
		return nil, errwrap.Wrap(errors.New("error seeking signature file"), err)
	}
	entity, err := ks.CheckSignature(v.ImageName(), v.image, sig)
	if err == pgperrors.ErrUnknownIssuer {
		fmt.Println("If you expected the signing key to change, try running:")
		fmt.Println("    rkt trust --prefix <image>")
	}
	if err != nil {
		return nil, err
	}
	return entity, nil
}

// printIdentities prints a message that signature was verified.
func printIdentities(entity *openpgp.Entity) {
	lines := []string{"signature verified:"}
	for _, v := range entity.Identities {
		lines = append(lines, fmt.Sprintf("  %s", v.Name))
	}
	fmt.Print(strings.Join(lines, "\n"))
}
