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
	"fmt"
	"net/url"
	"os"
	"path"

	"github.com/coreos/rkt/pkg/keystore"
	"github.com/coreos/rkt/rkt/config"
	rktflag "github.com/coreos/rkt/rkt/flag"
	"github.com/coreos/rkt/rkt/pubkey"
	"github.com/coreos/rkt/store/imagestore"
	"github.com/hashicorp/errwrap"

	"github.com/appc/spec/discovery"
)

// nameFetcher is used to download images via discovery
type nameFetcher struct {
	InsecureFlags      *rktflag.SecFlags
	S                  *imagestore.Store
	Ks                 *keystore.Keystore
	Debug              bool
	Headers            map[string]config.Headerer
	TrustKeysFromHTTPS bool
	Ft                 *Fetcher
}

// Hash runs the discovery, fetches the image, optionally verifies
// it against passed asc, stores it in the store and returns the hash.
func (f *nameFetcher) Hash(app *discovery.App, a *asc) (string, error) {
	ensureLogger(f.Debug)
	name := app.Name.String()
	log.Printf("searching for app image %s", name)
	ep, err := f.discoverApp(app)
	if err != nil {
		return "", errwrap.Wrap(fmt.Errorf("discovery failed for %q", name), err)
	}
	if !f.InsecureFlags.SkipImageCheck() {
		f.maybeFetchPubKeys(app.Name.String())
	}

	aciUrl, err := url.Parse(ep[0].ACI)
	if err != nil {
		return "", errwrap.Wrap(fmt.Errorf("error parsing ACI URL"), err)
	}
	ascUrl, err := url.Parse(ep[0].ASC)
	if err != nil {
		return "", errwrap.Wrap(fmt.Errorf("error getting ASC URL"), err)
	}
	rem, err := f.Ft.getRemoteForURL(aciUrl)
	if err != nil {
		return "", err
	}

	log.Printf("remote fetching from URL %q", aciUrl.String())

	pf := &pluginFetcher{
		InsecureFlags: f.InsecureFlags,
		Auth:          f.Headers,
		S:             f.S,
		Ks:            f.Ks,
		Debug:         f.Debug,
		Rem:           rem,
	}
	tmpDir, err := pf.GetHashedTmpDir(aciUrl)
	if err != nil {
		return "", errwrap.Wrap(fmt.Errorf("error getting temp directory"), err)
	}
	defer os.RemoveAll(tmpDir)

	aciFilePath := path.Join(tmpDir, "aci")
	ascFilePath := path.Join(tmpDir, "asc")

	res, err := pf.FetchToPath(aciUrl, ascUrl, aciFilePath, ascFilePath)
	if err != nil {
		return "", err
	}

	if rem != nil && (res.UseCached || useCached(rem.DownloadTime, res.MaxAge)) {
		return rem.BlobKey, nil
	}

	if !f.InsecureFlags.SkipImageCheck() {
		err = f.validate(app, aciFilePath, ascFilePath)
		if err != nil {
			return "", err
		}
	}

	return pf.ImportFetchedImage(aciUrl, ascUrl, aciFilePath, res)
}

func (f *nameFetcher) discoverApp(app *discovery.App) (discovery.ACIEndpoints, error) {
	insecure := discovery.InsecureNone
	if f.InsecureFlags.SkipTLSCheck() {
		insecure = insecure | discovery.InsecureTLS
	}
	if f.InsecureFlags.AllowHTTP() {
		insecure = insecure | discovery.InsecureHTTP
	}
	hostHeaders := config.ResolveAuthPerHost(f.Headers)
	ep, attempts, err := discovery.DiscoverACIEndpoints(*app, hostHeaders, insecure, 0)
	if f.Debug {
		for _, a := range attempts {
			log.PrintE(fmt.Sprintf("meta tag 'ac-discovery' not found on %s", a.Prefix), a.Error)
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

//func (f *nameFetcher) fetchImageFromEndpoints(app *discovery.App, ep discovery.ACIEndpoints, a *asc, latest bool) (string, error) {
//	ensureLogger(f.Debug)
//	// TODO(krnowak): we should probably try all the endpoints,
//	// for this we need to clone "a" and call
//	// maybeOverrideAscFetcherWithRemote on the clone
//	aciURL := ep[0].ACI
//	ascURL := ep[0].ASC
//	log.Printf("remote fetching from URL %q", aciURL)
//	f.maybeOverrideAscFetcherWithRemote(ascURL, a)
//	return f.fetchImageFromSingleEndpoint(app, aciURL, a, latest)
//}
//
//func (f *nameFetcher) fetchImageFromSingleEndpoint(app *discovery.App, aciURL string, a *asc, latest bool) (string, error) {
//	if f.Debug {
//		log.Printf("fetching image from %s", aciURL)
//	}
//
//	aciFile, cd, err := f.fetch(app, aciURL, a)
//	if err != nil {
//		return "", err
//	}
//	defer aciFile.Close()
//
//	key, err := f.S.WriteACI(aciFile, latest)
//	if err != nil {
//		return "", err
//	}
//
//	rem := store.NewRemote(aciURL, a.Location)
//	rem.BlobKey = key
//	rem.DownloadTime = time.Now()
//	rem.ETag = cd.ETag
//	rem.CacheMaxAge = cd.MaxAge
//	err = f.S.WriteRemote(rem)
//	if err != nil {
//		return "", err
//	}
//
//	return key, nil
//}
//
//func (f *nameFetcher) fetch(app *discovery.App, aciURL string, a *asc) (readSeekCloser, *cacheData, error) {
//	if f.InsecureFlags.SkipTLSCheck() && f.Ks != nil {
//		log.Print("warning: TLS verification has been disabled")
//	}
//	if f.InsecureFlags.SkipImageCheck() && f.Ks != nil {
//		log.Print("warning: image signature verification has been disabled")
//	}
//
//	u, err := url.Parse(aciURL)
//	if err != nil {
//		return nil, nil, errwrap.Wrap(errors.New("error parsing ACI url"), err)
//	}
//
//	if f.InsecureFlags.SkipImageCheck() || f.Ks == nil {
//		o := f.httpOps()
//		aciFile, cd, err := o.DownloadImage(u)
//		if err != nil {
//			return nil, nil, err
//		}
//		return aciFile, cd, nil
//	}
//
//	return f.fetchVerifiedURL(app, u, a)
//}
//
//func (f *nameFetcher) fetchVerifiedURL(app *discovery.App, u *url.URL, a *asc) (readSeekCloser, *cacheData, error) {
//	appName := app.Name.String()
//	f.maybeFetchPubKeys(appName)
//
//	o := f.httpOps()
//	ascFile, retry, err := o.DownloadSignature(a)
//	if err != nil {
//		return nil, nil, err
//	}
//	defer func() { maybeClose(ascFile) }()
//
//	if !retry {
//		if err := f.checkIdentity(appName, ascFile); err != nil {
//			return nil, nil, err
//		}
//	}
//
//	aciFile, cd, err := o.DownloadImage(u)
//	if err != nil {
//		return nil, nil, err
//	}
//	defer func() { maybeClose(aciFile) }()
//
//	if retry {
//		ascFile, err = o.DownloadSignatureAgain(a)
//		if err != nil {
//			return nil, nil, err
//		}
//	}
//
//	if err := f.validate(app, aciFile, ascFile); err != nil {
//		return nil, nil, err
//	}
//	retAciFile := aciFile
//	aciFile = nil
//	return retAciFile, cd, nil
//}

func (f *nameFetcher) maybeFetchPubKeys(appName string) {
	exists, err := f.Ks.TrustedKeyPrefixExists(appName)
	if err != nil {
		log.Printf("error checking for existing keys: %v", err)
		return
	}
	if exists {
		log.Printf("keys already exist for prefix %q, not fetching again", appName)
		return
	}
	allowHTTP := false
	if f.InsecureFlags.ConsiderInsecurePubKeys() {
		log.Printf("signing keys may be downloaded from an insecure connection")
		allowHTTP = f.InsecureFlags.AllowHTTP()
	}
	if !f.InsecureFlags.SkipTLSCheck() || f.InsecureFlags.ConsiderInsecurePubKeys() {
		m := &pubkey.Manager{
			AuthPerHost:          f.Headers,
			InsecureAllowHTTP:    allowHTTP,
			InsecureSkipTLSCheck: f.InsecureFlags.SkipTLSCheck(),
			TrustKeysFromHTTPS:   f.TrustKeysFromHTTPS,
			Ks:                   f.Ks,
			Debug:                f.Debug,
		}
		pkls, err := m.GetPubKeyLocations(appName)
		// We do not bail out here, because if fetching the
		// public keys fails but we already trust the key, we
		// should be able to run the image anyway.
		if err != nil {
			log.PrintE("error determining key location", err)
		} else {
			accept := pubkey.AcceptAsk
			if f.TrustKeysFromHTTPS {
				accept = pubkey.AcceptForce
			}
			err := m.AddKeys(pkls, appName, accept)
			if err != nil {
				log.PrintE("error adding keys", err)
			}
		}
	}
}

//func (f *nameFetcher) checkIdentity(appName string, ascFile io.ReadSeeker) error {
//	if _, err := ascFile.Seek(0, 0); err != nil {
//		return errwrap.Wrap(errors.New("error seeking signature file"), err)
//	}
//	empty := bytes.NewReader([]byte{})
//	if _, err := f.Ks.CheckSignature(appName, empty, ascFile); err != nil {
//		if err == pgperrors.ErrUnknownIssuer {
//			log.Printf("if you expected the signing key to change, try running:")
//			log.Printf("    rkt trust --prefix %q", appName)
//		}
//		if _, ok := err.(pgperrors.SignatureError); !ok {
//			return err
//		}
//	}
//	return nil
//}
//
func (f *nameFetcher) validate(app *discovery.App, aciFilePath, ascFilePath string) error {
	aciFile, err := os.Open(aciFilePath)
	if err != nil {
		return err
	}
	defer aciFile.Close()
	ascFile, err := os.Open(ascFilePath)
	if err != nil {
		return err
	}
	defer ascFile.Close()

	v, err := newValidator(aciFile)
	if err != nil {
		return err
	}

	if err := v.ValidateName(app.Name.String()); err != nil {
		return err
	}

	if err := v.ValidateLabels(app.Labels); err != nil {
		return err
	}

	entity, err := v.ValidateWithSignature(f.Ks, ascFile)
	if err != nil {
		return err
	}

	printIdentities(entity)
	return nil
}

//
//func (f *nameFetcher) maybeOverrideAscFetcherWithRemote(ascURL string, a *asc) {
//	if a.Fetcher != nil {
//		return
//	}
//	a.Location = ascURL
//	a.Fetcher = f.httpOps().AscRemoteFetcher()
//}
//
//func (f *nameFetcher) httpOps() *httpOps {
//	return &httpOps{
//		InsecureSkipTLSVerify: f.InsecureFlags.SkipTLSCheck(),
//		S:       f.S,
//		Headers: f.Headers,
//		Debug:   f.Debug,
//	}
//}
