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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/coreos/rkt/rkt/image/fetchers"
	"github.com/hashicorp/errwrap"
)

// httpOps is a kind of facade around a downloader and a
// resumableSession. It provides some higher-level functions for
// fetching images and signature keys. It also is a provider of a
// remote fetcher for asc.
type httpOps struct {
	Conf fetchers.Config
}

// DownloadSignature takes an asc instance and tries to get the
// signature. If the remote server asked to to defer the download,
// this function will return true and no error and no file.
func (o *httpOps) DownloadSignature() (bool, error) {
	ascUrl := o.Conf.Scheme + "://" + o.Conf.AscName
	u, err := url.Parse(ascUrl)
	if err != nil {
		return false, err
	}
	ascFile, err := os.OpenFile(o.Conf.OutputASCPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return false, err
	}
	defer ascFile.Close()

	session := o.getSession(u, ascFile, "ASC", "")
	dl := o.getDownloader(session)
	err = dl.Download(u, ascFile)
	if err == nil {
		return false, nil
	}
	if _, ok := err.(*statusAcceptedError); ok {
		stderr("server requested deferring the signature download")
		return true, nil
	}
	return false, errwrap.Wrap(errors.New("error downloading the signature file"), err)
}

// DownloadSignatureAgain does a similar thing to DownloadSignature,
// but it expects the signature to be actually provided, that is - no
// deferring this time.
func (o *httpOps) DownloadSignatureAgain() error {
	retry, err := o.DownloadSignature()
	if err != nil {
		return err
	}
	if retry {
		return fmt.Errorf("error downloading the signature file: server asked to defer the download again")
	}
	return nil
}

// DownloadImage download the image, duh. It expects to actually
// receive the file, instead of being asked to use the cached version.
func (o *httpOps) DownloadImage() (*cacheData, error) {
	cd, err := o.DownloadImageWithETag()
	if err != nil {
		return nil, err
	}
	if cd.UseCached {
		return nil, fmt.Errorf("asked to use cached image even if not asked for that")
	}
	return cd, nil
}

// DownloadImageWithETag might download an image or tell you to use
// the cached image. In the latter case the returned file will be nil.
func (o *httpOps) DownloadImageWithETag() (*cacheData, error) {
	aciUrl := o.Conf.Scheme + "://" + o.Conf.AciName
	u, err := url.Parse(aciUrl)
	if err != nil {
		return nil, err
	}
	aciFile, err := os.OpenFile(o.Conf.OutputACIPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	defer aciFile.Close()

	session := o.getSession(u, aciFile, "ACI", "") // TODO: ETag
	dl := o.getDownloader(session)
	if err := dl.Download(u, aciFile); err != nil {
		return nil, errwrap.Wrap(errors.New("error downloading ACI"), err)
	}
	return session.Cd, nil
}

//// AscRemoteFetcher provides a remoteAscFetcher for asc.
//func (o *httpOps) AscRemoteFetcher() *remoteAscFetcher {
//	ensureLogger(o.Debug)
//	f := func(u *url.URL, file *os.File) error {
//		switch u.Scheme {
//		case "http", "https":
//		default:
//			return fmt.Errorf("invalid signature location: expected %q scheme, got %q", "http(s)", u.Scheme)
//		}
//		session := o.getSession(u, file, "signature", "")
//		dl := o.getDownloader(session)
//		err := dl.Download(u, file)
//		if err != nil {
//			return err
//		}
//		if session.Cd.UseCached {
//			return fmt.Errorf("unexpected cache reuse request for signature %q", u.String())
//		}
//		return nil
//	}
//	return &remoteAscFetcher{
//		F: f,
//		S: o.S,
//	}
//}

func (o *httpOps) getSession(u *url.URL, file *os.File, label, etag string) *resumableSession {
	eTagFilePath := fmt.Sprintf("%s.etag", file.Name())
	return &resumableSession{
		InsecureSkipTLSVerify: o.Conf.InsecureOpts.SkipTLSCheck,
		Headers:               o.Conf.Headers[u.Host],
		File:                  file,
		ETagFilePath:          eTagFilePath,
		Label:                 label,
	}
}

func (o *httpOps) getDownloader(session downloadSession) *downloader {
	return &downloader{
		Session: session,
	}
}

func (o *httpOps) getHeaders(u *url.URL, etag string) http.Header {
	options := o.getHeadersForURL(u, etag)
	if etag != "" {
		options.Add("If-None-Match", etag)
	}
	return options
}

func (o *httpOps) getHeadersForURL(u *url.URL, etag string) http.Header {
	return make(http.Header)
}
