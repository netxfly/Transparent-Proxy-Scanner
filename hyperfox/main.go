// Copyright (c) 2012-2014 José Carlos Nieto, https://menteslibres.net/xiam
// Copyright (c) 2015 netxfly x@xsec.io, http://www.xsec.io
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package main

import (
	"flag"
	"fmt"
	"github.com/netxfly/hyperfox/proxy"
	"github.com/netxfly/hyperfox/tools/capture"
	"strings"
	// "github.com/netxfly/hyperfox/tools/logger"
	"github.com/toolkits/slice"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
	"upper.io/db"
	"upper.io/db/mongo"
)

const version = "0.9"

const (
	defaultAddress = `0.0.0.0`
	defaultPort    = uint(3129)
	defaultSSLPort = uint(3128)
)

const (
	Host     = "127.0.0.1"
	Port     = "27017"
	User     = "xsec"
	Password = "x@xsec.io"
	Database = "passive_scan"
)

type Header struct {
	http.Header
}

type HttpInfo struct {
	//	ID            uint      `json:"id" db:",omitempty,json"`
	Origin        string    `json:"origin" db:",json"`
	Method        string    `json:"method" db:",json"`
	Status        int       `json:"status" db:",json"`
	ContentType   string    `json:"content_type" db:",json"`
	ContentLength uint      `json:"content_length" db:",json"`
	Host          string    `json:"host" db:",json"`
	URL           string    `json:"url" db:",json"`
	Scheme        string    `json:"scheme" db:",json"`
	Path          string    `json:"path" db:",path"`
	Header        Header    `json:"header,omitempty" db:",json"`
	Body          []byte    `json:"body,omitempty" db:",json"`
	RequestHeader Header    `json:"request_header,omitempty" db:",json"`
	RequestBody   []byte    `json:"request_body,omitempty" db:",json"`
	DateStart     time.Time `json:"date_start" db:",json"`
	DateEnd       time.Time `json:"date_end" db:",json"`
	TimeTaken     int64     `json:"time_taken" db:",json"`
}

var settings = mongo.ConnectionURL{
	Address:  db.Host(Host), // MongoDB hostname.
	Database: Database,      // Database name.
	User:     User,          // Optional user name.
	Password: Password,      // Optional user password.
}

var (
	flagAddress     = flag.String("l", defaultAddress, "Bind address.")
	flagPort        = flag.Uint("p", defaultPort, "Port to bind to, default is 3129")
	flagSSLPort     = flag.Uint("s", defaultSSLPort, "Port to bind to (SSL mode), default is 3128.")
	flagSSLCertFile = flag.String("c", "", "Path to root CA certificate.")
	flagSSLKeyFile  = flag.String("k", "", "Path to root CA key.")
)

var (
	sess db.Database
	col  db.Collection
)

var (
	static_resource []string = []string{"js", "css", "jpg", "gif", "png", "exe", "zip", "rar", "ico",
		"gz", "7z", "tgz", "bmp", "pdf", "avi", "mp3", "mp4", "htm", "html", "shtml"}
)

// dbsetup sets up the database.
func dbsetup() error {
	var err error
	// Attemping to establish a connection to the database.
	sess, err = db.Open(mongo.Adapter, settings)
	fmt.Println(sess)

	if err != nil {
		log.Fatalf("db.Open(): %q\n", err)
	}

	// Pointing to the "http_info" table.
	col, err = sess.Collection("http_info")

	return nil
}

// filter function
func filter(content_type string, raw_url string) bool {
	ret := false
	if strings.Contains(content_type, "text/plain") || strings.Contains(content_type, "application/x-gzip") {
		url_parsed, _ := url.Parse(raw_url)
		path := url_parsed.Path
		t := strings.Split(path[1:], ".")
		suffix := t[len(t)-1]
		if !slice.ContainsString(static_resource, suffix) {
			ret = true
		}

	}
	return ret
}

// Parses flags and initializes Hyperfox tool.
func main() {
	var err error
	var sslEnabled bool

	// Parsing command line flags.
	flag.Parse()

	// Opening database.
	if err = dbsetup(); err != nil {
		log.Fatalf("db: %q", err)
	}

	// Remember to close the database session.
	defer sess.Close()

	// Is SSL enabled?
	if *flagSSLPort > 0 && *flagSSLCertFile != "" {
		sslEnabled = true
	}

	// User requested SSL mode.
	if sslEnabled {
		if *flagSSLCertFile == "" {
			flag.Usage()
			log.Fatal(ErrMissingSSLCert)
		}

		if *flagSSLKeyFile == "" {
			flag.Usage()
			log.Fatal(ErrMissingSSLKey)
		}

		os.Setenv(proxy.EnvSSLCert, *flagSSLCertFile)
		os.Setenv(proxy.EnvSSLKey, *flagSSLKeyFile)
	}

	// Creatig proxy.
	p := proxy.NewProxy()

	// Attaching logger.
	// p.AddLogger(logger.Stdout{})

	// Attaching capture tool.
	res := make(chan capture.Response, 256)

	p.AddBodyWriteCloser(capture.New(res))

	// Saving captured data with a goroutine.
	go func() {
		for {
			select {
			case r := <-res:
				if filter(r.ContentType, r.URL) {
					fmt.Println(r.Method, r.URL, r.ContentType)
				}
				//				if _, err := col.Append(r); err != nil {
				//					log.Printf(ErrDatabaseError.Error(), err)
				//				}
			}
		}
	}()

	cerr := make(chan error)

	// Starting proxy servers.

	go func() {
		if err := p.Start(fmt.Sprintf("%s:%d", *flagAddress, *flagPort)); err != nil {
			cerr <- err
		}
	}()

	if sslEnabled {
		go func() {
			if err := p.StartTLS(fmt.Sprintf("%s:%d", *flagAddress, *flagSSLPort)); err != nil {
				cerr <- err
			}
		}()
	}

	err = <-cerr

	log.Fatalf(ErrBindFailed.Error(), err)
}
