// Package shade provides an interface to the Shade storage system.
package shade

import (
	"context"
	"fmt"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/pacer"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/rest"
)

const (
	defaultEndpoint = "http://localhost:8001"
	minSleep        = 10 * time.Millisecond
	maxSleep        = 5 * time.Minute
	decayConstant   = 1 // bigger for slower decay, exponential
)

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "shade",
		Description: "Shade FS",
		NewFs:       NewFS,
		CommandHelp: []fs.CommandHelp{{
			// TODO
		}},
		Options: []fs.Option{{
			Name:      "drive_id",
			Help:      "The ID of your drive, see this in the drive settings. Individual rclone configs must be made per drive.",
			Required:  true,
			Sensitive: false,
		}, {
			Name:      "api_key",
			Help:      "An API key for your account.",
			Required:  true,
			Sensitive: true,
		}, {
			Name:     "endpoint",
			Help:     "Endpoint for the service.\n\nLeave blank normally.",
			Advanced: true,
		}, {
			Name:     config.ConfigEncoding,
			Help:     config.ConfigEncodingHelp,
			Advanced: true,
			Default: encoder.Display |
				encoder.EncodeBackSlash |
				encoder.EncodeInvalidUtf8,
		}},
	})
}

type Options struct {
	Drive    string `config:"drive_id"`
	ApiKey   string `config:"api_key"`
	Endpoint string `config:"endpoint"`
}

type Fs struct {
	name     string
	root     string
	opt      Options
	features *fs.Features

	srv *rest.Client

	endpoint string
	drive    string

	pacer *fs.Pacer
	// todo drive
}

type Object struct {
	fs     *Fs
	remote string // the remote path

	mtime int64
	hash  string
	size  int64
}

type Directory struct {
	Object
}

func NewFS(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	opt := new(Options)

	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	f := &Fs{
		name: name,
		root: root, // fmt.Sprintf("%s/%s", name, root),
		opt:  *opt,
		// No features get rekt
		features: &fs.Features{},

		drive: opt.Drive,

		srv: rest.NewClient(fshttp.NewClient(ctx)),
		// Pacer
		pacer: fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}

	if opt.Endpoint == "" {
		f.endpoint = defaultEndpoint
	}

	return f, nil
}

func (d Directory) Items() int64 {
	//TODO implement me
	panic("implement me")
}

func (d Directory) ID() string {
	//TODO implement me
	panic("implement me")
}

/*
------------------ FS APIS
*/

func (f *Fs) Name() string {
	return f.name
}

func (f *Fs) Root() string {
	return f.root
}

func (f *Fs) String() string {
	return fmt.Sprintf("Shade drive %s path %s", f.opt.Drive, f.root)
}

func (f *Fs) Precision() time.Duration {
	println("precision")
	//TODO implement me
	panic("implement me")
}

func (f *Fs) Hashes() hash.Set {
	println("hashes")
	return hash.Set(hash.MD5)
}

func (f *Fs) Features() *fs.Features {
	println("features")
	return f.features
}

func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	encodedPath := url.QueryEscape(fmt.Sprintf("%s/%s", f.root, remote))

	opts := rest.Opts{
		Method:  "GET",
		Path:    fmt.Sprintf("/%s/fs/attr?path=%s", f.drive, encodedPath),
		RootURL: f.endpoint,
	}

	println(fmt.Sprintf("Attring %s", opts.Path))

	var response ListDirResponse

	res, _ := f.srv.CallJSON(ctx, &opts, nil, &response)

	if res.StatusCode == http.StatusNotFound {
		return nil, fs.ErrorObjectNotFound
	}

	// TODO isdirectory error

	fmt.Printf("Response %s", response.Path)

	var entry fs.Object

	if response.Type == "file" {
		entry = &Object{
			fs:     f,
			remote: response.Path[len(response.Path)+1:],
			mtime:  response.Mtime,
			hash:   response.Hash,
			size:   response.Size,
		}
	} else {
		entry = &Directory{
			Object{
				fs:     f,
				remote: response.Path[len(response.Path)+1:],
				mtime:  response.Mtime,
				hash:   response.Hash,
				size:   response.Size,
			},
		}
	}

	return entry, nil
}

func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	println("put")
	//TODO implement me
	panic("implement me")
}

func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	encodedPath := url.QueryEscape(fmt.Sprintf("%s/%s", f.root, dir))

	opts := rest.Opts{
		Method:  "POST",
		Path:    fmt.Sprintf("/%s/fs/mkdir?path=%s&email=system@shade.inc", f.drive, encodedPath),
		RootURL: f.endpoint,
	}

	_, _ = f.srv.Call(ctx, &opts)

	//if res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusInternalServerError {
	//	return nil
	//}

	return nil
}

func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	encodedPath := url.QueryEscape(fmt.Sprintf("%s/%s", f.root, dir))

	opts := rest.Opts{
		Method:  "DELETE",
		Path:    fmt.Sprintf("/%s/fs/delete?path=%s&email=system@shade.inc", f.drive, encodedPath),
		RootURL: f.endpoint,
	}

	_, _ = f.srv.Call(ctx, &opts)

	return nil
}

/*
------------------ OBJECT APIS
*/

func (o Object) Fs() fs.Info {
	println("fs")
	return o.fs
}

func (o Object) String() string {
	println("string")
	return o.remote
}

func (o Object) Remote() string {
	println("remote")
	return o.remote
}

func (o Object) ModTime(ctx context.Context) time.Time {
	println("modtime might not be right")
	return time.Unix(0, o.mtime)
}

func (o Object) Size() int64 {
	return o.size
}

func (o Object) Hash(ctx context.Context, ty hash.Type) (string, error) {
	return o.hash, nil
}

func (o Object) Storable() bool {
	println("storable")
	//TODO implement me
	panic("implement me")
}

func (o Object) SetModTime(ctx context.Context, t time.Time) error {
	println("setmodtime")
	//TODO implement me
	panic("implement me")
}

func (o Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	println("open")
	//TODO implement me
	panic("implement me")
}

func (o Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	println("update")
	//TODO implement me
	panic("implement me")
}

func (o Object) Remove(ctx context.Context) error {
	println("remove")
	//TODO implement me
	panic("implement me")
}

/*
[

	{
	  "type": "file",
	  "path": "/.fseventsd",
	  "ino": 2,
	  "mtime": 0,
	  "ctime": 0,
	  "size": 0,
	  "hash": "main-0-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	  "draft": false
	}

]
*/

type ListDirResponse struct {
	Type  string `json:"type"`
	Path  string `json:"path"`
	Ino   int    `json:"ino"`
	Mtime int64  `json:"mtime"`
	Ctime int64  `json:"ctime"`
	Size  int64  `json:"size"`
	Hash  string `json:"hash"`
	Draft bool   `json:"draft"`
}

//// errorHandler parses a non 2xx error response into an error
//func errorHandler(resp *http.Response) error {
//	body, err := rest.ReadBody(resp)
//	if err != nil {
//		fs.Errorf(nil, "Couldn't read error out of body: %v", err)
//		body = nil
//	}
//	// Decode error response if there was one - they can be blank
//	errResponse := new(api.Error)
//	if len(body) > 0 {
//		err = json.Unmarshal(body, errResponse)
//		if err != nil {
//			fs.Errorf(nil, "Couldn't decode error response: %v", err)
//		}
//	}
//	if errResponse.Code == "" {
//		errResponse.Code = "unknown"
//	}
//	if errResponse.Status == 0 {
//		errResponse.Status = resp.StatusCode
//	}
//	if errResponse.Message == "" {
//		errResponse.Message = "Unknown " + resp.Status
//	}
//	return errResponse
//}

func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	//println(fmt.Sprintf("Listing %s", dir))
	// fmt.Printf("Dir %s\n", dir)
	//resp := rest.Opts{
	//	Method: "GET",
	//	Path: "/admin/fs/listdir",
	//}
	//
	//err := f.pacer.Call(func () (bool, error)) {
	//	resp, err := f.srv.CallJSON(ctx, resp, nil, &f.info)
	//}
	//entry := &Object{
	//	fs:     f,
	//	remote: "folder/gotem.txt",
	//
	//	mtime: 0,
	//	hash:  "8dbd7b38675abc0fe88054b783cc1d39",
	//	size:  123,
	//}
	//entries = append(entries, entry)
	//
	//entry2 := &Object{
	//	fs:     f,
	//	remote: "gotem1.txt",
	//
	//	mtime: 0,
	//	hash:  "8dbd7b38675abc0fe88054b783cc1d39",
	//	size:  123,
	//}

	encodedPath := url.QueryEscape(fmt.Sprintf("%s/%s", f.root, dir))

	opts := rest.Opts{
		Method:  "GET",
		Path:    fmt.Sprintf("/%s/fs/listdir?path=%s", f.drive, encodedPath),
		RootURL: f.endpoint,
	}

	println(fmt.Sprintf("Listing %s", opts.Path))

	var response []ListDirResponse

	res, _ := f.srv.CallJSON(ctx, &opts, nil, &response)

	if res.StatusCode == http.StatusNotFound {
		return nil, fs.ErrorDirNotFound
	}

	fmt.Printf("Response: %v\n", response[0].Hash)

	for _, r := range response {
		fmt.Printf("Response: %v\n", r.Path)
		if r.Draft {
			continue
		}
		if r.Type == "file" {
			entries = append(entries, &Object{
				fs:     f,
				remote: r.Path[len(f.root)+1:],

				mtime: r.Mtime,
				hash:  r.Hash,
				size:  r.Size,
			})
		} else {
			entries = append(entries, &Directory{
				Object: Object{
					fs:     f,
					remote: r.Path[len(f.root)+1:],
					mtime:  r.Mtime,
					hash:   r.Hash,
					size:   r.Size,
				},
			})
		}
	}

	return entries, nil
}

var (
	_ fs.Fs        = &Fs{}
	_ fs.Object    = &Object{}
	_ fs.Directory = &Directory{}
)
