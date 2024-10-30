// Package shade provides an interface to the Shade storage system.
package shade

import (
	"context"
	"fmt"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/pacer"
	"io"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/lib/encoder"
)

const (
	defaultEndpoint = "https://fs.shade.inc"
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
			Sensitive: true,
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
	Workspace string `config:"drive_id"`
	ApiKey    string `config:"api_key"`
	Endpoint  string `config:"endpoint"`
}

type Fs struct {
	name     string
	root     string
	opt      Options
	features *fs.Features

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
	return fmt.Sprintf("Shade drive %s path %s", f.opt.Workspace, f.root)
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
	println("newobject")
	//TODO implement me
	panic("implement me")
}

func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	println("put")
	//TODO implement me
	panic("implement me")
}

func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	println("mkdir")
	//TODO implement me
	panic("implement me")
}

func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	println("rmdir")
	//TODO implement me
	panic("implement me")
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
	println("modtime")
	//TODO implement me
	panic("implement me")
}

func (o Object) Size() int64 {
	println("size")
	return 0
	////TODO implement me
	//panic("implement me")
}

func (o Object) Hash(ctx context.Context, ty hash.Type) (string, error) {
	println("hash")
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

func NewFS(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	opt := new(Options)

	println(fmt.Sprintf("%s/%s", name, root))

	f := &Fs{
		name: name,
		root: root, // fmt.Sprintf("%s/%s", name, root),
		opt:  *opt,
		// No features get rekt
		features: &fs.Features{},
		// Pacer
		pacer: fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}

	return f, nil
}

func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {

	//println(fmt.Sprintf("Listing %s", dir))
	fmt.Printf("Dir %s\n", dir)
	//resp := rest.Opts{
	//	Method: "GET",
	//	Path: "/admin/fs/listdir",
	//}
	//
	//err := f.pacer.Call(func () (bool, error)) {
	//	resp, err := f.srv.CallJSON(ctx, resp, nil, &f.info)
	//}
	entry := &Object{
		fs:     f,
		remote: "folder/gotem.txt",

		mtime: 0,
		hash:  "8dbd7b38675abc0fe88054b783cc1d39",
		size:  123,
	}
	entries = append(entries, entry)

	entry2 := &Object{
		fs:     f,
		remote: "gotem1.txt",

		mtime: 0,
		hash:  "8dbd7b38675abc0fe88054b783cc1d39",
		size:  123,
	}
	entries = append(entries, entry2)

	return entries, nil
}

var (
	_ fs.Fs        = &Fs{}
	_ fs.Object    = &Object{}
	_ fs.Directory = &Directory{}
)
