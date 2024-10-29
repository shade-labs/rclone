// Package shade provides an interface to the Shade storage system.
package shade

import (
	"context"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/hash"
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

// Options defines the configuration for this backend
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
}

func (f *Fs) Name() string {
	return f.name
}

func (f *Fs) Root() string {
	return f.root
}

func (f *Fs) String() string {
	//TODO implement me
	panic("implement me")
}

func (f *Fs) Precision() time.Duration {
	//TODO implement me
	panic("implement me")
}

func (f *Fs) Hashes() hash.Set {
	//TODO implement me
	panic("implement me")
}

func (f *Fs) Features() *fs.Features {
	//TODO implement me
	panic("implement me")
}

func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	//TODO implement me
	panic("implement me")
}

func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	//TODO implement me
	panic("implement me")
}

func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	//TODO implement me
	panic("implement me")
}

func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	//TODO implement me
	panic("implement me")
}

type Object struct {
	fs *Fs
}

func NewFS(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	opt := new(Options)

	f := &Fs{
		name: name,
		opt:  *opt,
		// No features get rekt
		features: &fs.Features{},
	}

	return f, nil
}

func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	return nil, nil
}

var (
	_ fs.Fs = &Fs{}
)
