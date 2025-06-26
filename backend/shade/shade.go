// Package shade provides an interface to the Shade storage system.
// running with: -vv copy shadefs_v1:Test "/Users/gurish/Movies/Shade/Movie Trailers" --multi-thread-cutoff 1000G
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
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/rest"
)

const (
	defaultEndpoint = "https://fs.shade.inc"  // Default local development endpoint
	apiEndpoint     = "https://api.shade.inc" // API endpoint for getting tokens
	minSleep        = 10 * time.Millisecond   // Minimum sleep time for the pacer
	maxSleep        = 5 * time.Minute         // Maximum sleep time for the pacer
	decayConstant   = 1                       // Bigger for slower decay, exponential
	tokenTTL        = 5 * time.Minute         // Token expires in 5 mins, refresh after 4
)

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "shade",
		Description: "Shade FS",
		NewFs:       NewFS,
		CommandHelp: []fs.CommandHelp{{
			Name:  "token",
			Short: "Get a ShadeFS token",
			Long:  "Get and display a ShadeFS token for the configured drive",
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

// Options defines the configuration for this backend
type Options struct {
	Drive    string `config:"drive_id"`
	ApiKey   string `config:"api_key"`
	Endpoint string `config:"endpoint"`
	Encoding encoder.MultiEncoder
}

// Fs represents a shade remote
type Fs struct {
	name      string       // name of this remote
	root      string       // the path we are working on
	opt       Options      // parsed options
	features  *fs.Features // optional features
	srv       *rest.Client // REST client for ShadeFS API
	apiSrv    *rest.Client // REST client for Shade API
	endpoint  string       // endpoint for ShadeFS
	drive     string       // drive ID
	pacer     *fs.Pacer    // pacer for API calls
	token     string       // ShadeFS token
	tokenExp  time.Time    // Token expiration time
	tokenMu   sync.Mutex
	recursive bool
}

// Object describes a ShadeFS object
type Object struct {
	fs     *Fs    // what this object is part of
	remote string // The remote path
	mtime  int64  // Modified time
	hash   string // Content hash
	size   int64  // Size of the object
}

// Directory describes a ShadeFS directory
type Directory struct {
	fs     *Fs    // Reference to the filesystem
	remote string // Path to the directory
	mtime  int64  // Modification time
	size   int64  // Size (typically 0 for directories)
}

// NewFS constructs an FS from the path, container:path
func NewFS(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	// Parse config into Options struct
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	fs.Debugf(nil, "Creating new ShadeFS backend with drive: %s", opt.Drive)

	// Check if the root path looks like a single file
	// This will prevent users from specifying single files in the source
	if root != "" && filepath.Ext(root) != "" {
		return nil, fmt.Errorf("can't use ShadeFS with a single file path (%s), must use a directory", root)
	}

	f := &Fs{
		name:      name,
		root:      root,
		opt:       *opt,
		drive:     opt.Drive,
		srv:       rest.NewClient(fshttp.NewClient(ctx)),
		apiSrv:    rest.NewClient(fshttp.NewClient(ctx)),
		pacer:     fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
		recursive: true,
	}

	f.features = &fs.Features{
		// Initially set minimal features
		// We'll expand this in a future iteration
		CanHaveEmptyDirectories: true,
	}

	// Set the endpoint
	if opt.Endpoint == "" {
		f.endpoint = defaultEndpoint
	} else {
		f.endpoint = opt.Endpoint
	}

	// Ensure root doesn't have trailing slash
	f.root = strings.Trim(f.root, "/")
	if f.root != "" {
		fs.Debugf(f, "Root directory is: %s", f.root)
	}

	// Check that we can log in by getting a token
	_, err = f.getShadeToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get ShadeFS token: %w", err)
	}

	return f, nil
}

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// String returns a description of the FS
func (f *Fs) String() string {
	return fmt.Sprintf("Shade drive %s path %s", f.opt.Drive, f.root)
}

// Precision returns the precision of the ModTimes
func (f *Fs) Precision() time.Duration {
	return time.Millisecond
}

// Hashes returns the supported hash types
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.MD5)
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// getShadeToken retrieves or refreshes the ShadeFS token
func (f *Fs) getShadeToken(ctx context.Context) (string, error) {
	fs.Debugf(f, "Checking if token is valid...")
	f.tokenMu.Lock()
	defer f.tokenMu.Unlock()

	// Return existing token if it's still valid
	if f.token != "" && time.Now().Before(f.tokenExp) {
		fs.Debugf(f, "Using existing token (expires in %v)", f.tokenExp.Sub(time.Now()))
		return f.token, nil
	}

	fs.Debugf(f, "Token expired or not set, requesting new token from API")

	// Token has expired or doesn't exist, get a new one
	opts := rest.Opts{
		Method:  "GET",
		RootURL: apiEndpoint,
		Path:    fmt.Sprintf("/workspaces/drives/%s/shade-fs-token", f.drive),
		ExtraHeaders: map[string]string{
			"Authorization": f.opt.ApiKey,
		},
	}

	var err error
	var tokenStr string

	f.tokenMu.Unlock()
	defer f.tokenMu.Lock() // Re-lock before updating shared state

	err = f.pacer.Call(func() (bool, error) {
		res, err := f.apiSrv.Call(ctx, &opts)
		if err != nil {
			fs.Debugf(f, "Token request failed: %v", err)
			return false, err
		}

		defer fs.CheckClose(res.Body, &err)

		if res.StatusCode != http.StatusOK {
			fs.Debugf(f, "Token request failed with code: %d", res.StatusCode)
			return res.StatusCode == http.StatusTooManyRequests, fmt.Errorf("failed to get ShadeFS token, status: %d", res.StatusCode)
		}

		// Read token directly as plain text
		tokenBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}

		tokenStr = strings.TrimSpace(string(tokenBytes))
		return false, nil
	})

	if err != nil {
		return "", err
	}

	if tokenStr == "" {
		return "", fmt.Errorf("empty token received from server")
	}

	fs.Debugf(f, "Successfully obtained new token")
	f.token = tokenStr
	f.tokenExp = time.Now().Add(tokenTTL)
	return f.token, nil
}

// List the objects and directories in dir into entries
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {

	encodedPath := f.buildFullPath(dir)

	var response []ListDirResponse
	res, err := f.callAPI(ctx, "GET", fmt.Sprintf("/%s/fs/listdir?path=%s", f.drive, encodedPath), &response)
	if err != nil {
		fs.Debugf(f, "Error from List call: %v", err)
		return nil, err
	}

	if res.StatusCode == http.StatusNotFound {
		fs.Debugf(f, "Directory not found")
		return nil, fs.ErrorDirNotFound
	}

	if res.StatusCode != http.StatusOK {
		fs.Debugf(f, "Bad status code from server: %d", res.StatusCode)
		return nil, fmt.Errorf("listdir failed with status code: %d", res.StatusCode)
	}

	fs.Debugf(f, "Received %d entries from server", len(response))
	for _, r := range response {
		if r.Draft {
			fs.Debugf(f, "Skipping draft file: %s", r.Path)
			continue
		}

		// Make path relative to f.root
		entryPath := r.Path
		if strings.HasPrefix(entryPath, "/") {
			entryPath = entryPath[1:]
		}
		if f.root != "" {
			if !strings.HasPrefix(entryPath, f.root) {
				fs.Debugf(f, "Path %s doesn't have root prefix %s, skipping", entryPath, f.root)
				continue
			}
			entryPath = strings.TrimPrefix(entryPath, f.root)
			if strings.HasPrefix(entryPath, "/") {
				entryPath = entryPath[1:]
			}
		}

		fs.Debugf(f, "Processing entry: %s, type: %s, size: %d", entryPath, r.Type, r.Size)

		if r.Type == "file" {
			entries = append(entries, &Object{
				fs:     f,
				remote: entryPath,
				mtime:  r.Mtime,
				size:   r.Size,
			})
		} else if r.Type == "tree" {
			dirEntry := &Directory{
				fs:     f,
				remote: entryPath,
				mtime:  r.Mtime,
				size:   r.Size, // Typically 0 for directories
			}
			entries = append(entries, dirEntry)
		} else {
			fs.Debugf(f, "Unknown entry type: %s for path: %s", r.Type, entryPath)
		}
	}

	return entries, nil
}

// NewObject finds the Object at remote
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	fs.Debugf(f, "Finding object: %s", remote)

	encodedPath := f.buildFullPath(remote)

	var response ListDirResponse
	res, err := f.callAPI(ctx, "GET", fmt.Sprintf("/%s/fs/attr?path=%s", f.drive, encodedPath), &response)

	if err != nil {
		fs.Debugf(f, "Error from NewObject call: %v", err)
		return nil, err
	}

	if res.StatusCode == http.StatusNotFound {
		fs.Debugf(f, "Object not found")
		return nil, fs.ErrorObjectNotFound
	}

	if res.StatusCode != http.StatusOK {
		fs.Debugf(f, "Bad status code from server: %d", res.StatusCode)
		return nil, fmt.Errorf("attr failed with status code: %d", res.StatusCode)
	}

	fs.Debugf(f, "Received object info: type=%s, size=%d", response.Type, response.Size)

	if response.Type == "dir" {
		fs.Debugf(f, "Path is a directory: %s", remote)
		return nil, fs.ErrorIsDir
	}

	if response.Type != "file" {
		fs.Debugf(f, "Path is not a file: %s (type=%s)", remote, response.Type)
		return nil, fmt.Errorf("path is not a file: %s", remote)
	}

	return &Object{
		fs:     f,
		remote: remote,
		mtime:  response.Mtime,
		size:   response.Size,
	}, nil
}

// Put uploads a file
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	// Currently not implementing upload functionality
	// This will be part of future enhancements
	return nil, fs.ErrorNotImplemented
}

// Mkdir creates a directory
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	return fs.ErrorNotImplemented
}

// Rmdir removes a directory
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	return fs.ErrorNotImplemented
}

// -------------------------------------------------
// Object implementation
// -------------------------------------------------

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

// String returns a description of the Object
func (o *Object) String() string {
	return o.remote
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// ModTime returns the modification date of the object
func (o *Object) ModTime(ctx context.Context) time.Time {
	return time.Unix(0, o.mtime*int64(time.Millisecond))
}

// Size returns the size of the object
func (o *Object) Size() int64 {
	return o.size
}

// Hash returns the requested hash of the object content
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	if t != hash.MD5 {
		return "", hash.ErrUnsupported
	}

	// If we already have the hash from reading the file, return it
	if o.hash != "" {
		return o.hash, nil
	}

	// If no hash is available yet, trigger a read that will compute it
	reader, err := o.Open(ctx)
	if err != nil {
		return "", err
	}
	defer reader.Close()

	// Read the entire file to compute the hash
	_, err = io.Copy(io.Discard, reader)
	if err != nil {
		return "", err
	}

	// The hash should now be set by the hashingReadCloser
	if o.hash == "" {
		return "", fmt.Errorf("failed to compute MD5 hash")
	}

	return o.hash, nil
}

// Storable returns whether this object is storable
func (o *Object) Storable() bool {
	return true
}

// SetModTime sets the modification time of the object
func (o *Object) SetModTime(ctx context.Context, t time.Time) error {
	// Not implemented for now
	return fs.ErrorCantSetModTime
}

func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	fs.Debugf(o.fs, "Opening file: %s", o.remote)

	if o.Size() == 0 && filepath.Ext(o.remote) == "" { // Heuristic for directories
		fs.Debugf(o.fs, "Attempted to open directory as file: %s", o.remote)
		return nil, fs.ErrorIsDir
	}

	token, err := o.fs.getShadeToken(ctx)
	if err != nil {
		return nil, err
	}

	fullPath := o.remote
	if o.fs.root != "" {
		fullPath = path.Join(o.fs.root, o.remote)
	}
	encodedPath := url.QueryEscape(fullPath)
	fs.Debugf(o.fs, "Encoded path for download: %s", encodedPath)

	// Construct the initial request URL
	downloadURL := fmt.Sprintf("%s/%s/fs/download?path=%s", o.fs.endpoint, o.fs.drive, encodedPath)

	// Create HTTP request manually
	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		fs.Debugf(o.fs, "Failed to create request: %v", err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// Use pacer to manage retries and rate limiting
	var res *http.Response
	err = o.fs.pacer.Call(func() (bool, error) {
		client := http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		}
		res, err = client.Do(req)
		if err != nil {
			fs.Debugf(o.fs, "Initial download request failed: %v", err)
			return false, err
		}
		return res.StatusCode == http.StatusTooManyRequests, nil
	})
	if err != nil {
		fs.Debugf(o.fs, "Failed to make initial download request: %v", err)
		return nil, fmt.Errorf("failed to make initial download request: %w", err)
	}
	if res == nil {
		return nil, fmt.Errorf("no response received from initial request")
	}

	// Handle response based on status code
	switch res.StatusCode {
	case http.StatusOK:
		fs.Debugf(o.fs, "Received file directly from ShadeFS")
		return res.Body, nil

	case http.StatusTemporaryRedirect:
		// Read the presigned URL from the body
		bodyBytes, err := io.ReadAll(res.Body)
		fs.CheckClose(res.Body, &err) // Close body after reading
		if err != nil {
			fs.Debugf(o.fs, "Failed to read redirect body: %v", err)
			return nil, fmt.Errorf("failed to read redirect body: %w", err)
		}

		presignedURL := strings.TrimSpace(string(bodyBytes))
		fs.Debugf(o.fs, "Received presigned URL: %q", presignedURL)

		// Create request for presigned URL
		req, err := http.NewRequestWithContext(ctx, "GET", presignedURL, nil)
		if err != nil {
			fs.Debugf(o.fs, "Failed to create presigned URL request: %v", err)
			return nil, fmt.Errorf("failed to create presigned URL request: %w", err)
		}

		// Fetch the file from presigned URL with pacer
		var downloadRes *http.Response
		err = o.fs.pacer.Call(func() (bool, error) {
			client := http.Client{}
			downloadRes, err = client.Do(req)
			if err != nil {
				fs.Debugf(o.fs, "Failed to fetch presigned URL: %v", err)
				return false, err
			}
			return downloadRes.StatusCode == http.StatusTooManyRequests, nil
		})
		if err != nil {
			fs.Debugf(o.fs, "Failed to fetch presigned URL: %v", err)
			return nil, fmt.Errorf("failed to fetch presigned URL: %w", err)
		}

		if downloadRes.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(downloadRes.Body)
			fs.CheckClose(downloadRes.Body, &err)
			return nil, fmt.Errorf("presigned URL request failed with status %d: %q", downloadRes.StatusCode, string(body))
		}

		// Create a MultiHasher with just MD5 support
		multiHasher, err := hash.NewMultiHasherTypes(hash.NewHashSet(hash.MD5))
		if err != nil {
			fs.Debugf(o.fs, "Failed to create MultiHasher: %v", err)
			return downloadRes.Body, nil // Still return the body even if we can't hash
		}

		return &hashingReadCloser{
			closer: downloadRes.Body,
			hasher: multiHasher,
			o:      o,
			Reader: io.TeeReader(downloadRes.Body, multiHasher),
		}, nil

	default:
		body, _ := io.ReadAll(res.Body)
		fs.CheckClose(res.Body, &err)
		fs.Debugf(o.fs, "Unexpected status code from ShadeFS: %d, body: %q", res.StatusCode, string(body))
		return nil, fmt.Errorf("download failed with status %d: %q", res.StatusCode, string(body))
	}
}

type hashingReadCloser struct {
	Reader io.Reader
	closer io.ReadCloser
	hasher *hash.MultiHasher
	o      *Object
	read   int64
}

func (h *hashingReadCloser) Read(p []byte) (n int, err error) {
	n, err = h.Reader.Read(p)
	if n > 0 {
		h.read += int64(n)
	}
	if err == io.EOF {
		// At EOF, store the computed hash
		sums := h.hasher.Sums()
		if md5sum, ok := sums[hash.MD5]; ok {
			h.o.hash = md5sum
			fs.Debugf(h.o.fs, "Computed MD5 hash at EOF: %s (read %d bytes)", h.o.hash, h.read)
		}
	}
	return n, err
}

func (h *hashingReadCloser) Close() error {
	// If we haven't computed the hash yet, calculate it now
	if h.o.hash == "" {
		sums := h.hasher.Sums()
		if md5sum, ok := sums[hash.MD5]; ok {
			h.o.hash = md5sum
			fs.Debugf(h.o.fs, "Computed MD5 hash at Close: %s (read %d bytes)", h.o.hash, h.read)
		}
	}
	return h.closer.Close()
}

// Update updates the object with the contents of the io.Reader
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	// Currently not implementing upload functionality
	// This will be part of future enhancements
	return fs.ErrorNotImplemented
}

// Remove removes the object
func (o *Object) Remove(ctx context.Context) error {
	fs.Debugf(o.fs, "Removing file: %s", o.remote)

	encodedPath := o.fs.buildFullPath(o.remote)
	fs.Debugf(o.fs, "Encoded path for delete: %s", encodedPath)

	res, err := o.fs.callAPI(ctx, "POST", fmt.Sprintf("/%s/fs/delete?path=%s", o.fs.drive, encodedPath), nil)
	if err != nil {
		return err
	}
	defer fs.CheckClose(res.Body, &err) // Ensure body is closed

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return fmt.Errorf("Object removal failed with status code: %d", res.StatusCode)
	}
	return nil
}

func (f *Fs) buildFullPath(remote string) string {
	if f.root == "" {
		return url.QueryEscape(remote)
	}
	return url.QueryEscape(path.Join(f.root, remote))
}

func (f *Fs) callAPI(ctx context.Context, method, path string, response interface{}) (*http.Response, error) {
	token, err := f.getShadeToken(ctx)
	if err != nil {
		return nil, err
	}
	opts := rest.Opts{
		Method:  method,
		Path:    path,
		RootURL: f.endpoint,
		ExtraHeaders: map[string]string{
			"Authorization": "Bearer " + token,
		},
	}
	var res *http.Response
	err = f.pacer.Call(func() (bool, error) {
		if response != nil {
			res, err = f.srv.CallJSON(ctx, &opts, nil, response)
		} else {
			res, err = f.srv.Call(ctx, &opts)
		}
		if err != nil {
			return res != nil && res.StatusCode == http.StatusTooManyRequests, err
		}
		return false, nil
	})
	return res, err
}

// -------------------------------------------------
// Directory implementation
// -------------------------------------------------

// Remote returns the remote path
func (d *Directory) Remote() string {
	return d.remote
}

// ModTime returns the modification time
func (d *Directory) ModTime(ctx context.Context) time.Time {
	return time.Unix(0, d.mtime*int64(time.Millisecond))
}

// Size returns the size (0 for directories)
func (d *Directory) Size() int64 {
	return d.size
}

// Fs returns the filesystem info
func (d *Directory) Fs() fs.Info {
	return d.fs
}

// Hash is unsupported for directories
func (d *Directory) Hash(ctx context.Context, t hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

// SetModTime is unsupported for directories
func (d *Directory) SetModTime(ctx context.Context, t time.Time) error {
	return fs.ErrorCantSetModTime
}

// Storable indicates directories aren’t storable as files
func (d *Directory) Storable() bool {
	return false
}

// Open returns an error for directories
func (d *Directory) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	fs.Debugf(d.fs, "Attempted to open directory: %s", d.remote)
	return nil, fs.ErrorIsDir
}

// Items returns the number of items in the directory (-1 if unknown)
func (d *Directory) Items() int64 {
	return -1 // Unknown
}

// ID returns the directory ID (empty if not applicable)
func (d *Directory) ID() string {
	return ""
}

func (d *Directory) String() string {
	return fmt.Sprintf("Directory: %s", d.remote)
}

// -------------------------------------------------
// ListDir Response format
// -------------------------------------------------

type ListDirResponse struct {
	Type  string `json:"type"`  // "file" or "dir"
	Path  string `json:"path"`  // Full path including root
	Ino   int    `json:"ino"`   // inode number
	Mtime int64  `json:"mtime"` // Modified time in milliseconds
	Ctime int64  `json:"ctime"` // Created time in milliseconds
	Size  int64  `json:"size"`  // Size in bytes
	Hash  string `json:"hash"`  // MD5 hash
	Draft bool   `json:"draft"` // Whether this is a draft file
}

// Register interface implementations
var (
	_ fs.Fs        = &Fs{}
	_ fs.Object    = &Object{}
	_ fs.Directory = &Directory{}
)
