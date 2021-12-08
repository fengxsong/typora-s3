package main

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/policy"
	"github.com/spf13/pflag"
	"github.com/stoewer/go-strcase"
	"gopkg.in/yaml.v2"
)

const (
	app    = "typora-s3"
	imgDir = "images"
)

type Config struct {
	fs          *pflag.FlagSet
	HashAlg     string `yaml:"hashAlg"`
	Path        string `yaml:"-"`
	EndPoint    string `yaml:"endpoint"`
	AccessKey   string `yaml:"accessKey"`
	SecretKey   string `yaml:"secretKey"`
	BucketName  string `yaml:"bucketName"`
	UseSSL      bool   `yaml:"useSsl"`
	RemoveAfter bool   `yaml:"removeAfter"`
}

func (c *Config) AddFlags(fs *pflag.FlagSet) {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	var username string
	currentUser, err := user.Current()
	if err != nil {
		username = os.Getenv("USER")
	} else {
		username = currentUser.Username
	}
	c.fs = fs
	c.fs.StringVarP(&c.Path, "configPath", "c", path.Join(home, fmt.Sprintf(".%s.yaml", app)), "Path of config file")
	c.fs.StringVar(&c.EndPoint, "endpoint", "", "S3-compatible server endpoint")
	c.fs.StringVar(&c.AccessKey, "accessKey", "", "AccessKey")
	c.fs.StringVar(&c.SecretKey, "secretKey", "", "SecretKey")
	c.fs.StringVarP(&c.BucketName, "bucketName", "b", username, "S3 bucket name")
	c.fs.BoolVar(&c.UseSSL, "useSsl", false, "Perform ssl connection")
}

func copyValue(src, dest *Config) {
	from := reflect.ValueOf(src).Elem()
	to := reflect.ValueOf(dest).Elem()
	for i := 0; i < from.NumField(); i++ {
		if !from.Field(i).IsZero() {
			to.Field(i).Set(from.Field(i))
		}
	}
}

func (c *Config) Validate() error {
	mustSetError := func(s string) error { return fmt.Errorf("%s must been set", s) }
	if c.EndPoint == "" {
		return mustSetError("endpoint")
	}
	if c.AccessKey == "" {
		return mustSetError("accessKey")
	}
	if c.SecretKey == "" {
		return mustSetError("secretKey")
	}
	return nil
}

func (c *Config) Load() error {
	if c.Path != "" {
		if fi, err := os.Open(c.Path); err == nil {
			var tmp Config
			if err = yaml.NewDecoder(fi).Decode(&tmp); err != nil {
				return err
			}
			copyValue(&tmp, c)
		}
	}
	normalize := func(prefix, key string) string {
		return strings.ToUpper(strcase.SnakeCase(prefix + key))
	}
	c.fs.VisitAll(func(f *pflag.Flag) {
		key := normalize(app, f.Name)
		if v := os.Getenv(key); v != "" {
			f.Value.Set(v)
		}
	})
	return c.Validate()
}

func NewClient(cfg *Config) (*Client, error) {
	mc, err := minio.New(cfg.EndPoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, err
	}
	return &Client{cfg, mc}, nil
}

type Client struct {
	cfg *Config
	mc  *minio.Client
}

func (c *Client) hashPath(alg string, s string) (string, error) {
	var hasher hash.Hash
	switch alg {
	case "md5":
		hasher = md5.New()
	case "sha1":
		hasher = sha1.New()
	default:
		hasher = sha256.New()
	}
	if _, err := hasher.Write([]byte(s)); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

func (c *Client) Upload(ctx context.Context, fileName string) (*minio.UploadInfo, error) {
	absPath, err := filepath.Abs(fileName)
	if err != nil {
		return nil, err
	}
	hashPath, err := c.hashPath(c.cfg.HashAlg, absPath)
	if err != nil {
		return nil, err
	}
	objectPath := fmt.Sprintf("%s/%s%s", imgDir, hashPath, path.Ext(absPath))
	info, err := c.mc.FPutObject(
		ctx,
		c.cfg.BucketName,
		objectPath,
		absPath,
		minio.PutObjectOptions{})
	if err != nil {
		return nil, err
	}
	if c.cfg.RemoveAfter {
		os.Remove(absPath)
	}
	return &info, nil
}

func (c *Client) ensureBucket() error {
	err := c.mc.MakeBucket(context.Background(), c.cfg.BucketName, minio.MakeBucketOptions{})
	if err != nil {
		exists, err := c.mc.BucketExists(context.Background(), c.cfg.BucketName)
		if err == nil && exists {
			return nil
		}
		return fmt.Errorf("failed to ensure bucket: %v", err)
	}
	return nil
}

// or maybe just set policy to parent dir
func (c *Client) setPublic(ctx context.Context, object string) error {
	const bucketPolicy = policy.BucketPolicyReadOnly
	policyStr, err := c.mc.GetBucketPolicy(ctx, c.cfg.BucketName)
	if err != nil {
		return err
	}
	var p = policy.BucketAccessPolicy{Version: "2012-10-17"}
	if policyStr != "" {
		if err = json.Unmarshal([]byte(policyStr), &p); err != nil {
			return err
		}
	}
	p.Statements = policy.SetPolicy(p.Statements, bucketPolicy, c.cfg.BucketName, object)
	policyB, err := json.Marshal(p)
	if err != nil {
		return err
	}
	err = c.mc.SetBucketPolicy(ctx, c.cfg.BucketName, string(policyB))
	if err != nil {
		return fmt.Errorf("failed to set bucket public: %v", err)
	}
	return nil
}

func (c *Client) setImgDirPublic() error {
	return c.setPublic(context.Background(), imgDir)
}

func toURL(ep string, info *minio.UploadInfo) string {
	return strings.Join([]string{ep, info.Bucket, info.Key}, "/")
}

func main() {
	fs := pflag.NewFlagSet(app, pflag.ExitOnError)
	cfg := &Config{}
	cfg.AddFlags(fs)
	fs.Parse(os.Args[1:])
	if fs.NArg() == 0 {
		return
	}

	if err := cfg.Load(); err != nil {
		fatal(err)
	}
	clnt, err := NewClient(cfg)
	if err != nil {
		fatal(err)
	}
	for _, fn := range []func() error{
		clnt.ensureBucket,
		clnt.setImgDirPublic,
	} {
		if err = fn(); err != nil {
			fatal(err)
		}
	}

	assets := make([]*minio.UploadInfo, 0, len(fs.Args()))
	for i := range fs.Args() {
		twCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		info, err := clnt.Upload(twCtx, fs.Arg(i))
		if err != nil {
			fatal(err)
		}
		assets = append(assets, info)
	}
	for _, as := range assets {
		fmt.Println(toURL(clnt.mc.EndpointURL().String(), as))
	}
}

func fatal(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
