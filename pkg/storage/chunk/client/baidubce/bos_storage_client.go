package baidubce

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"io"
	"time"

	"github.com/baidubce/bce-sdk-go/auth"
	"github.com/baidubce/bce-sdk-go/bce"
	"github.com/baidubce/bce-sdk-go/services/bos"
	"github.com/baidubce/bce-sdk-go/services/bos/api"
	"github.com/grafana/dskit/flagext"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/weaveworks/common/instrument"
	"gopkg.in/fsnotify.v1"

	"github.com/grafana/loki/pkg/storage/chunk/client"
)

// NoSuchKeyErr The resource you requested does not exist.
// refer to: https://cloud.baidu.com/doc/BOS/s/Ajwvysfpl
//
//	https://intl.cloud.baidu.com/doc/BOS/s/Ajwvysfpl-en
const NoSuchKeyErr = "NoSuchKey"

const DefaultEndpoint = bos.DEFAULT_SERVICE_DOMAIN

const DefaultStsTokenRefreshPeriod = 5 * time.Minute

var bosRequestDuration = instrument.NewHistogramCollector(prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Namespace: "loki",
	Name:      "bos_request_duration_seconds",
	Help:      "Time spent doing BOS requests.",
	Buckets:   prometheus.ExponentialBuckets(0.005, 4, 6),
}, []string{"operation", "status_code"}))

func init() {
	bosRequestDuration.Register()
}

type BOSStorageConfig struct {
	BucketName      string         `yaml:"bucket_name"`
	Endpoint        string         `yaml:"endpoint"`
	AccessKeyID     string         `yaml:"access_key_id"`
	SecretAccessKey flagext.Secret `yaml:"secret_access_key"`

	// StsTokenPath Once this is enabled, AccessKeyID SecretAccessKey will be an invalid value
	StsTokenPath string `yaml:"sts_token_path,omitempty"`
	// StsTokenRefreshPeriod Time to refresh StsToken,If StsTokenPath is empty, this value is invalid
	// If StsTokenPath is file path, this value is invalid StsToken will be refreshed every time when the file is modified
	StsTokenRefreshPeriod time.Duration `yaml:"sts_token_refresh_period,omitempty"`

	PathPrefix string `yaml:"path_prefix"`
}

// RegisterFlags adds the flags required to config this to the given FlagSet
func (cfg *BOSStorageConfig) RegisterFlags(f *flag.FlagSet) {
	cfg.RegisterFlagsWithPrefix("", f)
}

// RegisterFlagsWithPrefix adds the flags required to config this to the given FlagSet
func (cfg *BOSStorageConfig) RegisterFlagsWithPrefix(prefix string, f *flag.FlagSet) {
	f.StringVar(&cfg.BucketName, prefix+"baidubce.bucket-name", "", "Name of BOS bucket.")
	f.StringVar(&cfg.Endpoint, prefix+"baidubce.endpoint", DefaultEndpoint, "BOS endpoint to connect to.")
	f.StringVar(&cfg.AccessKeyID, prefix+"baidubce.access-key-id", "", "Baidu Cloud Engine (BCE) Access Key ID.")
	f.Var(&cfg.SecretAccessKey, prefix+"baidubce.secret-access-key", "Baidu Cloud Engine (BCE) Secret Access Key.")
	f.StringVar(&cfg.StsTokenPath, prefix+"baidubce.sts-token-path", "", "Must be an HTTP address(must start with `http://` prefix) or file address where authentication can be obtained.")
	f.DurationVar(&cfg.StsTokenRefreshPeriod, prefix+"baidubce.sts-token-refresh-period", DefaultStsTokenRefreshPeriod, "Time to refresh STS token.")
	f.StringVar(&cfg.PathPrefix, prefix+"baidubce.path-prefix", "", "BOS write prefix")
}

type SessionToken struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	CreateTime      string `json:"create_time,omitempty"`
	Expiration      string `json:"expiration,omitempty"`
	UserID          string `json:"user_id,omitempty"`
}

func (b *BOSObjectStorage) startStsTokenReFresh() {
	if strings.HasPrefix(b.cfg.StsTokenPath, "http://") {
		timeTicker := time.NewTicker(b.cfg.StsTokenRefreshPeriod)
		for {
			err := b.refreshStsClient()
			if err != nil {
				continue
			}
			<-timeTicker.C
		}
	}
	// If StsTokenPath is file path
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op == fsnotify.Remove {
					watcher.Remove(event.Name)
					watcher.Add(b.cfg.StsTokenPath)
					err := b.refreshStsClient()
					if err != nil {
						continue
					}
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					err := b.refreshStsClient()
					if err != nil {
						continue
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)
			}
		}
	}()

	err = watcher.Add(b.cfg.StsTokenPath)
	if err != nil {
		log.Fatal(err)
	}

	<-done
}

func (b *BOSObjectStorage) refreshStsClient() error {
	return instrument.CollectedRequest(context.Background(), "BOS.refreshStsClient", bosRequestDuration, instrument.ErrorCode, func(ctx context.Context) error {
		sts, err := getSts(b.cfg.StsTokenPath)
		if err != nil {
			return err
		}
		stsBOSClient, err := buildStsBOSClient(sts, b.cfg.Endpoint)
		if err != nil {
			return err
		}
		b.client = stsBOSClient
		return nil
	})
}

func buildStsBOSClient(sts SessionToken, endPoint string) (*bos.Client, error) {
	bosClient, err := bos.NewClient(sts.AccessKeyID, sts.SecretAccessKey, endPoint)
	if err != nil {
		return nil, err
	}
	stsCredential, err := auth.NewSessionBceCredentials(
		sts.AccessKeyID,
		sts.SecretAccessKey,
		sts.SessionToken)
	if err != nil {
		return nil, err
	}
	bosClient.Config.Credentials = stsCredential
	return bosClient, nil
}

func getSts(stsTokenPath string) (SessionToken, error) {
	if strings.HasPrefix(stsTokenPath, "http://") {
		resp, err := http.Get(stsTokenPath)
		if err != nil {
			return SessionToken{}, err
		}
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		var sessionToken SessionToken
		err = json.Unmarshal(body, &sessionToken)
		if err != nil {
			return SessionToken{}, err
		}
		return sessionToken, nil
	}
	// If StsTokenPath is file path
	body, err := ioutil.ReadFile(stsTokenPath)
	if err != nil {
		return SessionToken{}, err
	}
	var sessionToken SessionToken
	err = json.Unmarshal(body, &sessionToken)
	if err != nil {
		return SessionToken{}, err
	}
	return sessionToken, nil
}

type BOSObjectStorage struct {
	cfg    *BOSStorageConfig
	client *bos.Client
}

func NewBOSObjectStorage(cfg *BOSStorageConfig) (*BOSObjectStorage, error) {
	if cfg.StsTokenPath == "" {
		clientConfig := bos.BosClientConfiguration{
			Ak:               cfg.AccessKeyID,
			Sk:               cfg.SecretAccessKey.String(),
			Endpoint:         cfg.Endpoint,
			RedirectDisabled: false,
		}
		bosClient, err := bos.NewClientWithConfig(&clientConfig)
		if err != nil {
			return nil, err
		}
		return &BOSObjectStorage{
			cfg:    cfg,
			client: bosClient,
		}, nil
	}
	bosObjectStorage := &BOSObjectStorage{
		cfg: cfg,
	}
	// when first created check the current Sts
	err := bosObjectStorage.refreshStsClient()
	if err != nil {
		return nil, err
	}
	// start a goroutine to refresh the Sts
	go bosObjectStorage.startStsTokenReFresh()
	return bosObjectStorage, nil
}

func (b *BOSObjectStorage) PutObject(ctx context.Context, objectKey string, object io.ReadSeeker) error {
	return instrument.CollectedRequest(ctx, "BOS.PutObject", bosRequestDuration, instrument.ErrorCode, func(ctx context.Context) error {
		body, err := bce.NewBodyFromSizedReader(object, -1)
		if err != nil {
			return err
		}
		objectKey := fmt.Sprintf("%s/%s", b.cfg.PathPrefix, objectKey)
		_, err = b.client.BasicPutObject(b.cfg.BucketName, objectKey, body)
		return err
	})
}

func (b *BOSObjectStorage) GetObject(ctx context.Context, objectKey string) (io.ReadCloser, int64, error) {
	var res *api.GetObjectResult
	err := instrument.CollectedRequest(ctx, "BOS.GetObject", bosRequestDuration, instrument.ErrorCode, func(ctx context.Context) error {
		var requestErr error
		objectKey := fmt.Sprintf("%s/%s", b.cfg.PathPrefix, objectKey)
		res, requestErr = b.client.BasicGetObject(b.cfg.BucketName, objectKey)
		return requestErr
	})
	if err != nil {
		return nil, 0, errors.Wrapf(err, "failed to get BOS object [ %s ]", objectKey)
	}
	size := res.ContentLength
	return res.Body, size, nil
}

func (b *BOSObjectStorage) List(ctx context.Context, prefix string, delimiter string) ([]client.StorageObject, []client.StorageCommonPrefix, error) {
	var storageObjects []client.StorageObject
	var commonPrefixes []client.StorageCommonPrefix

	err := instrument.CollectedRequest(ctx, "BOS.List", bosRequestDuration, instrument.ErrorCode, func(ctx context.Context) error {
		args := new(api.ListObjectsArgs)
		prefix := fmt.Sprintf("%s/%s", b.cfg.PathPrefix, prefix)
		args.Prefix = prefix
		args.Delimiter = delimiter
		for {
			listObjectResult, err := b.client.ListObjects(b.cfg.BucketName, args)
			if err != nil {
				return err
			}
			for _, content := range listObjectResult.Contents {
				// LastModified format 2021-10-28T06:55:01Z
				lastModifiedTime, err := time.Parse(time.RFC3339, content.LastModified)
				if err != nil {
					return err
				}
				storageObjects = append(storageObjects, client.StorageObject{
					Key:        content.Key,
					ModifiedAt: lastModifiedTime,
				})
			}
			for _, commonPrefix := range listObjectResult.CommonPrefixes {
				commonPrefixes = append(commonPrefixes, client.StorageCommonPrefix(commonPrefix.Prefix))
			}
			if !listObjectResult.IsTruncated {
				break
			}
			args.Prefix = listObjectResult.Prefix
			args.Marker = listObjectResult.NextMarker
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return storageObjects, commonPrefixes, nil
}

func (b *BOSObjectStorage) DeleteObject(ctx context.Context, objectKey string) error {
	return instrument.CollectedRequest(ctx, "BOS.DeleteObject", bosRequestDuration, instrument.ErrorCode, func(ctx context.Context) error {
		objectKey := fmt.Sprintf("%s/%s", b.cfg.PathPrefix, objectKey)
		err := b.client.DeleteObject(b.cfg.BucketName, objectKey)
		return err
	})
}

func (b *BOSObjectStorage) IsObjectNotFoundErr(err error) bool {
	switch realErr := errors.Cause(err).(type) {
	// Client exception indicates an exception encountered when the client attempts to send a request to the BOS and transmits data.
	case *bce.BceClientError:
		return false
	// When an exception occurs on the BOS server, the BOS server returns the corresponding error message to the user to locate the problem.
	// BceServiceError will return an error message string to contain the error code :
	// https://github.com/baidubce/bce-sdk-go/blob/1e5bfbecf07c6ed5d97a0090a9faee7d89466239/bce/error.go#L47-L53
	case *bce.BceServiceError:
		if realErr.Code == NoSuchKeyErr {
			return true
		}
	default:
		return false
	}
	return false
}

func (b *BOSObjectStorage) Stop() {}
