/*
Copyright 2021 The Dapr Authors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package redis

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/dapr/kit/config"
	kitlogger "github.com/dapr/kit/logger"
)

const (
	defaultRedisPort               = "6379"
	defaultRedisDialTimeout        = 5 * time.Second
	entraIDCredentialRefreshWindow = 5 * time.Minute
	entraIDMaxConnAge              = 4 * time.Minute
	entraIDConnExpirySafetyMargin  = 30 * time.Second
)

type Settings struct {
	// The Redis host
	Host string `mapstructure:"redisHost"`
	// The Redis port (optional, appended to Host if Host does not already contain a port)
	Port uint16 `mapstructure:"redisPort"`
	// The Redis password
	Password string `mapstructure:"redisPassword"`
	// The Redis username
	Username string `mapstructure:"redisUsername"`
	// The Redis Sentinel password
	SentinelPassword string `mapstructure:"sentinelPassword"`
	// The Redis Sentinel username
	SentinelUsername string `mapstructure:"sentinelUsername"`
	// Database to be selected after connecting to the server.
	DB int `mapstructure:"redisDB"`
	// The redis type node or cluster
	RedisType string `mapstructure:"redisType"`
	// Maximum number of retries before giving up.
	// A value of -1 (not 0) disables retries
	// Default is 3 retries
	RedisMaxRetries int `mapstructure:"redisMaxRetries"`
	// Minimum backoff between each retry.
	// Default is 8 milliseconds; -1 disables backoff.
	RedisMinRetryInterval Duration `mapstructure:"redisMinRetryInterval"`
	// Maximum backoff between each retry.
	// Default is 512 milliseconds; -1 disables backoff.
	RedisMaxRetryInterval Duration `mapstructure:"redisMaxRetryInterval"`
	// Dial timeout for establishing new connections.
	DialTimeout Duration `mapstructure:"dialTimeout"`
	// Timeout for socket reads. If reached, commands will fail
	// with a timeout instead of blocking. Use value -1 for no timeout and 0 for default.
	ReadTimeout Duration `mapstructure:"readTimeout"`
	// Timeout for socket writes. If reached, commands will fail
	WriteTimeout Duration `mapstructure:"writeTimeout"`
	// Maximum number of socket connections.
	PoolSize int `mapstructure:"poolSize"`
	// Minimum number of idle connections which is useful when establishing
	// new connection is slow.
	MinIdleConns int `mapstructure:"minIdleConns"`
	// Maximum connection age. go-redis expires aged connections lazily before reuse.
	MaxConnAge Duration `mapstructure:"maxConnAge"`
	// Amount of time client waits for connection if all connections
	// are busy before returning an error.
	// Default is ReadTimeout + 1 second.
	PoolTimeout Duration `mapstructure:"poolTimeout"`
	// Amount of time after which client closes idle connections.
	// Should be less than server's timeout.
	// Default is 5 minutes. -1 disables idle timeout check.
	IdleTimeout Duration `mapstructure:"idleTimeout"`
	// Frequency of idle checks made by idle connections reaper.
	// Default is 1 minute. -1 disables idle connections reaper,
	// but idle connections are still discarded by the client
	// if IdleTimeout is set.
	IdleCheckFrequency Duration `mapstructure:"idleCheckFrequency"`
	// The master name
	SentinelMasterName string `mapstructure:"sentinelMasterName"`
	// Use Redis Sentinel for automatic failover.
	Failover bool `mapstructure:"failover"`

	// A flag to enables TLS by setting InsecureSkipVerify to true
	EnableTLS bool `mapstructure:"enableTLS"`

	// Client certificate and key
	ClientCert string `mapstructure:"clientCert"`
	ClientKey  string `mapstructure:"clientKey"`

	// == state only properties ==
	TTLInSeconds *int   `mapstructure:"ttlInSeconds" mdonly:"state"`
	QueryIndexes string `mapstructure:"queryIndexes" mdonly:"state"`

	// == pubsub only properties ==
	// The consumer identifier
	ConsumerID string `mapstructure:"consumerID" mdonly:"pubsub"`
	// The interval between checking for pending messages to redelivery (0 disables redelivery)
	RedeliverInterval time.Duration `mapstructure:"-" mdonly:"pubsub"`
	// The amount time a message must be pending before attempting to redeliver it (0 disables redelivery)
	ProcessingTimeout time.Duration `mapstructure:"processingTimeout" mdonly:"pubsub"`
	// The size of the message queue for processing
	QueueDepth uint `mapstructure:"queueDepth" mdonly:"pubsub"`
	// The number of concurrent workers that are processing messages
	Concurrency uint `mapstructure:"concurrency" mdonly:"pubsub"`

	// The max len of stream
	MaxLenApprox int64 `mapstructure:"maxLenApprox" mdonly:"pubsub"`

	// The TTL of stream entries
	StreamTTL time.Duration `mapstructure:"streamTTL" mdonly:"pubsub"`

	// EntraID / AzureAD Authentication based on the shared code which essentially uses the DefaultAzureCredential
	// from the official Azure Identity SDK for Go
	UseEntraID bool `mapstructure:"useEntraID" mapstructurealiases:"useAzureAD"`

	// == Entra ID runtime state (populated by InitEntraIDCredential when UseEntraID is true; not configurable via metadata) ==

	// entraIDUsername is the OID parsed from the initial Entra access token's "oid" claim.
	// Used as the Redis ACL username by the per-new-connection AUTH callback.
	entraIDUsername string

	// entraIDTokenCredential is the Azure SDK credential used to acquire fresh Entra access
	// tokens on demand.
	entraIDTokenCredential *azcore.TokenCredential
	// The gate serializes credential calls and lets callers cancel while they wait.
	entraIDCredentialGateOnce sync.Once
	entraIDCredentialGate     chan struct{}
	entraIDLogger             *kitlogger.Logger
	entraIDLifecycleMu        sync.Mutex
	entraIDCurrentExpiry      int64
	entraIDPreviousExpiry     int64
	entraIDCurrentGeneration  uint64
	entraIDPreviousGeneration uint64
	entraIDCurrentAccepted    bool
	entraIDPreviousAccepted   bool
	entraIDCurrentAuthStats   entraIDAuthStats
	entraIDPreviousAuthStats  entraIDAuthStats
	entraIDAuthAttempt        uint64
}

type entraIDAuthStats struct {
	attempted    uint64
	acknowledged uint64
	failed       uint64
}

// EntraIDFetchAuthArgs returns the Redis ACL username and a freshly-acquired Entra access
// token suitable for use as the AUTH password. It must only be called when UseEntraID is
// true and after InitEntraIDCredential has succeeded; otherwise it returns an error.
//
// This is invoked from the OnConnect callback installed on the underlying go-redis client
// so that every new pool connection authenticates with a current token, rather than the
// stale snapshot Password that would otherwise be sent during initial AUTH.
func (s *Settings) EntraIDFetchAuthArgs(
	ctx context.Context,
) (username, password string, generation, attempt uint64, err error) {
	attempt = s.nextEntraIDAuthAttempt()
	if s.entraIDTokenCredential == nil {
		return "", "", 0, attempt, errors.New("redis client: EntraID credential not initialized")
	}
	gate := s.entraIDTokenGate()
	select {
	case gate <- struct{}{}:
		defer func() { <-gate }()
	case <-ctx.Done():
		if s.entraIDLogger != nil {
			(*s.entraIDLogger).Warnf(
				"event=redis_entra_token_acquisition outcome=failed phase=credential_wait auth_attempt=%d error_type=%T",
				attempt, ctx.Err(),
			)
		}
		return "", "", 0, attempt, fmt.Errorf("redis client: waiting for EntraID credential timed out: %w", ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		return "", "", 0, attempt, fmt.Errorf("redis client: EntraID authentication timed out before token acquisition: %w", err)
	}
	// Azure credentials are called synchronously. Their GetToken implementation must honor ctx.
	tok, err := (*s.entraIDTokenCredential).GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://redis.azure.com/.default"},
	})
	if err != nil {
		if s.entraIDLogger != nil {
			(*s.entraIDLogger).Warnf(
				"event=redis_entra_token_acquisition outcome=failed auth_attempt=%d error_type=%T",
				attempt, err,
			)
		}
		return "", "", 0, attempt, fmt.Errorf("failed to acquire EntraID token for redis AUTH: %w", err)
	}
	maxConnAge := s.effectiveMaxConnAge()
	if err := validateEntraIDTokenLifetime(tok.ExpiresOn, time.Now(), maxConnAge); err != nil {
		if s.entraIDLogger != nil {
			(*s.entraIDLogger).Warnf(
				"event=redis_entra_token_acquisition outcome=rejected auth_attempt=%d expires_at=%s remaining=%s max_conn_age=%s",
				attempt, tok.ExpiresOn.UTC().Format(time.RFC3339), time.Until(tok.ExpiresOn).Round(time.Second), maxConnAge,
			)
		}
		return "", "", 0, attempt, err
	}
	generation, accepted, previousStats := s.acceptEntraIDToken(tok.ExpiresOn)
	if accepted && s.entraIDLogger != nil {
		(*s.entraIDLogger).Infof(
			"event=redis_entra_token_acquisition outcome=accepted token_generation=%d expires_at=%s max_conn_age=%s prior_auth_attempts=%d prior_auth_acknowledgements=%d prior_auth_failures=%d",
			generation, tok.ExpiresOn.UTC().Format(time.RFC3339), maxConnAge,
			previousStats.attempted, previousStats.acknowledged, previousStats.failed,
		)
	}
	return s.entraIDUsername, tok.Token, generation, attempt, nil
}

func (s *Settings) entraIDAuthContext(ctx context.Context) (context.Context, context.CancelFunc) {
	// The callback uses this context for both token acquisition and the AUTH acknowledgment.
	return context.WithTimeout(ctx, s.effectiveDialTimeout())
}

func (s *Settings) effectiveDialTimeout() time.Duration {
	if timeout := time.Duration(s.DialTimeout); timeout > 0 {
		return timeout
	}
	return defaultRedisDialTimeout
}

func (s *Settings) entraIDTokenGate() chan struct{} {
	s.entraIDCredentialGateOnce.Do(func() {
		s.entraIDCredentialGate = make(chan struct{}, 1)
	})
	return s.entraIDCredentialGate
}

func (s *Settings) nextEntraIDAuthAttempt() uint64 {
	s.entraIDLifecycleMu.Lock()
	defer s.entraIDLifecycleMu.Unlock()
	s.entraIDAuthAttempt++
	return s.entraIDAuthAttempt
}

func (s *Settings) acceptEntraIDToken(expiresOn time.Time) (uint64, bool, entraIDAuthStats) {
	s.entraIDLifecycleMu.Lock()
	defer s.entraIDLifecycleMu.Unlock()

	expiryKey := expiresOn.UnixNano()
	if expiryKey != s.entraIDCurrentExpiry && expiryKey != s.entraIDPreviousExpiry {
		if s.entraIDCurrentGeneration == 0 {
			s.entraIDCurrentGeneration = 1
			s.entraIDCurrentExpiry = expiryKey
		} else {
			s.entraIDPreviousExpiry = s.entraIDCurrentExpiry
			s.entraIDPreviousGeneration = s.entraIDCurrentGeneration
			s.entraIDPreviousAuthStats = s.entraIDCurrentAuthStats
			s.entraIDPreviousAccepted = s.entraIDCurrentAccepted
			s.entraIDCurrentGeneration++
			s.entraIDCurrentExpiry = expiryKey
			s.entraIDCurrentAuthStats = entraIDAuthStats{}
			s.entraIDCurrentAccepted = false
		}
	}

	generation := s.entraIDCurrentGeneration
	accepted := &s.entraIDCurrentAccepted
	if expiryKey == s.entraIDPreviousExpiry {
		generation = s.entraIDPreviousGeneration
		accepted = &s.entraIDPreviousAccepted
	}
	stats := &s.entraIDCurrentAuthStats
	if generation != s.entraIDCurrentGeneration {
		stats = &s.entraIDPreviousAuthStats
	}
	if *accepted {
		stats.attempted++
		return generation, false, entraIDAuthStats{}
	}
	*accepted = true
	stats.attempted++
	return generation, true, s.entraIDPreviousAuthStats
}

func (s *Settings) recordEntraIDAuthResult(generation uint64, acknowledged bool) (uint64, bool) {
	s.entraIDLifecycleMu.Lock()
	defer s.entraIDLifecycleMu.Unlock()
	stats := &s.entraIDCurrentAuthStats
	if generation == s.entraIDPreviousGeneration {
		stats = &s.entraIDPreviousAuthStats
	} else if generation != s.entraIDCurrentGeneration {
		return 0, false
	}
	if acknowledged {
		stats.acknowledged++
	} else {
		stats.failed++
	}
	return stats.acknowledged, stats.acknowledged == 1
}

func clampEntraIDMaxConnAge(configured time.Duration) time.Duration {
	if configured <= 0 || configured > entraIDMaxConnAge {
		return entraIDMaxConnAge
	}
	return configured
}

func (s *Settings) effectiveMaxConnAge() time.Duration {
	configured := time.Duration(s.MaxConnAge)
	if s.UseEntraID {
		return clampEntraIDMaxConnAge(configured)
	}
	return configured
}

func validateEntraIDTokenLifetime(expiresOn, now time.Time, maxConnAge time.Duration) error {
	minimumLifetime := maxConnAge + entraIDConnExpirySafetyMargin
	if minimumLifetime >= entraIDCredentialRefreshWindow {
		return errors.New("redis client: EntraID maxConnAge exceeds the credential refresh window")
	}
	if !expiresOn.After(now.Add(minimumLifetime)) {
		return errors.New("redis client: EntraID token lifetime does not cover maxConnAge and safety margin")
	}
	return nil
}

func (s *Settings) Decode(in interface{}) error {
	if err := config.Decode(in, s); err != nil {
		return fmt.Errorf("decode failed. %w", err)
	}

	resolved, err := resolveHost(s.Host, s.Port)
	if err != nil {
		return err
	}
	s.Host = resolved

	return nil
}

// resolveHost ensures Host contains a port. If Host already includes a port
// (contains ":"), it is returned unchanged. Otherwise, the separate Port value
// is appended; when Port is empty the Redis default (6379) is used.
// For comma-separated host lists (cluster/sentinel), each entry is resolved
// individually.
// Returns an error if any address already contains a port that conflicts with
// a separately configured port value.
func resolveHost(host string, port uint16) (string, error) {
	if host == "" {
		return host, nil
	}

	// Comma-separated addresses (cluster or sentinel mode).
	if strings.Contains(host, ",") {
		parts := strings.Split(host, ",")
		addrs := make([]string, len(parts))
		for i, addr := range parts {
			resolved, err := resolveAddr(strings.TrimSpace(addr), port)
			if err != nil {
				return "", err
			}
			addrs[i] = resolved
		}
		return strings.Join(addrs, ","), nil
	}

	return resolveAddr(host, port)
}

// resolveAddr appends port to a single address when it does not already
// contain one. Returns an error if the address already contains a port that
// conflicts with the separately configured port value.
func resolveAddr(addr string, port uint16) (string, error) {
	if addr == "" {
		return addr, nil
	}

	portStr := strconv.FormatUint(uint64(port), 10)

	// Already has a port.
	if _, existingPort, err := net.SplitHostPort(addr); err == nil {
		if port != 0 && portStr != existingPort {
			return "", fmt.Errorf(
				"redis host %q already contains port %s, but redisPort is set to %s; "+
					"either remove the port from redisHost or remove the redisPort setting",
				addr, existingPort, portStr)
		}
		return addr, nil
	}

	if port == 0 {
		portStr = defaultRedisPort
	}
	return net.JoinHostPort(addr, portStr), nil
}

func (s *Settings) SetCertificate(fn func(cert *tls.Certificate)) error {
	if s.ClientCert == "" || s.ClientKey == "" {
		return nil
	}
	cert, err := tls.X509KeyPair([]byte(s.ClientCert), []byte(s.ClientKey))
	if err != nil {
		return err
	}
	fn(&cert)
	return nil
}

func (s *Settings) GetMinID(now time.Time) string {
	// If StreamTTL is not set, return empty string (no trimming)
	if s.StreamTTL == 0 {
		return ""
	}

	return fmt.Sprintf("%d-1", now.Add(-s.StreamTTL).UnixMilli())
}

type Duration time.Duration

func (r *Duration) DecodeString(value string) error {
	if val, err := strconv.Atoi(value); err == nil {
		if val < 0 {
			*r = Duration(val)

			return nil
		}
		*r = Duration(time.Duration(val) * time.Millisecond)

		return nil
	}

	// Convert it by parsing
	d, err := time.ParseDuration(value)
	if err != nil {
		return err
	}

	*r = Duration(d)

	return nil
}
