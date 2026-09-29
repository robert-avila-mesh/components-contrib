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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	kitlogger "github.com/dapr/kit/logger"
	v8 "github.com/go-redis/redis/v8"
	v9 "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestClampEntraIDMaxConnAge(t *testing.T) {
	tests := []struct {
		name       string
		configured time.Duration
		want       time.Duration
	}{
		{name: "unset", configured: 0, want: entraIDMaxConnAge},
		{name: "negative disables age", configured: -time.Second, want: entraIDMaxConnAge},
		{name: "long override is clamped", configured: time.Hour, want: entraIDMaxConnAge},
		{name: "short override is kept", configured: 30 * time.Second, want: 30 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, clampEntraIDMaxConnAge(tt.configured))
		})
	}
}

type deadlineCredential struct {
	calls       atomic.Int32
	slowFirst   bool
	failFirst   bool
	shortFirst  bool
	tokenExpiry time.Time
}

type blockingCredential struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (c *blockingCredential) GetToken(ctx context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if c.calls.Add(1) == 1 {
		close(c.started)
	}
	select {
	case <-c.release:
		return azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}, nil // test token, never sent to a real Redis server.
	case <-ctx.Done():
		return azcore.AccessToken{}, ctx.Err()
	}
}

func TestEntraIDCredentialGateWaitHonorsContext(t *testing.T) {
	credential := &blockingCredential{started: make(chan struct{}), release: make(chan struct{})}
	var tokenCredential azcore.TokenCredential = credential
	settings := &Settings{UseEntraID: true, entraIDUsername: "test-user", entraIDTokenCredential: &tokenCredential}

	firstResult := make(chan error, 1)
	go func() {
		_, _, _, _, err := settings.EntraIDFetchAuthArgs(context.Background())
		firstResult <- err
	}()
	defer func() {
		select {
		case <-credential.release:
		default:
			close(credential.release)
		}
	}()
	select {
	case <-credential.started:
	case <-time.After(time.Second):
		t.Fatal("credential request did not acquire the gate")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, _, _, _, err := settings.EntraIDFetchAuthArgs(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, int32(1), credential.calls.Load(), "the caller waiting for the credential gate must not enter the SDK")

	select {
	case <-credential.release:
	default:
		close(credential.release)
	}
	select {
	case err := <-firstResult:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("credential request did not finish after release")
	}
}

func (c *deadlineCredential) GetToken(ctx context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	call := c.calls.Add(1)
	if c.failFirst && call == 1 {
		return azcore.AccessToken{}, fmt.Errorf("synthetic credential failure")
	}
	if c.slowFirst && call == 1 {
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return azcore.AccessToken{}, ctx.Err()
		}
	}
	expiresOn := c.tokenExpiry
	if c.shortFirst && call == 1 {
		expiresOn = time.Now().Add(time.Second)
	}
	return azcore.AccessToken{Token: "test-token", ExpiresOn: expiresOn}, nil // test token, never sent to a real Redis server.
}

func TestEntraIDAuthTimeoutAndPoolRecovery(t *testing.T) {
	for _, version := range []string{"v8", "v9"} {
		for _, authStage := range []string{"credential timeout", "caller cancellation", "AUTH timeout", "credential error", "short token", "AUTH rejection"} {
			t.Run(version+"/"+authStage, func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				defer listener.Close()

				var authCommands atomic.Int32
				serverDone := make(chan struct{})
				go func() {
					defer close(serverDone)
					for {
						conn, acceptErr := listener.Accept()
						if acceptErr != nil {
							return
						}
						go func() {
							defer conn.Close()
							reader := bufio.NewReader(conn)
							for {
								command, readErr := readRESPCommand(reader)
								if readErr != nil {
									return
								}
								switch strings.ToUpper(command[0]) {
								case "HELLO":
									_, _ = io.WriteString(conn, "-ERR unknown command 'HELLO'\r\n")
								case "AUTH":
									if authCommands.Add(1) == 1 {
										if authStage == "AUTH timeout" {
											continue
										}
										if authStage == "AUTH rejection" {
											_, _ = io.WriteString(conn, "-WRONGPASS invalid credentials\r\n")
											continue
										}
									}
									_, _ = io.WriteString(conn, "+OK\r\n")
								case "PING":
									_, _ = io.WriteString(conn, "+PONG\r\n")
								default:
									_, _ = io.WriteString(conn, "+OK\r\n")
								}
							}
						}()
					}
				}()

				credential := &deadlineCredential{
					slowFirst:   authStage == "credential timeout" || authStage == "caller cancellation",
					failFirst:   authStage == "credential error",
					shortFirst:  authStage == "short token",
					tokenExpiry: time.Now().Add(time.Hour),
				}
				var logOutput bytes.Buffer
				logger := kitlogger.NewLogger("redis-test")
				logger.SetOutput(&logOutput)
				logger.SetOutputLevel(kitlogger.DebugLevel)
				var tokenCredential azcore.TokenCredential = credential
				dialTimeout := 100 * time.Millisecond
				if authStage == "caller cancellation" {
					dialTimeout = time.Second
				}
				settings := &Settings{
					Host: listener.Addr().String(), RedisMaxRetries: -1,
					DialTimeout: Duration(dialTimeout), UseEntraID: true,
					entraIDUsername: "test-user", entraIDTokenCredential: &tokenCredential,
					entraIDLogger: &logger,
				}
				var client RedisClient
				if version == "v8" {
					client, err = newV8Client(settings)
				} else {
					client, err = newV9Client(settings)
				}
				require.NoError(t, err)
				defer client.Close()

				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				firstCtx := ctx
				if authStage == "caller cancellation" {
					var firstCancel context.CancelFunc
					firstCtx, firstCancel = context.WithTimeout(ctx, 20*time.Millisecond)
					defer firstCancel()
				}
				err = execTestPipelinePing(client, firstCtx)
				require.Error(t, err, "the first connection authentication must fail")
				if authStage == "credential error" || authStage == "short token" {
					require.Zero(t, authCommands.Load(), "rejected credentials must fail before AUTH")
				}
				require.NoError(t, execTestPipelinePing(client, ctx), "a later connection must authenticate and return to the pool")
				require.GreaterOrEqual(t, credential.calls.Load(), int32(2))
				require.Contains(t, logOutput.String(), "outcome=accepted")
				require.Contains(t, logOutput.String(), "outcome=server_acknowledged")
				require.NotContains(t, logOutput.String(), "test-token")
				if authStage == "AUTH timeout" || authStage == "AUTH rejection" {
					require.GreaterOrEqual(t, authCommands.Load(), int32(2))
				}
				_ = listener.Close()
				<-serverDone
			})
		}
	}
}

func execTestPipelinePing(client RedisClient, ctx context.Context) error {
	switch client := client.(type) {
	case v8Client:
		pipeline := client.client.Pipeline()
		pipeline.Ping(ctx)
		_, err := pipeline.Exec(ctx)
		return err
	case v9Client:
		pipeline := client.client.Pipeline()
		pipeline.Ping(ctx)
		_, err := pipeline.Exec(ctx)
		return err
	default:
		return fmt.Errorf("unexpected Redis client type %T", client)
	}
}

func TestAcceptEntraIDTokenSnapshotsPreviousAuthStatsOnce(t *testing.T) {
	settings := &Settings{}
	firstExpiry := time.Now().Add(time.Hour)
	firstGeneration, accepted, _ := settings.acceptEntraIDToken(firstExpiry)
	require.True(t, accepted)
	settings.recordEntraIDAuthResult(firstGeneration, true)
	settings.recordEntraIDAuthResult(firstGeneration, false)

	newExpiry := firstExpiry.Add(time.Hour)
	var wg sync.WaitGroup
	results := make(chan struct {
		generation uint64
		accepted   bool
		stats      entraIDAuthStats
	}, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			generation, accepted, stats := settings.acceptEntraIDToken(newExpiry)
			results <- struct {
				generation uint64
				accepted   bool
				stats      entraIDAuthStats
			}{generation, accepted, stats}
		}()
	}
	wg.Wait()
	close(results)

	acceptedCount := 0
	for result := range results {
		require.Equal(t, firstGeneration+1, result.generation)
		if result.accepted {
			acceptedCount++
			require.Equal(t, entraIDAuthStats{attempted: 1, acknowledged: 1, failed: 1}, result.stats)
		}
	}
	require.Equal(t, 1, acceptedCount)
}

func TestEntraIDAcceptanceLogUsesPreviousGenerationStats(t *testing.T) {
	var output bytes.Buffer
	logger := kitlogger.NewLogger("redis-test")
	logger.SetOutput(&output)
	logger.SetOutputLevel(kitlogger.InfoLevel)
	credential := &deadlineCredential{tokenExpiry: time.Now().Add(2 * time.Hour)}
	var tokenCredential azcore.TokenCredential = credential
	settings := &Settings{
		UseEntraID: true, entraIDUsername: "test-user", entraIDTokenCredential: &tokenCredential,
		entraIDLogger: &logger,
	}
	firstExpiry := time.Now().Add(time.Hour)
	firstGeneration, accepted, _ := settings.acceptEntraIDToken(firstExpiry)
	require.True(t, accepted)
	settings.recordEntraIDAuthResult(firstGeneration, true)
	settings.recordEntraIDAuthResult(firstGeneration, false)

	_, _, generation, _, err := settings.EntraIDFetchAuthArgs(context.Background())
	require.NoError(t, err)
	require.Equal(t, firstGeneration+1, generation)
	message := output.String()
	require.Contains(t, message, "outcome=accepted")
	require.Contains(t, message, "prior_auth_attempts=1")
	require.Contains(t, message, "prior_auth_acknowledgements=1")
	require.Contains(t, message, "prior_auth_failures=1")
	require.NotContains(t, message, "test-token")
	require.NotContains(t, message, "server_acknowledged", "token acceptance must not claim Redis acknowledged AUTH")
}

func TestValidateEntraIDTokenLifetime(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	maxAge := time.Minute
	requiredLife := maxAge + entraIDConnExpirySafetyMargin

	tests := []struct {
		name      string
		expiresOn time.Time
		maxAge    time.Duration
		wantErr   bool
	}{
		{name: "token covers retirement and margin", expiresOn: now.Add(requiredLife + time.Second), maxAge: maxAge},
		{name: "token at margin boundary is rejected", expiresOn: now.Add(requiredLife), maxAge: maxAge, wantErr: true},
		{name: "cached token near expiry is rejected", expiresOn: now.Add(time.Minute), maxAge: maxAge, wantErr: true},
		{name: "age must fit credential refresh window", expiresOn: now.Add(time.Hour), maxAge: entraIDCredentialRefreshWindow, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEntraIDTokenLifetime(tt.expiresOn, now, tt.maxAge)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestAuthACLExecutesQueuedCommand(t *testing.T) {
	tests := []struct {
		name string
		auth func(context.Context, string, string, string) error
	}{
		{
			name: "v8",
			auth: func(ctx context.Context, address, username, token string) error {
				client := v8.NewClient(&v8.Options{Addr: address})
				defer client.Close()
				return (v8Client{client: client}).AuthACL(ctx, username, token)
			},
		},
		{
			name: "v9",
			auth: func(ctx context.Context, address, username, token string) error {
				client := v9.NewClient(&v9.Options{Addr: address, Protocol: 2})
				defer client.Close()
				return (v9Client{client: client}).AuthACL(ctx, username, token)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()

			commands := make(chan []string, 1)
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					command, readErr := readRESPCommand(reader)
					if readErr != nil {
						return
					}
					if strings.EqualFold(command[0], "HELLO") {
						_, _ = io.WriteString(conn, "-ERR unknown command 'HELLO'\r\n")
						continue
					}
					if strings.EqualFold(command[0], "AUTH") {
						commands <- command
					}
					_, _ = io.WriteString(conn, "+OK\r\n")
				}
			}()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			require.NoError(t, tt.auth(ctx, listener.Addr().String(), "test-user", "test-token"))

			select {
			case command := <-commands:
				require.Equal(t, "AUTH", strings.ToUpper(command[0]))
			case <-ctx.Done():
				t.Fatal("AUTH command was not sent")
			}
		})
	}
}

func readRESPCommand(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 || line[0] != '*' {
		return nil, fmt.Errorf("unexpected RESP array header")
	}
	count, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSuffix(line[1:], "\n"), "\r"))
	if err != nil {
		return nil, err
	}
	command := make([]string, count)
	for i := range count {
		bulkHeader, readErr := reader.ReadString('\n')
		if readErr != nil {
			return nil, readErr
		}
		if len(bulkHeader) < 3 || bulkHeader[0] != '$' {
			return nil, fmt.Errorf("unexpected RESP bulk header")
		}
		bulkLength, parseErr := strconv.Atoi(strings.TrimSuffix(strings.TrimSuffix(bulkHeader[1:], "\n"), "\r"))
		if parseErr != nil {
			return nil, parseErr
		}
		bulk := make([]byte, bulkLength+2)
		if _, readErr = io.ReadFull(reader, bulk); readErr != nil {
			return nil, readErr
		}
		command[i] = string(bulk[:bulkLength])
	}
	return command, nil
}
