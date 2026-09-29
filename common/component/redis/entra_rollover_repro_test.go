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
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/require"
)

const (
	reproToken1 = "repro-token-1" // test-only: synthetic token for the local RESP server.
	reproToken2 = "repro-token-2" // test-only: synthetic token for the local RESP server.
)

// TestEntraIDPoolRolloverRepro is a long-running integration test for the stale
// credential behavior. Run it in a disposable pod with
// REDIS_ENTRA_ROLLOVER_REPRO=1. It waits through the configured connection
// retirement window before it checks the pooled connections again.
func TestEntraIDPoolRolloverRepro(t *testing.T) {
	if os.Getenv("REDIS_ENTRA_ROLLOVER_REPRO") != "1" {
		t.Skip("set REDIS_ENTRA_ROLLOVER_REPRO=1 to run the long-lived pool repro")
	}

	for _, version := range []string{"v8", "v9"} {
		version := version
		t.Run(version, func(t *testing.T) {
			t.Parallel()
			runEntraIDPoolRolloverRepro(t, version)
		})
	}
}

type rolloverCredential struct {
	started time.Time
}

func (c *rolloverCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	token := reproToken1
	expiresOn := c.started.Add(5*time.Minute + 15*time.Second)
	if time.Since(c.started) >= 3*time.Minute {
		token = reproToken2
		expiresOn = c.started.Add(15 * time.Minute)
	}
	return azcore.AccessToken{Token: token, ExpiresOn: expiresOn}, nil
}

func runEntraIDPoolRolloverRepro(t *testing.T, version string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	credential := &rolloverCredential{started: time.Now()}
	var accepted atomic.Int32
	var warmupPings atomic.Int32
	var expiredCloses atomic.Int32
	var token2Auths atomic.Int32
	warmupDone := make(chan struct{})
	var closeWarmup sync.Once
	serverExpiry := credential.started.Add(5*time.Minute + 15*time.Second)

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepted.Add(1)
			go serveRolloverRESP(conn, serverExpiry, &warmupPings, warmupDone, &closeWarmup, &expiredCloses, &token2Auths)
		}
	}()

	settings := &Settings{
		Host:            listener.Addr().String(),
		PoolSize:        2,
		RedisMaxRetries: -1,
		DialTimeout:     Duration(5 * time.Second),
		ReadTimeout:     Duration(5 * time.Second),
		WriteTimeout:    Duration(5 * time.Second),
		UseEntraID:      true,
		entraIDUsername: "repro-user",
	}
	var tokenCredential azcore.TokenCredential = credential
	settings.entraIDTokenCredential = &tokenCredential

	var client RedisClient
	if version == "v8" {
		client, err = newV8Client(settings)
	} else {
		client, err = newV9Client(settings)
	}
	require.NoError(t, err)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	warmupResults := make(chan error, 2)
	for range 2 {
		go func() {
			_, pingErr := client.PingResult(ctx)
			warmupResults <- pingErr
		}()
	}
	for range 2 {
		require.NoError(t, <-warmupResults)
	}
	select {
	case <-warmupDone:
	case <-ctx.Done():
		t.Fatal("server did not observe two simultaneous pooled connections")
	}
	require.GreaterOrEqual(t, accepted.Load(), int32(2))

	if wait := time.Until(serverExpiry); wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal("context expired before the fake credential expired")
		}
	}

	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, pingErr := client.PingResult(ctx)
			results <- pingErr
		}()
	}
	result1, result2 := <-results, <-results
	t.Logf("version=%s accepted_connections=%d token2_authentications=%d expired_socket_closes=%d post_expiry_errors=[%v %v]", version, accepted.Load(), token2Auths.Load(), expiredCloses.Load(), result1, result2)
	require.NoError(t, result1, "pooled connection must roll over before its credential expires")
	require.NoError(t, result2, "pooled connection must roll over before its credential expires")
	require.GreaterOrEqual(t, token2Auths.Load(), int32(2), "both retired pooled connections must authenticate with the new token")
}

func serveRolloverRESP(conn net.Conn, expires time.Time, warmupPings *atomic.Int32, warmupDone chan struct{}, closeWarmup *sync.Once, expiredCloses, token2Auths *atomic.Int32) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	token := ""
	for {
		command, err := readRolloverRESPCommand(reader)
		if err != nil {
			return
		}
		switch strings.ToUpper(command[0]) {
		case "HELLO":
			_, _ = io.WriteString(conn, "-ERR unknown command 'HELLO'\r\n")
		case "AUTH":
			if len(command) == 3 {
				token = command[2]
			}
			if len(command) == 2 {
				token = command[1]
			}
			if token == reproToken2 {
				token2Auths.Add(1)
			}
			_, _ = io.WriteString(conn, "+OK\r\n")
		case "PING":
			if warmupPings.Add(1) <= 2 {
				if warmupPings.Load() == 2 {
					closeWarmup.Do(func() { close(warmupDone) })
				}
				<-warmupDone
			}
			if time.Now().After(expires) && token != reproToken2 {
				expiredCloses.Add(1)
				return
			}
			_, _ = io.WriteString(conn, "+PONG\r\n")
		default:
			_, _ = io.WriteString(conn, "+OK\r\n")
		}
	}
}

func readRolloverRESPCommand(reader *bufio.Reader) ([]string, error) {
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
