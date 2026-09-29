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
	"strconv"
	"strings"
	"testing"
	"time"

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
