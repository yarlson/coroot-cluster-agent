package aws

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"k8s.io/klog"
)

const (
	keyspacesPort               = "9142"
	keyspacesEndpointsTimeout   = 20 * time.Second
	keyspacesEndpointsInterval  = 5 * time.Minute
	keyspacesPeersQueryTimeout  = 5 * time.Second
	keyspacesPeersQueryParallel = 10
)

var errKeyspacesEndpoints = errors.New("keyspaces: failed to discover the endpoints")

type keyspacesPeersFunc func(ctx context.Context, host string) ([]string, error)

func (k *Keyspaces) discoverEndpoints(ctx context.Context, d *Discoverer, region string) {
	ctx, cancel := context.WithTimeout(ctx, keyspacesEndpointsTimeout)
	defer cancel()
	fqdns := []string{"cassandra." + region + ".amazonaws.com", "cassandra." + region + ".api.aws"}

	ips, complete, err := discoverKeyspacesIPs(ctx, fqdns[0], keyspacesPeers(d.awsCfg, region, fqdns[0]))
	k.lock.Lock()
	defer k.lock.Unlock()
	if err != nil {
		klog.Errorln("keyspaces: failed to discover the endpoints:", err)
		d.registerError(errKeyspacesEndpoints)
		if len(k.endpoints) > 0 && k.endpointsRegion == region {
			return
		}
	}
	if !complete && k.endpointsRegion == region {
		ips = append(ips, k.endpoints...)
	}
	k.endpoints = uniqSorted(slices.Concat(fqdns, ips))
}

func discoverKeyspacesIPs(ctx context.Context, fqdn string, peers keyspacesPeersFunc) ([]string, bool, error) {
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", fqdn)
	if err != nil {
		return nil, false, err
	}
	if !allPrivate(addrs) {
		return crawlKeyspacesPeers(ctx, addrs[0].String(), peers)
	}
	var res []string
	for _, a := range addrs {
		res = append(res, a.String())
	}
	return res, true, nil
}

func allPrivate(addrs []net.IP) bool {
	for _, a := range addrs {
		if !a.IsPrivate() {
			return false
		}
	}
	return len(addrs) > 0
}

// one hop is enough: every node lists all but 2-3 IPs of the regional pool, and the seed's peers list the rest
func crawlKeyspacesPeers(ctx context.Context, seed string, peers keyspacesPeersFunc) ([]string, bool, error) {
	first, err := peers(ctx, seed)
	if err != nil {
		return nil, false, fmt.Errorf("query peers of %s: %w", seed, err)
	}
	found := append([]string{seed}, first...)
	complete := true
	var lock sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, keyspacesPeersQueryParallel)
	for _, p := range first {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			complete = false
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res, err := peers(ctx, p)
			lock.Lock()
			defer lock.Unlock()
			if err != nil {
				klog.Warningln("keyspaces: failed to query peers of", p, err)
				complete = false
				return
			}
			found = append(found, res...)
		}()
	}
	wg.Wait()
	return uniqSorted(found), complete, nil
}

func uniqSorted(s []string) []string {
	res := slices.Clone(s)
	slices.Sort(res)
	return slices.Compact(res)
}

func keyspacesPeers(awsCfg aws.Config, region, serverName string) keyspacesPeersFunc {
	return func(ctx context.Context, host string) ([]string, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cluster := gocql.NewCluster(host)
		cluster.Port = 9142
		cluster.ProtoVersion = 4
		cluster.Consistency = gocql.LocalQuorum
		cluster.NumConns = 1
		cluster.Timeout = keyspacesPeersQueryTimeout
		cluster.ConnectTimeout = keyspacesPeersQueryTimeout
		cluster.DisableInitialHostLookup = true
		cluster.Events.DisableNodeStatusEvents = true
		cluster.Events.DisableTopologyEvents = true
		cluster.Events.DisableSchemaEvents = true
		cluster.Metadata.CacheMode = gocql.Disabled
		cluster.SslOpts = &gocql.SslOptions{Config: &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}, EnableHostVerification: true}
		cluster.Authenticator = keyspacesAuthenticator{region: region, credentials: awsCfg.Credentials}
		session, err := cluster.CreateSession()
		if err != nil {
			return nil, err
		}
		defer session.Close()
		ctx, cancel := context.WithTimeout(ctx, keyspacesPeersQueryTimeout)
		defer cancel()
		iter := session.Query("SELECT rpc_address FROM system.peers").IterContext(ctx)
		var res []string
		var ip net.IP
		for iter.Scan(&ip) {
			if ip != nil {
				res = append(res, ip.String())
			}
		}
		if err = iter.Close(); err != nil {
			return nil, err
		}
		return res, nil
	}
}

type keyspacesAuthenticator struct {
	region      string
	credentials aws.CredentialsProvider
}

func (a keyspacesAuthenticator) Challenge([]byte) ([]byte, gocql.Authenticator, error) {
	return []byte("SigV4\000\000"), keyspacesSigner(a), nil
}

func (a keyspacesAuthenticator) Success([]byte) error {
	return nil
}

type keyspacesSigner keyspacesAuthenticator

func (s keyspacesSigner) Challenge(req []byte) ([]byte, gocql.Authenticator, error) {
	_, nonce, ok := strings.Cut(string(req), "nonce=")
	if !ok {
		return nil, nil, errors.New("no nonce in the SigV4 challenge")
	}
	if s.credentials == nil {
		return nil, nil, errors.New("no AWS credentials provider configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), keyspacesPeersQueryTimeout)
	defer cancel()
	creds, err := s.credentials.Retrieve(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("retrieve AWS credentials: %w", err)
	}
	return []byte(signKeyspacesChallenge(s.region, nonce, creds, time.Now().UTC())), s, nil
}

func (s keyspacesSigner) Success([]byte) error {
	return nil
}

// the SigV4 handshake of Amazon Keyspaces: https://github.com/aws/aws-sigv4-auth-cassandra-gocql-driver-plugin
func signKeyspacesChallenge(region, nonce string, creds aws.Credentials, t time.Time) string {
	date := t.Format("20060102")
	timestamp := t.Format("2006-01-02T15:04:05.000Z")
	scope := date + "/" + region + "/cassandra/aws4_request"
	nonceHash := sha256.Sum256([]byte(nonce))
	query := []string{
		"X-Amz-Algorithm=AWS4-HMAC-SHA256",
		"X-Amz-Credential=" + creds.AccessKeyID + "%2F" + url.QueryEscape(scope),
		"X-Amz-Date=" + url.QueryEscape(timestamp),
		"X-Amz-Expires=900",
	}
	slices.Sort(query)
	canonicalRequest := "PUT\n/authenticate\n" + strings.Join(query, "&") + "\nhost:cassandra\n\nhost\n" + hex.EncodeToString(nonceHash[:])
	canonicalRequestHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := "AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + hex.EncodeToString(canonicalRequestHash[:])

	key := []byte("AWS4" + creds.SecretAccessKey)
	for _, v := range []string{date, region, "cassandra", "aws4_request"} {
		key = hmacSHA256(key, v)
	}
	res := "signature=" + hex.EncodeToString(hmacSHA256(key, stringToSign)) + ",access_key=" + creds.AccessKeyID + ",amzdate=" + timestamp
	if creds.SessionToken != "" {
		res += ",session_token=" + creds.SessionToken
	}
	return res
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
