package aws

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/keyspaces"
	kstypes "github.com/aws/aws-sdk-go-v2/service/keyspaces/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sigv4-auth-cassandra-gocql-driver-plugin/sigv4"
	"github.com/coroot/coroot-cluster-agent/common"
	"github.com/gocql/gocql"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog"
)

const (
	keyspacesPort             = "9142"
	keyspacesCWNamespace      = "AWS/Cassandra"
	keyspacesCWMaxBatchSize   = 500
	keyspacesPeerPollInterval = 5 * time.Minute
	keyspacesCWBaseInterval   = time.Minute
	keyspacesCWLatencyPeriod  = 5 * time.Minute
	keyspacesCWSizePeriod     = time.Hour
	keyspacesErrorWindow      = 5 * time.Minute
)

var (
	dKSInfo = common.Desc("aws_keyspaces_info", "Amazon Keyspaces account/region info",
		"account", "region",
	)
	dKSEndpointInfo = common.Desc("aws_keyspaces_endpoint_info", "Amazon Keyspaces endpoint address",
		"addr", "port", "kind",
	)
	dKSTableInfo = common.Desc("aws_keyspaces_table_info", "Amazon Keyspaces table info",
		"keyspace", "table", "capacity_mode", "status",
	)
	dKSProvisionedCap = common.Desc("aws_keyspaces_provisioned_capacity_units", "Amazon Keyspaces provisioned capacity units",
		"keyspace", "table", "type",
	)
	dKSWarmThroughput = common.Desc("aws_keyspaces_warm_throughput_units", "Amazon Keyspaces warm throughput units",
		"keyspace", "table", "type",
	)
	dKSConsumedCap = common.Desc("aws_keyspaces_consumed_capacity_units_per_second", "Amazon Keyspaces consumed capacity units per second",
		"keyspace", "table", "type",
	)
	dKSTableSize = common.Desc("aws_keyspaces_table_size_bytes", "Amazon Keyspaces billable table size in bytes",
		"keyspace", "table",
	)
	dKSRequestsWindow = common.Desc("aws_keyspaces_requests_window", "Amazon Keyspaces successful requests in the trailing 5m window",
		"keyspace", "table", "operation",
	)
	dKSRequestLatency = common.Desc("aws_keyspaces_request_latency_seconds", "Amazon Keyspaces server-side request latency in seconds",
		"keyspace", "table", "operation", "stat",
	)
	dKSThrottleEvents = common.Desc("aws_keyspaces_throttle_events", "Amazon Keyspaces throttle events in the trailing 5m window",
		"keyspace", "table", "type",
	)
	dKSPartitionLimitEvents = common.Desc("aws_keyspaces_partition_limit_events", "Amazon Keyspaces hot partition limit events in the trailing 5m window",
		"keyspace", "table",
	)
	dKSUserErrors = common.Desc("aws_keyspaces_user_errors", "Amazon Keyspaces per-table user errors in the trailing 5m window",
		"keyspace", "table",
	)
	dKSAccountUserErrors = common.Desc("aws_keyspaces_account_user_errors", "Amazon Keyspaces account-level user errors in the trailing 5m window",
		"operation",
	)
	dKSSystemErrors = common.Desc("aws_keyspaces_system_errors", "Amazon Keyspaces system errors in the trailing 5m window",
		"keyspace", "table",
	)
	dKSPerConnLimitEvents = common.Desc("aws_keyspaces_per_connection_limit_events", "Amazon Keyspaces per-connection rate limit events in the trailing 5m window")
)

type keyspacesTableKey struct {
	Keyspace string
	Table    string
}

type keyspacesTableMeta struct {
	Keyspace          string
	Table             string
	CapacityMode      string
	Status            string
	ProvisionedRead   float64
	ProvisionedWrite  float64
	WarmRead          float64
	WarmWrite         float64
	AutoScaleReadOff  bool
	AutoScaleWriteOff bool
}

type keyspacesEndpoint struct {
	Addr string
	Port string
	Kind string // public | vpc | peer
}

type keyspacesOpKey struct {
	Keyspace  string
	Table     string
	Operation string
}

type keyspacesCWSnapshot struct {
	consumedReadPerSec  map[keyspacesTableKey]float64
	consumedWritePerSec map[keyspacesTableKey]float64
	tableSizeBytes      map[keyspacesTableKey]float64
	requestsWindow      map[keyspacesOpKey]float64
	latencyP99Sec       map[keyspacesOpKey]float64
	readThrottles       map[keyspacesTableKey]float64
	writeThrottles      map[keyspacesTableKey]float64
	partitionLimits     map[keyspacesTableKey]float64
	tableUserErrors     map[keyspacesTableKey]float64
	tableSystemErrors   map[keyspacesTableKey]float64
	accountUserErrors   map[string]float64
	perConnLimits       float64
	hasPerConnLimit     bool
	hasAnyCWData        bool
}

func newKeyspacesCWSnapshot() *keyspacesCWSnapshot {
	return &keyspacesCWSnapshot{
		consumedReadPerSec:  map[keyspacesTableKey]float64{},
		consumedWritePerSec: map[keyspacesTableKey]float64{},
		tableSizeBytes:      map[keyspacesTableKey]float64{},
		requestsWindow:      map[keyspacesOpKey]float64{},
		latencyP99Sec:       map[keyspacesOpKey]float64{},
		readThrottles:       map[keyspacesTableKey]float64{},
		writeThrottles:      map[keyspacesTableKey]float64{},
		partitionLimits:     map[keyspacesTableKey]float64{},
		tableUserErrors:     map[keyspacesTableKey]float64{},
		tableSystemErrors:   map[keyspacesTableKey]float64{},
		accountUserErrors:   map[string]float64{},
	}
}

type KeyspacesCollector struct {
	discoverer *Discoverer
	accountID  string
	region     string

	mu        sync.RWMutex
	tables    map[keyspacesTableKey]keyspacesTableMeta
	endpoints []keyspacesEndpoint
	cw        *keyspacesCWSnapshot

	lastLatencyPoll time.Time
	lastSizePoll    time.Time
	knownOps        map[keyspacesOpKey]bool

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func NewKeyspacesCollector(d *Discoverer, accountID, region string, tables map[keyspacesTableKey]keyspacesTableMeta) *KeyspacesCollector {
	c := &KeyspacesCollector{
		discoverer: d,
		accountID:  accountID,
		region:     region,
		tables:     cloneTableMeta(tables),
		endpoints:  defaultKeyspacesEndpoints(region),
		cw:         newKeyspacesCWSnapshot(),
		knownOps:   map[keyspacesOpKey]bool{},
		stop:       make(chan struct{}),
	}

	c.wg.Add(2)
	go c.peerLoop()
	go c.cwLoop()
	return c
}

func (c *KeyspacesCollector) UpdateTables(tables map[keyspacesTableKey]keyspacesTableMeta) {
	c.mu.Lock()
	c.tables = cloneTableMeta(tables)
	c.mu.Unlock()
}

func (c *KeyspacesCollector) Stop() {
	c.stopOnce.Do(func() {
		close(c.stop)
	})
	c.wg.Wait()
}

func (c *KeyspacesCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("aws_keyspaces_collector", "", nil, nil)
}

func (c *KeyspacesCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ch <- common.Gauge(dKSInfo, 1, c.accountID, c.region)

	for _, ep := range c.endpoints {
		ch <- common.Gauge(dKSEndpointInfo, 1, ep.Addr, ep.Port, ep.Kind)
	}

	for tk, tm := range c.tables {
		ch <- common.Gauge(dKSTableInfo, 1, tm.Keyspace, tm.Table, tm.CapacityMode, tm.Status)
		if tm.CapacityMode == string(kstypes.ThroughputModeProvisioned) {
			ch <- common.Gauge(dKSProvisionedCap, tm.ProvisionedRead, tm.Keyspace, tm.Table, "read")
			ch <- common.Gauge(dKSProvisionedCap, tm.ProvisionedWrite, tm.Keyspace, tm.Table, "write")
		}
		if tm.WarmRead > 0 {
			ch <- common.Gauge(dKSWarmThroughput, tm.WarmRead, tm.Keyspace, tm.Table, "read")
		}
		if tm.WarmWrite > 0 {
			ch <- common.Gauge(dKSWarmThroughput, tm.WarmWrite, tm.Keyspace, tm.Table, "write")
		}

		if v, ok := c.cw.consumedReadPerSec[tk]; ok {
			ch <- common.Gauge(dKSConsumedCap, v, tm.Keyspace, tm.Table, "read")
		}
		if v, ok := c.cw.consumedWritePerSec[tk]; ok {
			ch <- common.Gauge(dKSConsumedCap, v, tm.Keyspace, tm.Table, "write")
		}
		if v, ok := c.cw.tableSizeBytes[tk]; ok {
			ch <- common.Gauge(dKSTableSize, v, tm.Keyspace, tm.Table)
		}
		if v, ok := c.cw.readThrottles[tk]; ok {
			ch <- common.Gauge(dKSThrottleEvents, v, tm.Keyspace, tm.Table, "read")
		}
		if v, ok := c.cw.writeThrottles[tk]; ok {
			ch <- common.Gauge(dKSThrottleEvents, v, tm.Keyspace, tm.Table, "write")
		}
		if v, ok := c.cw.partitionLimits[tk]; ok {
			ch <- common.Gauge(dKSPartitionLimitEvents, v, tm.Keyspace, tm.Table)
		}
		if v, ok := c.cw.tableUserErrors[tk]; ok {
			ch <- common.Gauge(dKSUserErrors, v, tm.Keyspace, tm.Table)
		}
		if v, ok := c.cw.tableSystemErrors[tk]; ok {
			ch <- common.Gauge(dKSSystemErrors, v, tm.Keyspace, tm.Table)
		}
	}

	for okKey, v := range c.cw.requestsWindow {
		if _, exists := c.tables[keyspacesTableKey{Keyspace: okKey.Keyspace, Table: okKey.Table}]; exists {
			ch <- common.Gauge(dKSRequestsWindow, v, okKey.Keyspace, okKey.Table, okKey.Operation)
		}
	}
	for okKey, v := range c.cw.latencyP99Sec {
		if _, exists := c.tables[keyspacesTableKey{Keyspace: okKey.Keyspace, Table: okKey.Table}]; exists {
			ch <- common.Gauge(dKSRequestLatency, v, okKey.Keyspace, okKey.Table, okKey.Operation, "p99")
		}
	}
	for op, v := range c.cw.accountUserErrors {
		ch <- common.Gauge(dKSAccountUserErrors, v, op)
	}
	if c.cw.hasPerConnLimit {
		ch <- common.Gauge(dKSPerConnLimitEvents, c.cw.perConnLimits)
	}
}

func defaultKeyspacesEndpoints(region string) []keyspacesEndpoint {
	return []keyspacesEndpoint{
		{Addr: fmt.Sprintf("cassandra.%s.amazonaws.com", region), Port: keyspacesPort, Kind: "public"},
		{Addr: fmt.Sprintf("cassandra.%s.api.aws", region), Port: keyspacesPort, Kind: "public"},
	}
}

func isSystemKeyspace(name string) bool {
	switch name {
	case "system", "system_schema", "system_schema_mcs", "system_multiregion_info", "system_traces":
		return true
	}
	return strings.HasPrefix(name, "system_")
}

func isKeyspacesDMLOp(op string) bool {
	switch op {
	case "SELECT", "INSERT", "UPDATE", "DELETE", "BATCH":
		return true
	}
	return false
}

func cloneTableMeta(src map[keyspacesTableKey]keyspacesTableMeta) map[keyspacesTableKey]keyspacesTableMeta {
	dst := make(map[keyspacesTableKey]keyspacesTableMeta, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (c *KeyspacesCollector) peerLoop() {
	defer c.wg.Done()
	c.pollPeers()
	t := time.NewTicker(keyspacesPeerPollInterval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.pollPeers()
		}
	}
}

func (c *KeyspacesCollector) pollPeers() {
	host := fmt.Sprintf("cassandra.%s.amazonaws.com", c.region)
	ctx, cancel := context.WithTimeout(c.discoverer.ctx, 30*time.Second)
	defer cancel()

	dnsIPs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		klog.Warningf("keyspaces: DNS lookup for %s failed: %v", host, err)
		return
	}

	eps := crawlKeyspacesEndpoints(ctx, c.region, dnsIPs, func(ctx context.Context, ip string) ([]string, error) {
		return queryKeyspacesSystemPeers(ctx, c.discoverer.awsCfg, c.region, host, ip)
	})

	c.mu.Lock()
	c.endpoints = eps
	c.mu.Unlock()
	klog.Infof("keyspaces (%s/%s): discovered %d endpoints", c.accountID, c.region, len(eps))
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// crawlKeyspacesEndpoints builds the full set of reachable Keyspaces endpoints.
// For private VPC endpoints, DNS already returns every ENI IP so no CQL peer crawl is needed.
// For public endpoints, it performs a 1-hop system.peers crawl: query one DNS seed IP, then query
// each returned peer IP and take the union (deterministically recovering all 12/12 pool IPs even behind caching DNS).
func crawlKeyspacesEndpoints(
	ctx context.Context,
	region string,
	dnsIPs []string,
	queryPeers func(ctx context.Context, ip string) ([]string, error),
) []keyspacesEndpoint {
	eps := defaultKeyspacesEndpoints(region)
	seen := map[string]bool{}
	for _, ep := range eps {
		seen[ep.Addr] = true
	}

	var publicSeeds []string
	var vpcIPs []string
	for _, ip := range dnsIPs {
		if net.ParseIP(ip) == nil {
			continue
		}
		if isPrivateIP(ip) {
			vpcIPs = append(vpcIPs, ip)
		} else {
			publicSeeds = append(publicSeeds, ip)
		}
	}

	// VPC Interface Endpoint: private DNS returns every ENI IP directly; no gocql needed.
	if len(vpcIPs) > 0 {
		sort.Strings(vpcIPs)
		for _, ip := range vpcIPs {
			if !seen[ip] {
				seen[ip] = true
				eps = append(eps, keyspacesEndpoint{Addr: ip, Port: keyspacesPort, Kind: "vpc"})
			}
		}
		return eps
	}

	if len(publicSeeds) == 0 {
		return eps
	}

	discovered := map[string]bool{}
	for _, ip := range publicSeeds {
		discovered[ip] = true
	}

	if queryPeers != nil {
		// Hop 0: query one seed IP from DNS
		seed := publicSeeds[0]
		hop1, err := queryPeers(ctx, seed)
		if err != nil {
			klog.Warningf("keyspaces: system.peers seed query on %s failed: %v", seed, err)
		} else {
			var toQuery []string
			for _, p := range hop1 {
				if net.ParseIP(p) == nil {
					continue
				}
				if !discovered[p] {
					discovered[p] = true
				}
				if p != seed {
					toQuery = append(toQuery, p)
				}
			}
			// Hop 1: query each peer returned by the seed in parallel to get the complete union
			var wg sync.WaitGroup
			var mu sync.Mutex
			sem := make(chan struct{}, 5)
			for _, peerIP := range toQuery {
				wg.Add(1)
				go func(target string) {
					defer wg.Done()
					select {
					case sem <- struct{}{}:
						defer func() { <-sem }()
					case <-ctx.Done():
						return
					}
					peers, err := queryPeers(ctx, target)
					if err != nil {
						klog.V(2).Infof("keyspaces: hop-1 system.peers query on %s failed: %v", target, err)
						return
					}
					mu.Lock()
					for _, p := range peers {
						if net.ParseIP(p) != nil {
							discovered[p] = true
						}
					}
					mu.Unlock()
				}(peerIP)
			}
			wg.Wait()
		}
	}

	ips := make([]string, 0, len(discovered))
	for ip := range discovered {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		if !seen[ip] {
			seen[ip] = true
			eps = append(eps, keyspacesEndpoint{Addr: ip, Port: keyspacesPort, Kind: "peer"})
		}
	}
	return eps
}

func queryKeyspacesSystemPeers(ctx context.Context, awsCfg aws.Config, region, serverName, ip string) ([]string, error) {
	creds, err := awsCfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	auth := sigv4.NewAwsAuthenticator()
	auth.Region = region
	auth.AccessKeyId = creds.AccessKeyID
	auth.SecretAccessKey = creds.SecretAccessKey
	auth.SessionToken = creds.SessionToken

	cluster := gocql.NewCluster(ip)
	cluster.Port = 9142
	cluster.Consistency = gocql.LocalQuorum
	cluster.Authenticator = &auth
	cluster.SslOpts = &gocql.SslOptions{
		Config: &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		},
	}
	cluster.DisableInitialHostLookup = true
	cluster.IgnorePeerAddr = true
	cluster.NumConns = 1
	cluster.Timeout = 5 * time.Second
	cluster.ConnectTimeout = 5 * time.Second
	cluster.RetryPolicy = &gocql.SimpleRetryPolicy{NumRetries: 0}

	session, err := cluster.CreateSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	var peers []string
	iter := session.Query("SELECT peer, rpc_address FROM system.peers").WithContext(ctx).Iter()
	var peer, rpc string
	for iter.Scan(&peer, &rpc) {
		addr := rpc
		if addr == "" || addr == "0.0.0.0" {
			addr = peer
		}
		if net.ParseIP(addr) != nil {
			peers = append(peers, addr)
		}
	}
	if err := iter.Close(); err != nil {
		return nil, err
	}
	return peers, nil
}

// --- Static Tiered CloudWatch Polling ---

type cwQueryMeta struct {
	id         string
	metricName string
	stat       string
	keyspace   string
	table      string
	operation  string
	periodSec  int32
	isRolling  bool // sum trailing 5m window vs latest point
}

type cwActiveSeries struct {
	latencyOps         []keyspacesOpKey
	readThrottles      []keyspacesOpKey
	writeThrottles     []keyspacesOpKey
	partitionLimits    []keyspacesOpKey
	tableUserErrors    []keyspacesOpKey
	tableSystemErrors  []keyspacesOpKey
	accountUserErrors  []string // operation: EXECUTE, PREPARE
	hasPerConnLimit    bool
}

func (c *KeyspacesCollector) cwLoop() {
	defer c.wg.Done()
	c.pollCloudWatch(time.Now().UTC())
	t := time.NewTicker(keyspacesCWBaseInterval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case now := <-t.C:
			c.pollCloudWatch(now.UTC())
		}
	}
}

func (c *KeyspacesCollector) pollCloudWatch(now time.Time) {
	c.mu.RLock()
	tables := cloneTableMeta(c.tables)
	prev := c.cw
	c.mu.RUnlock()

	if len(tables) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(c.discoverer.ctx, 45*time.Second)
	defer cancel()

	cwClient := c.discoverer.cloudwatchClient
	if cwClient == nil {
		return
	}

	active, err := listActiveKeyspacesMetrics(ctx, cwClient, tables)
	if err != nil {
		klog.Errorf("keyspaces (%s/%s): ListMetrics failed: %v", c.accountID, c.region, err)
		c.discoverer.registerError(err)
		return
	}

	pollLatency := c.lastLatencyPoll.IsZero() || now.Sub(c.lastLatencyPoll) >= keyspacesCWLatencyPeriod
	// Also poll latency immediately if a newly active operation appeared in ListMetrics
	for _, op := range active.latencyOps {
		if !c.knownOps[op] {
			pollLatency = true
			c.knownOps[op] = true
		}
	}
	pollSize := c.lastSizePoll.IsZero() || now.Sub(c.lastSizePoll) >= keyspacesCWSizePeriod

	queries, metas := buildKeyspacesCWQueries(tables, active, pollLatency, pollSize)
	if len(queries) == 0 {
		return
	}

	// Query window: 15m covers 5m latency + 2m idle heartbeats + CW ingestion lag; 3h when polling hourly table size.
	startTime := now.Add(-15 * time.Minute)
	if pollSize {
		startTime = now.Add(-3 * time.Hour)
	}

	results, err := executeKeyspacesCWBatches(ctx, cwClient, queries, startTime, now)
	if err != nil {
		klog.Errorf("keyspaces (%s/%s): GetMetricData failed: %v", c.accountID, c.region, err)
		c.discoverer.registerError(err)
		return
	}

	next := applyKeyspacesCWResults(prev, tables, metas, results, now, pollLatency, pollSize)

	if pollLatency {
		c.lastLatencyPoll = now
	}
	if pollSize {
		c.lastSizePoll = now
	}

	c.mu.Lock()
	c.cw = next
	c.mu.Unlock()
}

func listActiveKeyspacesMetrics(ctx context.Context, client *cloudwatch.Client, tables map[keyspacesTableKey]keyspacesTableMeta) (cwActiveSeries, error) {
	var res cwActiveSeries
	seenLatency := map[keyspacesOpKey]bool{}
	seenReadThr := map[keyspacesOpKey]bool{}
	seenWriteThr := map[keyspacesOpKey]bool{}
	seenPartLim := map[keyspacesOpKey]bool{}
	seenTableUserErr := map[keyspacesOpKey]bool{}
	seenTableSysErr := map[keyspacesOpKey]bool{}
	seenAcctUserErr := map[string]bool{}

	paginator := cloudwatch.NewListMetricsPaginator(client, &cloudwatch.ListMetricsInput{
		Namespace:      aws.String(keyspacesCWNamespace),
		RecentlyActive: cwtypes.RecentlyActivePt3h,
	})
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return res, err
		}
		for _, m := range out.Metrics {
			name := aws.ToString(m.MetricName)
			var ks, tbl, op string
			for _, dim := range m.Dimensions {
				switch aws.ToString(dim.Name) {
				case "Keyspace":
					ks = aws.ToString(dim.Value)
				case "TableName":
					tbl = aws.ToString(dim.Value)
				case "Operation":
					op = aws.ToString(dim.Value)
				}
			}

			// Account-level metrics (no Keyspace/TableName dimensions)
			if ks == "" && tbl == "" {
				switch name {
				case "PerConnectionRequestRateExceeded":
					if op == "EXECUTE" || op == "" {
						res.hasPerConnLimit = true
					}
				case "UserErrors":
					if (op == "EXECUTE" || op == "PREPARE") && !seenAcctUserErr[op] {
						seenAcctUserErr[op] = true
						res.accountUserErrors = append(res.accountUserErrors, op)
					}
				}
				continue
			}

			if _, ok := tables[keyspacesTableKey{Keyspace: ks, Table: tbl}]; !ok {
				continue
			}

			opKey := keyspacesOpKey{Keyspace: ks, Table: tbl, Operation: op}
			switch name {
			case "SuccessfulRequestLatency":
				// Only poll DML ops (exclude account-level EXECUTE and one-time DDL like CREATE_TABLE).
				if isKeyspacesDMLOp(op) && !seenLatency[opKey] {
					seenLatency[opKey] = true
					res.latencyOps = append(res.latencyOps, opKey)
				}
			case "ReadThrottleEvents":
				if !seenReadThr[opKey] {
					seenReadThr[opKey] = true
					res.readThrottles = append(res.readThrottles, opKey)
				}
			case "WriteThrottleEvents":
				if !seenWriteThr[opKey] {
					seenWriteThr[opKey] = true
					res.writeThrottles = append(res.writeThrottles, opKey)
				}
			case "StoragePartitionThroughputCapacityExceeded":
				if !seenPartLim[opKey] {
					seenPartLim[opKey] = true
					res.partitionLimits = append(res.partitionLimits, opKey)
				}
			case "UserErrors":
				if !seenTableUserErr[opKey] {
					seenTableUserErr[opKey] = true
					res.tableUserErrors = append(res.tableUserErrors, opKey)
				}
			case "SystemErrors":
				if !seenTableSysErr[opKey] {
					seenTableSysErr[opKey] = true
					res.tableSystemErrors = append(res.tableSystemErrors, opKey)
				}
			}
		}
	}
	return res, nil
}

func cwDims(ks, tbl, op string) []cwtypes.Dimension {
	var dims []cwtypes.Dimension
	if ks != "" {
		dims = append(dims, cwtypes.Dimension{Name: aws.String("Keyspace"), Value: aws.String(ks)})
	}
	if tbl != "" {
		dims = append(dims, cwtypes.Dimension{Name: aws.String("TableName"), Value: aws.String(tbl)})
	}
	if op != "" {
		dims = append(dims, cwtypes.Dimension{Name: aws.String("Operation"), Value: aws.String(op)})
	}
	return dims
}

func buildKeyspacesCWQueries(
	tables map[keyspacesTableKey]keyspacesTableMeta,
	active cwActiveSeries,
	pollLatency bool,
	pollSize bool,
) ([]cwtypes.MetricDataQuery, map[string]cwQueryMeta) {
	var queries []cwtypes.MetricDataQuery
	metas := map[string]cwQueryMeta{}
	seq := 0

	add := func(metricName, stat, ks, tbl, op string, periodSec int32, isRolling bool) {
		seq++
		id := "q" + strconv.Itoa(seq)
		queries = append(queries, cwtypes.MetricDataQuery{
			Id: aws.String(id),
			MetricStat: &cwtypes.MetricStat{
				Metric: &cwtypes.Metric{
					Namespace:  aws.String(keyspacesCWNamespace),
					MetricName: aws.String(metricName),
					Dimensions: cwDims(ks, tbl, op),
				},
				Period: aws.Int32(periodSec),
				Stat:   aws.String(stat),
			},
			ReturnData: aws.Bool(true),
		})
		metas[id] = cwQueryMeta{
			id:         id,
			metricName: metricName,
			stat:       stat,
			keyspace:   ks,
			table:      tbl,
			operation:  op,
			periodSec:  periodSec,
			isRolling:  isRolling,
		}
	}

	// Deterministic table ordering for stable batching and tests.
	tableKeys := make([]keyspacesTableKey, 0, len(tables))
	for tk := range tables {
		tableKeys = append(tableKeys, tk)
	}
	sort.Slice(tableKeys, func(i, j int) bool {
		if tableKeys[i].Keyspace != tableKeys[j].Keyspace {
			return tableKeys[i].Keyspace < tableKeys[j].Keyspace
		}
		return tableKeys[i].Table < tableKeys[j].Table
	})

	// Tier 1 (every 1m): ConsumedRead/WriteCapacityUnits (Sum)
	for _, tk := range tableKeys {
		add("ConsumedReadCapacityUnits", "Sum", tk.Keyspace, tk.Table, "", 60, false)
		add("ConsumedWriteCapacityUnits", "Sum", tk.Keyspace, tk.Table, "", 60, false)
	}

	// Tier 2 (every 5m, active ops only): SuccessfulRequestLatency (p99 + SampleCount)
	if pollLatency {
		for _, op := range active.latencyOps {
			add("SuccessfulRequestLatency", "p99", op.Keyspace, op.Table, op.Operation, 300, false)
			add("SuccessfulRequestLatency", "SampleCount", op.Keyspace, op.Table, op.Operation, 300, false)
		}
	}

	// Tier 3 (every 60m): TableSizeBytes (Average)
	if pollSize {
		for _, tk := range tableKeys {
			add("TableSizeBytes", "Average", tk.Keyspace, tk.Table, "", 3600, false)
		}
	}

	// On-demand (every 1m ONLY when ListMetrics reports active series): errors & throttles
	for _, op := range active.readThrottles {
		add("ReadThrottleEvents", "Sum", op.Keyspace, op.Table, op.Operation, 60, true)
	}
	for _, op := range active.writeThrottles {
		add("WriteThrottleEvents", "Sum", op.Keyspace, op.Table, op.Operation, 60, true)
	}
	for _, op := range active.partitionLimits {
		add("StoragePartitionThroughputCapacityExceeded", "Sum", op.Keyspace, op.Table, op.Operation, 60, true)
	}
	for _, op := range active.tableUserErrors {
		add("UserErrors", "Sum", op.Keyspace, op.Table, op.Operation, 60, true)
	}
	for _, op := range active.tableSystemErrors {
		add("SystemErrors", "Sum", op.Keyspace, op.Table, op.Operation, 60, true)
	}
	for _, op := range active.accountUserErrors {
		add("UserErrors", "Sum", "", "", op, 60, true)
	}
	if active.hasPerConnLimit {
		add("PerConnectionRequestRateExceeded", "Sum", "", "", "EXECUTE", 60, true)
	}

	return queries, metas
}

func splitCWQueryBatches(queries []cwtypes.MetricDataQuery, maxPerBatch int) [][]cwtypes.MetricDataQuery {
	if maxPerBatch <= 0 {
		maxPerBatch = keyspacesCWMaxBatchSize
	}
	if len(queries) == 0 {
		return nil
	}
	var batches [][]cwtypes.MetricDataQuery
	for i := 0; i < len(queries); i += maxPerBatch {
		end := i + maxPerBatch
		if end > len(queries) {
			end = len(queries)
		}
		batches = append(batches, queries[i:end])
	}
	return batches
}

func executeKeyspacesCWBatches(
	ctx context.Context,
	client *cloudwatch.Client,
	queries []cwtypes.MetricDataQuery,
	startTime, endTime time.Time,
) (map[string]cwtypes.MetricDataResult, error) {
	results := map[string]cwtypes.MetricDataResult{}
	for _, batch := range splitCWQueryBatches(queries, keyspacesCWMaxBatchSize) {
		paginator := cloudwatch.NewGetMetricDataPaginator(client, &cloudwatch.GetMetricDataInput{
			MetricDataQueries: batch,
			StartTime:         aws.Time(startTime),
			EndTime:           aws.Time(endTime),
			ScanBy:            cwtypes.ScanByTimestampDescending,
		})
		for paginator.HasMorePages() {
			out, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, r := range out.MetricDataResults {
				id := aws.ToString(r.Id)
				existing, ok := results[id]
				if !ok {
					results[id] = r
				} else {
					existing.Timestamps = append(existing.Timestamps, r.Timestamps...)
					existing.Values = append(existing.Values, r.Values...)
					results[id] = existing
				}
			}
		}
	}
	return results, nil
}

func applyKeyspacesCWResults(
	prev *keyspacesCWSnapshot,
	tables map[keyspacesTableKey]keyspacesTableMeta,
	metas map[string]cwQueryMeta,
	results map[string]cwtypes.MetricDataResult,
	now time.Time,
	pollLatency bool,
	pollSize bool,
) *keyspacesCWSnapshot {
	next := newKeyspacesCWSnapshot()
	if prev != nil {
		// Preserve slower-tier caches between their 5m / 60m refresh ticks.
		if !pollLatency {
			for k, v := range prev.requestsWindow {
				next.requestsWindow[k] = v
			}
			for k, v := range prev.latencyP99Sec {
				next.latencyP99Sec[k] = v
			}
		}
		if !pollSize {
			for k, v := range prev.tableSizeBytes {
				next.tableSizeBytes[k] = v
			}
		}
		next.hasAnyCWData = prev.hasAnyCWData
	}

	// Trailing 5-minute window for rolling error/throttle counters (plus 2m cushion for CW ingestion lag).
	rollingCutoff := now.Add(-(keyspacesErrorWindow + 2*time.Minute))

	for id, meta := range metas {
		r, ok := results[id]
		if !ok || len(r.Values) == 0 {
			continue
		}
		next.hasAnyCWData = true
		tk := keyspacesTableKey{Keyspace: meta.keyspace, Table: meta.table}
		opKey := keyspacesOpKey{Keyspace: meta.keyspace, Table: meta.table, Operation: meta.operation}

		if meta.isRolling {
			var sum float64
			for i, v := range r.Values {
				if i < len(r.Timestamps) && r.Timestamps[i].Before(rollingCutoff) {
					continue
				}
				sum += v
			}
			switch meta.metricName {
			case "ReadThrottleEvents":
				next.readThrottles[tk] += sum
			case "WriteThrottleEvents":
				next.writeThrottles[tk] += sum
			case "StoragePartitionThroughputCapacityExceeded":
				next.partitionLimits[tk] += sum
			case "UserErrors":
				if meta.keyspace == "" && meta.table == "" {
					next.accountUserErrors[meta.operation] += sum
				} else {
					next.tableUserErrors[tk] += sum
				}
			case "SystemErrors":
				next.tableSystemErrors[tk] += sum
			case "PerConnectionRequestRateExceeded":
				next.perConnLimits += sum
				next.hasPerConnLimit = true
			}
			continue
		}

		// Latest datapoint (ScanByTimestampDescending puts newest first; verify by timestamp in case paginated).
		latestVal := r.Values[0]
		if len(r.Timestamps) == len(r.Values) && len(r.Timestamps) > 1 {
			latestTS := r.Timestamps[0]
			for i := 1; i < len(r.Timestamps); i++ {
				if r.Timestamps[i].After(latestTS) {
					latestTS = r.Timestamps[i]
					latestVal = r.Values[i]
				}
			}
		}

		switch meta.metricName {
		case "ConsumedReadCapacityUnits":
			next.consumedReadPerSec[tk] = latestVal / float64(meta.periodSec)
		case "ConsumedWriteCapacityUnits":
			next.consumedWritePerSec[tk] = latestVal / float64(meta.periodSec)
		case "TableSizeBytes":
			next.tableSizeBytes[tk] = latestVal
		case "SuccessfulRequestLatency":
			switch meta.stat {
			case "p99":
				next.latencyP99Sec[opKey] = latestVal / 1000.0
			case "SampleCount":
				next.requestsWindow[opKey] = latestVal
			}
		}
	}

	// Ensure discovered tables retain 0-initialized throttle/error series when none fired in this window
	// so Prometheus gauges cleanly return to 0 instead of going stale.
	for tk := range tables {
		if _, ok := next.readThrottles[tk]; !ok && prev != nil {
			if _, had := prev.readThrottles[tk]; had {
				next.readThrottles[tk] = 0
			}
		}
		if _, ok := next.writeThrottles[tk]; !ok && prev != nil {
			if _, had := prev.writeThrottles[tk]; had {
				next.writeThrottles[tk] = 0
			}
		}
		if _, ok := next.partitionLimits[tk]; !ok && prev != nil {
			if _, had := prev.partitionLimits[tk]; had {
				next.partitionLimits[tk] = 0
			}
		}
		if _, ok := next.tableUserErrors[tk]; !ok && prev != nil {
			if _, had := prev.tableUserErrors[tk]; had {
				next.tableUserErrors[tk] = 0
			}
		}
		if _, ok := next.tableSystemErrors[tk]; !ok && prev != nil {
			if _, had := prev.tableSystemErrors[tk]; had {
				next.tableSystemErrors[tk] = 0
			}
		}
	}
	if prev != nil {
		for op := range prev.accountUserErrors {
			if _, ok := next.accountUserErrors[op]; !ok {
				next.accountUserErrors[op] = 0
			}
		}
		if prev.hasPerConnLimit && !next.hasPerConnLimit {
			next.hasPerConnLimit = true
			next.perConnLimits = 0
		}
	}

	return next
}

// --- Control-plane discovery on Discoverer ---

func keyspacesLabels(id string) prometheus.Labels {
	return prometheus.Labels{"keyspaces_id": id}
}

func (d *Discoverer) discoverKeyspaces() {
	if !d.cfg.KeyspacesEnabled {
		if d.keyspacesCollector != nil {
			prometheus.WrapRegistererWith(keyspacesLabels(d.keyspacesID), d.reg).Unregister(d.keyspacesCollector)
			d.keyspacesCollector.Stop()
			d.keyspacesCollector = nil
			d.keyspacesID = ""
		}
		return
	}

	if d.accountID == "" {
		accID, err := resolveAccountID(d.ctx, d.awsCfg)
		if err != nil {
			klog.Errorf("keyspaces: sts:GetCallerIdentity failed: %v", err)
			d.registerError(fmt.Errorf("keyspaces requires sts:GetCallerIdentity: %w", err))
			return
		}
		d.accountID = accID
	}

	svc := d.keyspacesClient
	tables := map[keyspacesTableKey]keyspacesTableMeta{}

	ksPaginator := keyspaces.NewListKeyspacesPaginator(svc, &keyspaces.ListKeyspacesInput{})
	for ksPaginator.HasMorePages() {
		ksOut, err := ksPaginator.NextPage(d.ctx)
		if err != nil {
			klog.Error(err)
			d.registerError(err)
			return
		}
		for _, ks := range ksOut.Keyspaces {
			ksName := aws.ToString(ks.KeyspaceName)
			if isSystemKeyspace(ksName) {
				continue
			}

			// Match KeyspacesTagFilters against keyspace tags (tables do not inherit keyspace tags).
			if filters := d.cfg.KeyspacesTagFilters; len(filters) > 0 {
				tags, err := listAllKeyspacesTags(d.ctx, svc, aws.ToString(ks.ResourceArn))
				if err != nil {
					klog.Error(err)
					d.registerError(err)
					continue
				}
				if !tagsMatched(filters, tags) {
					klog.Infof("Keyspaces keyspace %s (tags: %s) skipped by tag filters: %s", ksName, tags, filters)
					continue
				}
			}

			tblPaginator := keyspaces.NewListTablesPaginator(svc, &keyspaces.ListTablesInput{
				KeyspaceName: aws.String(ksName),
			})
			for tblPaginator.HasMorePages() {
				tblOut, err := tblPaginator.NextPage(d.ctx)
				if err != nil {
					klog.Error(err)
					d.registerError(err)
					break
				}
				for _, t := range tblOut.Tables {
					tName := aws.ToString(t.TableName)
					gt, err := svc.GetTable(d.ctx, &keyspaces.GetTableInput{
						KeyspaceName: aws.String(ksName),
						TableName:    aws.String(tName),
					})
					if err != nil {
						klog.Error(err)
						d.registerError(err)
						continue
					}
					meta := keyspacesTableMeta{
						Keyspace: ksName,
						Table:    tName,
						Status:   string(gt.Status),
					}
					if gt.CapacitySpecification != nil {
						meta.CapacityMode = string(gt.CapacitySpecification.ThroughputMode)
						meta.ProvisionedRead = float64(aws.ToInt64(gt.CapacitySpecification.ReadCapacityUnits))
						meta.ProvisionedWrite = float64(aws.ToInt64(gt.CapacitySpecification.WriteCapacityUnits))
					}
					if gt.WarmThroughputSpecification != nil {
						meta.WarmRead = float64(aws.ToInt64(gt.WarmThroughputSpecification.ReadUnitsPerSecond))
						meta.WarmWrite = float64(aws.ToInt64(gt.WarmThroughputSpecification.WriteUnitsPerSecond))
					}

					// Call GetTableAutoScalingSettings ONLY on PROVISIONED tables (PAY_PER_REQUEST returns ResourceNotFoundException).
					if meta.CapacityMode == string(kstypes.ThroughputModeProvisioned) {
						asOut, err := svc.GetTableAutoScalingSettings(d.ctx, &keyspaces.GetTableAutoScalingSettingsInput{
							KeyspaceName: aws.String(ksName),
							TableName:    aws.String(tName),
						})
						if err != nil {
							var rnfe *kstypes.ResourceNotFoundException
							if !errors.As(err, &rnfe) {
								klog.Warningf("keyspaces: GetTableAutoScalingSettings %s.%s: %v", ksName, tName, err)
							}
						} else if asOut.AutoScalingSpecification != nil {
							if r := asOut.AutoScalingSpecification.ReadCapacityAutoScaling; r != nil {
								meta.AutoScaleReadOff = r.AutoScalingDisabled
							}
							if w := asOut.AutoScalingSpecification.WriteCapacityAutoScaling; w != nil {
								meta.AutoScaleWriteOff = w.AutoScalingDisabled
							}
						}
					}

					tables[keyspacesTableKey{Keyspace: ksName, Table: tName}] = meta
				}
			}
		}
	}

	ksID := d.accountID + "/" + d.region
	if d.keyspacesCollector == nil {
		klog.Infof("new Keyspaces collector started: %s (%d tables)", ksID, len(tables))
		c := NewKeyspacesCollector(d, d.accountID, d.region, tables)
		if err := prometheus.WrapRegistererWith(keyspacesLabels(ksID), d.reg).Register(c); err != nil {
			klog.Error(err)
			c.Stop()
			return
		}
		d.keyspacesCollector = c
		d.keyspacesID = ksID
		return
	}

	if d.keyspacesID != ksID {
		prometheus.WrapRegistererWith(keyspacesLabels(d.keyspacesID), d.reg).Unregister(d.keyspacesCollector)
		d.keyspacesCollector.Stop()
		c := NewKeyspacesCollector(d, d.accountID, d.region, tables)
		if err := prometheus.WrapRegistererWith(keyspacesLabels(ksID), d.reg).Register(c); err != nil {
			klog.Error(err)
			c.Stop()
			d.keyspacesCollector = nil
			d.keyspacesID = ""
			return
		}
		d.keyspacesCollector = c
		d.keyspacesID = ksID
		return
	}

	d.keyspacesCollector.UpdateTables(tables)
}

func listAllKeyspacesTags(ctx context.Context, svc *keyspaces.Client, resourceArn string) (map[string]string, error) {
	tags := map[string]string{}
	paginator := keyspaces.NewListTagsForResourcePaginator(svc, &keyspaces.ListTagsForResourceInput{
		ResourceArn: aws.String(resourceArn),
	})
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, t := range out.Tags {
			tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}
	return tags, nil
}

func resolveAccountID(ctx context.Context, awsCfg aws.Config) (string, error) {
	if awsCfg.Credentials == nil {
		return "", errors.New("no credentials provider configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := sts.NewFromConfig(awsCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	id := aws.ToString(out.Account)
	if id == "" {
		return "", errors.New("empty AWS account ID")
	}
	return id, nil
}

// Keep slices import used for potential sorting helpers.
var _ = slices.Sort[[]string]
