package aws

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyspacesTagAndSystemFiltering(t *testing.T) {
	assert.True(t, isSystemKeyspace("system"))
	assert.True(t, isSystemKeyspace("system_schema"))
	assert.True(t, isSystemKeyspace("system_schema_mcs"))
	assert.True(t, isSystemKeyspace("system_multiregion_info"))
	assert.False(t, isSystemKeyspace("orders_prod"))
	assert.False(t, isSystemKeyspace("keyspaces_val"))

	assert.True(t, tagsMatched(map[string]string{"project": "keyspaces-*"}, map[string]string{"project": "keyspaces-val", "env": "prod"}))
	assert.False(t, tagsMatched(map[string]string{"project": "keyspaces-*", "team": "checkout"}, map[string]string{"project": "keyspaces-val"}))
	assert.True(t, tagsMatched(map[string]string{}, map[string]string{}))
}

func TestCrawlKeyspacesEndpoints_PublicOneHopRecoversAll12(t *testing.T) {
	// Mirrors the 2026-11-22 ap-southeast-1 spike: 12 IPs partitioned into 3 groups of 4,
	// where each node omits 2-3 IPs (returning 9 peers). Behind caching DNS (1 seed IP),
	// a single query misses 2 IPs; a 1-hop crawl recovers all 12 deterministically.
	groupA := []string{"18.141.148.5", "18.141.148.49", "18.141.148.50", "18.141.148.51"}
	groupB := []string{"18.141.148.45", "18.141.148.46", "18.141.148.47", "18.141.148.48"}
	groupC := []string{"18.141.148.52", "18.141.148.53", "18.141.148.54", "18.141.148.55"}
	all12 := append(append(append([]string{}, groupA...), groupB...), groupC...)

	omitByGroup := map[string]map[string]bool{}
	for _, ip := range groupA {
		omitByGroup[ip] = map[string]bool{ip: true, "18.141.148.45": true, "18.141.148.52": true}
	}
	for _, ip := range groupB {
		omitByGroup[ip] = map[string]bool{ip: true, "18.141.148.49": true, "18.141.148.52": true}
	}
	for _, ip := range groupC {
		omitByGroup[ip] = map[string]bool{ip: true, "18.141.148.45": true, "18.141.148.49": true}
	}

	queried := 0
	eps := crawlKeyspacesEndpoints(context.Background(), "ap-southeast-1", []string{"18.141.148.51"}, func(ctx context.Context, ip string) ([]string, error) {
		queried++
		var peers []string
		for _, cand := range all12 {
			if !omitByGroup[ip][cand] {
				peers = append(peers, cand)
			}
		}
		return peers, nil
	})

	assert.Equal(t, 10, queried, "1 seed + 9 peers = 10 short queries")

	peerIPs := map[string]bool{}
	publicHosts := map[string]bool{}
	for _, ep := range eps {
		assert.Equal(t, "9142", ep.Port)
		if ep.Kind == "peer" {
			peerIPs[ep.Addr] = true
		} else if ep.Kind == "public" {
			publicHosts[ep.Addr] = true
		}
	}
	assert.True(t, publicHosts["cassandra.ap-southeast-1.amazonaws.com"])
	assert.True(t, publicHosts["cassandra.ap-southeast-1.api.aws"])
	assert.Len(t, peerIPs, 12, "1-hop union must recover all 12 pool IPs")
	for _, ip := range all12 {
		assert.True(t, peerIPs[ip], "missing IP %s", ip)
	}
}

func TestCrawlKeyspacesEndpoints_VPCSkipsPeerCrawl(t *testing.T) {
	called := false
	eps := crawlKeyspacesEndpoints(context.Background(), "ap-southeast-1", []string{"10.78.1.163", "10.78.2.136"}, func(ctx context.Context, ip string) ([]string, error) {
		called = true
		return nil, nil
	})

	assert.False(t, called, "VPC endpoint discovery should not call system.peers via gocql")
	vpcAddrs := map[string]bool{}
	for _, ep := range eps {
		if ep.Kind == "vpc" {
			vpcAddrs[ep.Addr] = true
		}
	}
	assert.Equal(t, map[string]bool{"10.78.1.163": true, "10.78.2.136": true}, vpcAddrs)
}

func TestBuildKeyspacesCWQueries_TieringAndBatching(t *testing.T) {
	tables := map[keyspacesTableKey]keyspacesTableMeta{
		{Keyspace: "ks", Table: "t_prov"}:     {Keyspace: "ks", Table: "t_prov", CapacityMode: "PROVISIONED"},
		{Keyspace: "ks", Table: "t_ondemand"}: {Keyspace: "ks", Table: "t_ondemand", CapacityMode: "PAY_PER_REQUEST"},
	}
	active := cwActiveSeries{
		latencyOps: []keyspacesOpKey{
			{Keyspace: "ks", Table: "t_prov", Operation: "INSERT"},
			{Keyspace: "ks", Table: "t_prov", Operation: "SELECT"},
		},
		writeThrottles:    []keyspacesOpKey{{Keyspace: "ks", Table: "t_prov", Operation: "INSERT"}},
		tableUserErrors:   []keyspacesOpKey{{Keyspace: "ks", Table: "t_prov", Operation: "INSERT"}},
		accountUserErrors: []string{"EXECUTE", "PREPARE"},
		hasPerConnLimit:   true,
	}

	// Steady 1m tick (no latency, no size): 4 consumed + 5 active error series = 9 queries
	q1, _ := buildKeyspacesCWQueries(tables, active, false, false)
	assert.Len(t, q1, 9)

	// 5m tick (with latency, no size): +4 latency queries (2 ops * (p99 + SampleCount)) = 13 queries
	q5, metas5 := buildKeyspacesCWQueries(tables, active, true, false)
	assert.Len(t, q5, 13)
	p99Count := 0
	scCount := 0
	for _, m := range metas5 {
		if m.metricName == "SuccessfulRequestLatency" && m.stat == "p99" {
			p99Count++
		}
		if m.metricName == "SuccessfulRequestLatency" && m.stat == "SampleCount" {
			scCount++
		}
	}
	assert.Equal(t, 2, p99Count)
	assert.Equal(t, 2, scCount)

	// 60m tick (with latency + size): +2 size queries = 15 queries
	q60, _ := buildKeyspacesCWQueries(tables, active, true, true)
	assert.Len(t, q60, 15)

	// Batching splits >500 queries cleanly
	big := make([]cwtypes.MetricDataQuery, 1205)
	batches := splitCWQueryBatches(big, 500)
	require.Len(t, batches, 3)
	assert.Len(t, batches[0], 500)
	assert.Len(t, batches[1], 500)
	assert.Len(t, batches[2], 205)
}

func TestApplyKeyspacesCWResults_UnitsAndRollingWindow(t *testing.T) {
	now := time.Date(2026, 11, 23, 4, 30, 0, 0, time.UTC)
	tk := keyspacesTableKey{Keyspace: "ks", Table: "t_prov"}
	tables := map[keyspacesTableKey]keyspacesTableMeta{tk: {Keyspace: "ks", Table: "t_prov"}}
	active := cwActiveSeries{
		latencyOps:        []keyspacesOpKey{{Keyspace: "ks", Table: "t_prov", Operation: "INSERT"}},
		writeThrottles:    []keyspacesOpKey{{Keyspace: "ks", Table: "t_prov", Operation: "INSERT"}},
		accountUserErrors: []string{"PREPARE"},
		hasPerConnLimit:   true,
	}

	_, metas := buildKeyspacesCWQueries(tables, active, true, true)
	results := map[string]cwtypes.MetricDataResult{}
	for id, m := range metas {
		switch {
		case m.metricName == "ConsumedWriteCapacityUnits":
			// 300 WCU over 60s -> 5.0 WCU/s
			results[id] = cwtypes.MetricDataResult{
				Id:         aws.String(id),
				Timestamps: []time.Time{now.Add(-time.Minute)},
				Values:     []float64{300},
			}
		case m.metricName == "SuccessfulRequestLatency" && m.stat == "p99":
			// 23.18 ms -> 0.02318 s
			results[id] = cwtypes.MetricDataResult{
				Id:         aws.String(id),
				Timestamps: []time.Time{now.Add(-2 * time.Minute)},
				Values:     []float64{23.18},
			}
		case m.metricName == "SuccessfulRequestLatency" && m.stat == "SampleCount":
			results[id] = cwtypes.MetricDataResult{
				Id:         aws.String(id),
				Timestamps: []time.Time{now.Add(-2 * time.Minute)},
				Values:     []float64{1803},
			}
		case m.metricName == "WriteThrottleEvents":
			// 2 points inside rolling window (400 + 196 = 596) + 1 stale point outside window (999 ignored)
			results[id] = cwtypes.MetricDataResult{
				Id:         aws.String(id),
				Timestamps: []time.Time{now.Add(-2 * time.Minute), now.Add(-3 * time.Minute), now.Add(-12 * time.Minute)},
				Values:     []float64{400, 196, 999},
			}
		case m.metricName == "UserErrors" && m.operation == "PREPARE":
			results[id] = cwtypes.MetricDataResult{
				Id:         aws.String(id),
				Timestamps: []time.Time{now.Add(-time.Minute)},
				Values:     []float64{50},
			}
		case m.metricName == "PerConnectionRequestRateExceeded":
			results[id] = cwtypes.MetricDataResult{
				Id:         aws.String(id),
				Timestamps: []time.Time{now.Add(-time.Minute)},
				Values:     []float64{144839},
			}
		}
	}

	snap := applyKeyspacesCWResults(nil, tables, metas, results, now, true, true)
	assert.InDelta(t, 5.0, snap.consumedWritePerSec[tk], 0.001)
	assert.InDelta(t, 0.02318, snap.latencyP99Sec[keyspacesOpKey{Keyspace: "ks", Table: "t_prov", Operation: "INSERT"}], 0.0001)
	assert.Equal(t, float64(1803), snap.requestsWindow[keyspacesOpKey{Keyspace: "ks", Table: "t_prov", Operation: "INSERT"}])
	assert.Equal(t, float64(596), snap.writeThrottles[tk])
	assert.Equal(t, float64(50), snap.accountUserErrors["PREPARE"])
	assert.Equal(t, float64(144839), snap.perConnLimits)

	// Next 1m tick (pollLatency=false, no new errors): latency preserved, errors decay cleanly to 0
	_, metas2 := buildKeyspacesCWQueries(tables, cwActiveSeries{}, false, false)
	snap2 := applyKeyspacesCWResults(snap, tables, metas2, map[string]cwtypes.MetricDataResult{}, now.Add(time.Minute), false, false)
	assert.InDelta(t, 0.02318, snap2.latencyP99Sec[keyspacesOpKey{Keyspace: "ks", Table: "t_prov", Operation: "INSERT"}], 0.0001)
	assert.Equal(t, float64(0), snap2.writeThrottles[tk])
	assert.Equal(t, float64(0), snap2.accountUserErrors["PREPARE"])
	assert.Equal(t, float64(0), snap2.perConnLimits)
}
