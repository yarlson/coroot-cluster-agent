package aws

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/keyspaces"
	kstypes "github.com/aws/aws-sdk-go-v2/service/keyspaces/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/coroot/coroot-cluster-agent/common"
	"github.com/coroot/coroot-cluster-agent/config"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog"
)

const (
	keyspacesStageTimeout         = 15 * time.Second
	keyspacesCallTimeout          = 10 * time.Second
	keyspacesTableDetailsInterval = 5 * time.Minute

	keyspacesCapacityModeProvisioned = "provisioned"
	keyspacesCapacityModeOnDemand    = "on-demand"
)

var (
	dKeyspacesInfo             = common.Desc("aws_keyspaces_info", "Amazon Keyspaces account and region", "keyspaces_id", "account_id", "region")
	dKeyspacesEndpoint         = common.Desc("aws_keyspaces_endpoint", "Amazon Keyspaces endpoint reachable by clients", "keyspaces_id", "host", "port")
	dKeyspacesTableInfo        = common.Desc("aws_keyspaces_table_info", "Amazon Keyspaces table info", "keyspaces_id", "keyspace", "table", "capacity_mode", "auto_scaling")
	dKeyspacesTableProvisioned = common.Desc("aws_keyspaces_table_provisioned_capacity_units", "Provisioned read or write capacity units", "keyspaces_id", "keyspace", "table", "operation")
	dKeyspacesTableConsumed    = common.Desc("aws_keyspaces_table_consumed_capacity_units", "Consumed read or write capacity units per second", "keyspaces_id", "keyspace", "table", "operation")
	dKeyspacesTableSize        = common.Desc("aws_keyspaces_table_size_bytes", "Table size", "keyspaces_id", "keyspace", "table")
	dKeyspacesTableLatency     = common.Desc("aws_keyspaces_table_latency_seconds", "p99 latency of successful requests over the last 5 minutes", "keyspaces_id", "keyspace", "table", "operation")
	dKeyspacesTableRequests    = common.Desc("aws_keyspaces_table_requests", "Number of successful requests over the last 5 minutes", "keyspaces_id", "keyspace", "table", "operation")
	dKeyspacesTableErrors      = common.Desc("aws_keyspaces_table_errors", "Number of rejections over the last 5 minutes by CloudWatch metric, AWS counts one rejection in several types", "keyspaces_id", "keyspace", "table", "type")
	dKeyspacesAccountErrors    = common.Desc("aws_keyspaces_account_errors", "Number of rejections over the last 5 minutes not attributed to a table, AWS counts one rejection in several types", "keyspaces_id", "type", "operation")

	keyspacesSystemKeyspaces = map[string]bool{"system": true, "system_schema": true, "system_schema_mcs": true, "system_multiregion_info": true}
)

type keyspacesTableKey struct {
	keyspace string
	table    string
}

type keyspacesTable struct {
	capacityMode     string
	autoScaling      string
	provisionedRead  int64
	provisionedWrite int64
}

type keyspacesValue struct {
	desc   *prometheus.Desc
	table  keyspacesTableKey // empty for account-level values
	labels []string
	value  float64
}

type Keyspaces struct {
	cfg *config.AWSConfig

	lock      sync.RWMutex
	accountId string
	region    string
	tables    map[keyspacesTableKey]*keyspacesTable
	endpoints []string
	values    map[keyspacesTier][]keyspacesValue

	endpointsRegion    string
	endpointsUpdatedAt time.Time
	tablesUpdatedAt    time.Time
	polledAt           map[keyspacesTier]time.Time
}

func NewKeyspaces(cfg *config.AWSConfig) *Keyspaces {
	return &Keyspaces{
		cfg:      cfg,
		tables:   map[keyspacesTableKey]*keyspacesTable{},
		values:   map[keyspacesTier][]keyspacesValue{},
		polledAt: map[keyspacesTier]time.Time{},
	}
}

func (k *Keyspaces) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("aws_keyspaces", "", nil, nil)
}

func (k *Keyspaces) Collect(ch chan<- prometheus.Metric) {
	k.lock.RLock()
	defer k.lock.RUnlock()
	if k.accountId == "" {
		return
	}
	id := k.accountId + "/" + k.region
	ch <- common.Gauge(dKeyspacesInfo, 1, id, k.accountId, k.region)
	for _, e := range k.endpoints {
		ch <- common.Gauge(dKeyspacesEndpoint, 1, id, e, keyspacesPort)
	}
	for key, t := range k.tables {
		ch <- common.Gauge(dKeyspacesTableInfo, 1, id, key.keyspace, key.table, t.capacityMode, t.autoScaling)
		if t.capacityMode == keyspacesCapacityModeProvisioned {
			ch <- common.Gauge(dKeyspacesTableProvisioned, float64(t.provisionedRead), id, key.keyspace, key.table, "read")
			ch <- common.Gauge(dKeyspacesTableProvisioned, float64(t.provisionedWrite), id, key.keyspace, key.table, "write")
		}
	}
	for _, values := range k.values {
		for _, v := range values {
			labels := []string{id}
			if v.table != (keyspacesTableKey{}) {
				if k.tables[v.table] == nil {
					continue
				}
				labels = append(labels, v.table.keyspace, v.table.table)
			}
			ch <- common.Gauge(v.desc, v.value, append(labels, v.labels...)...)
		}
	}
}

func (k *Keyspaces) TablesCount() int {
	k.lock.RLock()
	defer k.lock.RUnlock()
	return len(k.tables)
}

// each stage has its own budget, so that a slow control plane doesn't starve the CloudWatch polling
func (k *Keyspaces) refresh(d *Discoverer) {
	now := time.Now()
	region := d.region
	accountId := k.getAccountId(d)
	if accountId == "" {
		return
	}
	if accountId != k.accountId || region != k.region {
		k.lock.Lock()
		k.tables = map[keyspacesTableKey]*keyspacesTable{}
		k.values = map[keyspacesTier][]keyspacesValue{}
		k.endpoints = nil
		k.lock.Unlock()
		k.polledAt = map[keyspacesTier]time.Time{}
		k.tablesUpdatedAt = time.Time{}
		k.endpointsUpdatedAt = time.Time{}
	}

	ctx, cancel := context.WithTimeout(d.ctx, keyspacesStageTimeout)
	detailsDue := isDue(k.tablesUpdatedAt, now, keyspacesTableDetailsInterval)
	tables := k.discoverTables(ctx, d, detailsDue)
	cancel()
	if detailsDue {
		k.tablesUpdatedAt = now
	}
	k.lock.Lock()
	k.accountId = accountId
	k.region = region
	k.tables = tables
	k.lock.Unlock()

	if k.endpointsRegion != region || isDue(k.endpointsUpdatedAt, now, keyspacesEndpointsInterval) {
		ctx, cancel = context.WithTimeout(d.ctx, keyspacesStageTimeout)
		k.discoverEndpoints(ctx, d, region)
		cancel()
		k.endpointsRegion = region
		k.endpointsUpdatedAt = now
	}

	ctx, cancel = context.WithTimeout(d.ctx, keyspacesStageTimeout)
	k.poll(ctx, d, tables, now)
	cancel()
}

func (k *Keyspaces) getAccountId(d *Discoverer) string {
	out, err := withTimeout(d.ctx, func(ctx context.Context, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
		return d.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, optFns...)
	})
	if err != nil {
		klog.Errorln("keyspaces: failed to get the caller identity:", err)
		d.registerError(err)
		k.lock.RLock()
		defer k.lock.RUnlock()
		return k.accountId
	}
	return aws.ToString(out.Account)
}

func (k *Keyspaces) discoverTables(ctx context.Context, d *Discoverer, detailsDue bool) map[keyspacesTableKey]*keyspacesTable {
	svc := d.keyspacesClient
	k.lock.RLock()
	previous := k.tables
	k.lock.RUnlock()
	tables := map[keyspacesTableKey]*keyspacesTable{}
	keepPrevious := func(keyspace string) {
		for key, t := range previous {
			if key.keyspace == keyspace {
				tables[key] = t
			}
		}
	}

	var keyspaceNames []string
	paginator := keyspaces.NewListKeyspacesPaginator(svc, &keyspaces.ListKeyspacesInput{})
	for paginator.HasMorePages() {
		output, err := withTimeout(ctx, paginator.NextPage)
		if err != nil {
			klog.Errorln("keyspaces: failed to list keyspaces:", err)
			d.registerError(err)
			return previous
		}
		for _, ks := range output.Keyspaces {
			name := aws.ToString(ks.KeyspaceName)
			if keyspacesSystemKeyspaces[name] {
				continue
			}
			if filters := d.cfg.KeyspacesTagFilters; len(filters) > 0 {
				tags, err := keyspacesTags(ctx, svc, ks.ResourceArn)
				if err != nil {
					klog.Errorln("keyspaces: failed to get tags:", err)
					d.registerError(err)
					keepPrevious(name)
					continue
				}
				if !tagsMatched(filters, tags) {
					continue
				}
			}
			keyspaceNames = append(keyspaceNames, name)
		}
	}

	for _, keyspace := range keyspaceNames {
		paginator := keyspaces.NewListTablesPaginator(svc, &keyspaces.ListTablesInput{KeyspaceName: aws.String(keyspace)})
		for paginator.HasMorePages() {
			output, err := withTimeout(ctx, paginator.NextPage)
			if err != nil {
				klog.Errorln("keyspaces: failed to list tables:", err)
				d.registerError(err)
				keepPrevious(keyspace)
				break
			}
			for _, ts := range output.Tables {
				key := keyspacesTableKey{keyspace: keyspace, table: aws.ToString(ts.TableName)}
				if t := previous[key]; t != nil && !detailsDue {
					tables[key] = t
					continue
				}
				t, err := getKeyspacesTable(ctx, d, key, previous[key])
				if err != nil {
					klog.Errorln("keyspaces: failed to get table:", err)
					d.registerError(err)
					t = previous[key]
				}
				if t != nil {
					tables[key] = t
				}
			}
		}
	}
	return tables
}

func getKeyspacesTable(ctx context.Context, d *Discoverer, key keyspacesTableKey, previous *keyspacesTable) (*keyspacesTable, error) {
	svc := d.keyspacesClient
	out, err := withTimeout(ctx, func(ctx context.Context, optFns ...func(*keyspaces.Options)) (*keyspaces.GetTableOutput, error) {
		return svc.GetTable(ctx, &keyspaces.GetTableInput{KeyspaceName: aws.String(key.keyspace), TableName: aws.String(key.table)}, optFns...)
	})
	if err != nil {
		return nil, err
	}
	t := &keyspacesTable{capacityMode: keyspacesCapacityModeOnDemand}
	cs := out.CapacitySpecification
	if cs == nil || cs.ThroughputMode != kstypes.ThroughputModeProvisioned {
		return t, nil
	}
	t.capacityMode = keyspacesCapacityModeProvisioned
	t.provisionedRead = aws.ToInt64(cs.ReadCapacityUnits)
	t.provisionedWrite = aws.ToInt64(cs.WriteCapacityUnits)
	as, err := withTimeout(ctx, func(ctx context.Context, optFns ...func(*keyspaces.Options)) (*keyspaces.GetTableAutoScalingSettingsOutput, error) {
		return svc.GetTableAutoScalingSettings(ctx, &keyspaces.GetTableAutoScalingSettingsInput{KeyspaceName: aws.String(key.keyspace), TableName: aws.String(key.table)}, optFns...)
	})
	if err != nil {
		klog.Errorln("keyspaces: failed to get the auto scaling settings:", err)
		d.registerError(err)
		if previous != nil {
			t.autoScaling = previous.autoScaling
		}
		return t, nil
	}
	t.autoScaling = strconv.FormatBool(autoScalingEnabled(as.AutoScalingSpecification))
	return t, nil
}

func autoScalingEnabled(s *kstypes.AutoScalingSpecification) bool {
	if s == nil {
		return false
	}
	for _, as := range []*kstypes.AutoScalingSettings{s.ReadCapacityAutoScaling, s.WriteCapacityAutoScaling} {
		if as != nil && !as.AutoScalingDisabled {
			return true
		}
	}
	return false
}

func keyspacesTags(ctx context.Context, svc *keyspaces.Client, arn *string) (map[string]string, error) {
	tags := map[string]string{}
	paginator := keyspaces.NewListTagsForResourcePaginator(svc, &keyspaces.ListTagsForResourceInput{ResourceArn: arn})
	for paginator.HasMorePages() {
		output, err := withTimeout(ctx, paginator.NextPage)
		if err != nil {
			return nil, err
		}
		for _, t := range output.Tags {
			tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}
	return tags, nil
}

func withTimeout[T, O any](ctx context.Context, call func(context.Context, ...func(*O)) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, keyspacesCallTimeout)
	defer cancel()
	return call(ctx)
}

func isDue(last, now time.Time, interval time.Duration) bool {
	return last.IsZero() || now.Sub(last) > interval-discoveryInterval/2
}
