package aws

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog"
)

type keyspacesTier int

const (
	keyspacesTierCapacity keyspacesTier = iota
	keyspacesTierLatency
	keyspacesTierStorage
	keyspacesTierErrors
)

const (
	cloudwatchNamespace      = "AWS/Cassandra"
	cloudwatchBatchSize      = 500
	cloudwatchIngestionLag   = 2 * time.Minute
	cloudwatchWindowDuration = 5 * time.Minute
	cloudwatchStorageWindow  = 12 * time.Hour // the table size is recalculated every 4-6 hours
)

var (
	keyspacesTierIntervals = map[keyspacesTier]time.Duration{
		keyspacesTierCapacity: time.Minute,
		keyspacesTierLatency:  5 * time.Minute,
		keyspacesTierStorage:  time.Hour,
		keyspacesTierErrors:   time.Minute,
	}

	keyspacesDMLOperations = map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true, "BATCH": true}

	keyspacesTableErrorTypes = map[string]string{
		"StoragePartitionThroughputCapacityExceeded": "hot_partition",
		"ReadThrottleEvents":                         "read_throttle",
		"WriteThrottleEvents":                        "write_throttle",
		"UserErrors":                                 "user",
		"SystemErrors":                               "system",
	}
	keyspacesStreamOperations = map[string]bool{"GetRecords": true, "GetShardIterator": true, "GetStream": true, "ListStreams": true}

	keyspacesAccountErrorTypes = map[string]string{
		"UserErrors":                       "user",
		"PerConnectionRequestRateExceeded": "per_connection_limit",
	}
)

type cloudwatchQuery struct {
	metric     string
	stat       string
	dimensions map[string]string
	desc       *prometheus.Desc
	table      keyspacesTableKey
	labels     []string
	sum        bool
	scale      float64
}

type cloudwatchTimeRange struct {
	start, end time.Time
	period     int32
}

func (k *Keyspaces) poll(ctx context.Context, d *Discoverer, tables map[keyspacesTableKey]*keyspacesTable, now time.Time) {
	var due []keyspacesTier
	for _, tier := range []keyspacesTier{keyspacesTierCapacity, keyspacesTierLatency, keyspacesTierStorage, keyspacesTierErrors} {
		if isDue(k.polledAt[tier], now, keyspacesTierIntervals[tier]) {
			due = append(due, tier)
		}
	}
	var active []cwtypes.Metric
	if slices.Contains(due, keyspacesTierLatency) || slices.Contains(due, keyspacesTierErrors) {
		var err error
		if active, err = listActiveMetrics(ctx, d.cloudwatchClient); err != nil {
			klog.Errorln("keyspaces: failed to list CloudWatch metrics:", err)
			d.registerError(err)
			due = slices.DeleteFunc(due, func(t keyspacesTier) bool {
				if t == keyspacesTierLatency || t == keyspacesTierErrors {
					k.failTier(t)
					return true
				}
				return false
			})
		}
	}

	end := now.Truncate(time.Minute).Add(-cloudwatchIngestionLag)
	for _, tier := range due {
		var queries []cloudwatchQuery
		var window cloudwatchTimeRange
		switch tier {
		case keyspacesTierCapacity:
			queries = capacityQueries(tables)
			window = cloudwatchTimeRange{start: end.Add(-time.Minute), end: end, period: 60}
		case keyspacesTierLatency:
			queries = latencyQueries(tables, active)
			window = cloudwatchTimeRange{start: end.Add(-cloudwatchWindowDuration), end: end, period: int32(cloudwatchWindowDuration.Seconds())}
		case keyspacesTierStorage:
			queries = storageQueries(tables)
			window = cloudwatchTimeRange{start: end.Add(-cloudwatchStorageWindow), end: end, period: 3600}
		case keyspacesTierErrors:
			queries = errorQueries(tables, active)
			window = cloudwatchTimeRange{start: end.Add(-cloudwatchWindowDuration), end: end, period: 60}
		}
		values, err := getMetricData(ctx, d.cloudwatchClient, queries, window)
		if err != nil {
			klog.Errorln("keyspaces: failed to get CloudWatch metrics:", err)
			d.registerError(err)
			k.failTier(tier)
			continue
		}
		k.lock.Lock()
		k.values[tier] = values
		k.lock.Unlock()
		k.polledAt[tier] = now
	}
}

// stale values would keep reporting a past state as current
func (k *Keyspaces) failTier(tier keyspacesTier) {
	k.lock.Lock()
	delete(k.values, tier)
	k.lock.Unlock()
}

func listActiveMetrics(ctx context.Context, client cloudwatch.ListMetricsAPIClient) ([]cwtypes.Metric, error) {
	var res []cwtypes.Metric
	paginator := cloudwatch.NewListMetricsPaginator(client, &cloudwatch.ListMetricsInput{
		Namespace:      aws.String(cloudwatchNamespace),
		RecentlyActive: cwtypes.RecentlyActivePt3h,
	})
	for paginator.HasMorePages() {
		output, err := withTimeout(ctx, paginator.NextPage)
		if err != nil {
			return nil, err
		}
		res = append(res, output.Metrics...)
	}
	return res, nil
}

func capacityQueries(tables map[keyspacesTableKey]*keyspacesTable) []cloudwatchQuery {
	var res []cloudwatchQuery
	for key := range tables {
		for metric, operation := range map[string]string{"ConsumedReadCapacityUnits": "read", "ConsumedWriteCapacityUnits": "write"} {
			res = append(res, cloudwatchQuery{
				metric: metric, stat: "Sum", dimensions: tableDimensions(key),
				desc: dKeyspacesTableConsumed, table: key, labels: []string{operation}, scale: 1. / 60, sum: true,
			})
		}
	}
	return res
}

func storageQueries(tables map[keyspacesTableKey]*keyspacesTable) []cloudwatchQuery {
	var res []cloudwatchQuery
	for key := range tables {
		res = append(res, cloudwatchQuery{metric: "BillableTableSizeInBytes", stat: "Average", dimensions: tableDimensions(key), desc: dKeyspacesTableSize, table: key})
	}
	return res
}

func latencyQueries(tables map[keyspacesTableKey]*keyspacesTable, active []cwtypes.Metric) []cloudwatchQuery {
	var res []cloudwatchQuery
	for _, m := range active {
		if aws.ToString(m.MetricName) != "SuccessfulRequestLatency" {
			continue
		}
		dims := dimensions(m)
		key := keyspacesTableKey{keyspace: dims["Keyspace"], table: dims["TableName"]}
		operation := dims["Operation"]
		if tables[key] == nil || !keyspacesDMLOperations[operation] || len(dims) != 3 {
			continue
		}
		res = append(res,
			cloudwatchQuery{metric: "SuccessfulRequestLatency", stat: "p99", dimensions: dims, desc: dKeyspacesTableLatency, table: key, labels: []string{operation}, scale: 1. / 1000},
			cloudwatchQuery{metric: "SuccessfulRequestLatency", stat: "SampleCount", dimensions: dims, desc: dKeyspacesTableRequests, table: key, labels: []string{operation}},
		)
	}
	return res
}

// CloudWatch may publish a metric both per table and per table and operation, and the per-connection limit
// both per account and per table: the coarser series is used when it exists, so that a rejection is counted once
func errorQueries(tables map[keyspacesTableKey]*keyspacesTable, active []cwtypes.Metric) []cloudwatchQuery {
	type seriesKey struct {
		metric string
		table  keyspacesTableKey
	}
	coarse := map[seriesKey]bool{}
	for _, m := range active {
		dims := dimensions(m)
		metric := aws.ToString(m.MetricName)
		_, hasOperation := dims["Operation"]
		switch {
		case !hasOperation && len(dims) == 2:
			coarse[seriesKey{metric: metric, table: keyspacesTableKey{keyspace: dims["Keyspace"], table: dims["TableName"]}}] = true
		case hasOperation && len(dims) == 1:
			coarse[seriesKey{metric: metric}] = true
		}
	}

	var res []cloudwatchQuery
	for _, m := range active {
		metric := aws.ToString(m.MetricName)
		dims := dimensions(m)
		operation, hasOperation := dims["Operation"]
		if keyspacesStreamOperations[operation] || dims["StreamLabel"] != "" {
			continue
		}
		key := keyspacesTableKey{keyspace: dims["Keyspace"], table: dims["TableName"]}
		switch {
		case key.keyspace != "" && key.table != "" && metric == "PerConnectionRequestRateExceeded":
			if tables[key] == nil || !hasOperation || coarse[seriesKey{metric: metric}] {
				continue
			}
			res = append(res, cloudwatchQuery{metric: metric, stat: "Sum", dimensions: dims, desc: dKeyspacesAccountErrors, labels: []string{"per_connection_limit", operation}, sum: true})
		case key.keyspace != "" && key.table != "":
			t := keyspacesTableErrorTypes[metric]
			if t == "" || tables[key] == nil || (hasOperation && coarse[seriesKey{metric: metric, table: key}]) {
				continue
			}
			res = append(res, cloudwatchQuery{metric: metric, stat: "Sum", dimensions: dims, desc: dKeyspacesTableErrors, table: key, labels: []string{t}, sum: true})
		case hasOperation && len(dims) == 1:
			t := keyspacesAccountErrorTypes[metric]
			if t == "" {
				continue
			}
			res = append(res, cloudwatchQuery{metric: metric, stat: "Sum", dimensions: dims, desc: dKeyspacesAccountErrors, labels: []string{t, operation}, sum: true})
		}
	}
	return res
}

func getMetricData(ctx context.Context, client cloudwatch.GetMetricDataAPIClient, queries []cloudwatchQuery, window cloudwatchTimeRange) ([]keyspacesValue, error) {
	type valueKey struct {
		desc   *prometheus.Desc
		table  keyspacesTableKey
		labels string
	}
	var res []keyspacesValue
	index := map[valueKey]int{}
	for start := 0; start < len(queries); start += cloudwatchBatchSize {
		batch := queries[start:min(start+cloudwatchBatchSize, len(queries))]
		input := &cloudwatch.GetMetricDataInput{StartTime: aws.Time(window.start), EndTime: aws.Time(window.end)}
		for i, q := range batch {
			var dims []cwtypes.Dimension
			for name, value := range q.dimensions {
				dims = append(dims, cwtypes.Dimension{Name: aws.String(name), Value: aws.String(value)})
			}
			input.MetricDataQueries = append(input.MetricDataQueries, cwtypes.MetricDataQuery{
				Id: aws.String("q" + strconv.Itoa(i)),
				MetricStat: &cwtypes.MetricStat{
					Metric: &cwtypes.Metric{Namespace: aws.String(cloudwatchNamespace), MetricName: aws.String(q.metric), Dimensions: dims},
					Period: aws.Int32(window.period),
					Stat:   aws.String(q.stat),
				},
			})
		}
		paginator := cloudwatch.NewGetMetricDataPaginator(client, input)
		for paginator.HasMorePages() {
			output, err := withTimeout(ctx, paginator.NextPage)
			if err != nil {
				return nil, err
			}
			for _, r := range output.MetricDataResults {
				i, err := strconv.Atoi(strings.TrimPrefix(aws.ToString(r.Id), "q"))
				if err != nil || i < 0 || i >= len(batch) {
					continue
				}
				q := batch[i]
				var v float64
				switch {
				case q.sum:
					for _, p := range r.Values {
						v += p
					}
				case len(r.Values) > 0:
					v = r.Values[0] // newest first
				default:
					continue
				}
				if q.scale != 0 {
					v *= q.scale
				}
				key := valueKey{desc: q.desc, table: q.table, labels: strings.Join(q.labels, "\x00")}
				if j, ok := index[key]; ok {
					res[j].value += v
					continue
				}
				index[key] = len(res)
				res = append(res, keyspacesValue{desc: q.desc, table: q.table, labels: q.labels, value: v})
			}
		}
	}
	return res, nil
}

func tableDimensions(key keyspacesTableKey) map[string]string {
	return map[string]string{"Keyspace": key.keyspace, "TableName": key.table}
}

func dimensions(m cwtypes.Metric) map[string]string {
	res := map[string]string{}
	for _, d := range m.Dimensions {
		res[aws.ToString(d.Name)] = aws.ToString(d.Value)
	}
	return res
}
