package exporters

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	ipv4RegexStr = `^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$`
	ipv6RegexStr = `^(([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9])\.(25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9])\.(25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9])\.(25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9]))|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9])\.(25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9])\.(25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9])\.(25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9])))$`

	ipv4Regex = regexp.MustCompile(ipv4RegexStr)
	ipv6Regex = regexp.MustCompile(ipv6RegexStr)
)

// func init() {
// 	ipv4Regex := regexp.MustCompile(ipv4RegexStr)
// 	ipv6Regex := regexp.MustCompile(ipv6RegexStr)
// }

type OpenvpnServerHeader struct {
	LabelColumns []string
	Metrics      []OpenvpnServerHeaderField
}

type OpenvpnServerHeaderField struct {
	Column    string
	Desc      *prometheus.Desc
	ValueType prometheus.ValueType
}

type OpenVPNExporter struct {
	statusPaths                 []string
	openvpnUpDesc               *prometheus.Desc
	openvpnStatusUpdateTimeDesc *prometheus.Desc
	openvpnConnectedClientsDesc *prometheus.Desc
	openvpnClientDescs          map[string]*prometheus.Desc
	openvpnServerHeaders        map[string]OpenvpnServerHeader
}

func NewOpenVPNExporter(statusPaths []string, ignoreIndividuals bool) (*OpenVPNExporter, error) {
	// Metrics exported both for client and server statistics.
	openvpnUpDesc := prometheus.NewDesc(
		prometheus.BuildFQName("openvpn", "", "up"),
		"Whether scraping OpenVPN's metrics was successful.",
		[]string{"status_path"}, nil)
	openvpnStatusUpdateTimeDesc := prometheus.NewDesc(
		prometheus.BuildFQName("openvpn", "", "status_update_time_seconds"),
		"UNIX timestamp at which the OpenVPN statistics were updated.",
		[]string{"status_path"}, nil)

	// Metrics specific to OpenVPN servers.
	openvpnConnectedClientsDesc := prometheus.NewDesc(
		prometheus.BuildFQName("openvpn", "", "server_connected_clients"),
		"Number Of Connected Clients",
		[]string{"status_path"}, nil)

	// Metrics specific to OpenVPN clients.
	openvpnClientDescs := map[string]*prometheus.Desc{
		"TUN/TAP read bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "tun_tap_read_bytes_total"),
			"Total amount of TUN/TAP traffic read, in bytes.",
			[]string{"status_path"}, nil),
		"TUN/TAP write bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "tun_tap_write_bytes_total"),
			"Total amount of TUN/TAP traffic written, in bytes.",
			[]string{"status_path"}, nil),
		"TCP/UDP read bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "tcp_udp_read_bytes_total"),
			"Total amount of TCP/UDP traffic read, in bytes.",
			[]string{"status_path"}, nil),
		"TCP/UDP write bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "tcp_udp_write_bytes_total"),
			"Total amount of TCP/UDP traffic written, in bytes.",
			[]string{"status_path"}, nil),
		"Auth read bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "auth_read_bytes_total"),
			"Total amount of authentication traffic read, in bytes.",
			[]string{"status_path"}, nil),
		"pre-compress bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "pre_compress_bytes_total"),
			"Total amount of data before compression, in bytes.",
			[]string{"status_path"}, nil),
		"post-compress bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "post_compress_bytes_total"),
			"Total amount of data after compression, in bytes.",
			[]string{"status_path"}, nil),
		"pre-decompress bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "pre_decompress_bytes_total"),
			"Total amount of data before decompression, in bytes.",
			[]string{"status_path"}, nil),
		"post-decompress bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "post_decompress_bytes_total"),
			"Total amount of data after decompression, in bytes.",
			[]string{"status_path"}, nil),
	}

	var serverHeaderClientLabels []string
	var serverHeaderClientLabelColumns []string
	var serverHeaderRoutingLabels []string
	var serverHeaderRoutingLabelColumns []string
	if ignoreIndividuals {
		serverHeaderClientLabels = []string{"status_path", "common_name"}
		serverHeaderClientLabelColumns = []string{"Common Name"}
		serverHeaderRoutingLabels = []string{"status_path", "common_name"}
		serverHeaderRoutingLabelColumns = []string{"Common Name"}
	} else {
		serverHeaderClientLabels = []string{"status_path", "common_name", "connection_time", "real_address", "virtual_address", "username"}
		serverHeaderClientLabelColumns = []string{"Common Name", "Connected Since (time_t)", "Real Address", "Virtual Address", "Username"}
		serverHeaderRoutingLabels = []string{"status_path", "common_name", "real_address", "virtual_address"}
		serverHeaderRoutingLabelColumns = []string{"Common Name", "Real Address", "Virtual Address"}
	}

	openvpnServerHeaders := map[string]OpenvpnServerHeader{
		"CLIENT_LIST": {
			LabelColumns: serverHeaderClientLabelColumns,
			Metrics: []OpenvpnServerHeaderField{
				{
					Column: "Bytes Received",
					Desc: prometheus.NewDesc(
						prometheus.BuildFQName("openvpn", "server", "client_received_bytes_total"),
						"Amount of data received over a connection on the VPN server, in bytes.",
						serverHeaderClientLabels, nil),
					ValueType: prometheus.CounterValue,
				},
				{
					Column: "Bytes Sent",
					Desc: prometheus.NewDesc(
						prometheus.BuildFQName("openvpn", "server", "client_sent_bytes_total"),
						"Amount of data sent over a connection on the VPN server, in bytes.",
						serverHeaderClientLabels, nil),
					ValueType: prometheus.CounterValue,
				},
			},
		},
		"ROUTING_TABLE": {
			LabelColumns: serverHeaderRoutingLabelColumns,
			Metrics: []OpenvpnServerHeaderField{
				{
					Column: "Last Ref",
					Desc: prometheus.NewDesc(
						prometheus.BuildFQName("openvpn", "server", "route_last_reference_time_seconds"),
						"Time at which a route was last referenced, in seconds.",
						serverHeaderRoutingLabels, nil),
					ValueType: prometheus.GaugeValue,
				},
			},
		},
	}

	return &OpenVPNExporter{
		statusPaths:                 statusPaths,
		openvpnUpDesc:               openvpnUpDesc,
		openvpnStatusUpdateTimeDesc: openvpnStatusUpdateTimeDesc,
		openvpnConnectedClientsDesc: openvpnConnectedClientsDesc,
		openvpnClientDescs:          openvpnClientDescs,
		openvpnServerHeaders:        openvpnServerHeaders,
	}, nil
}

// Converts OpenVPN status information into Prometheus metrics. This
// function automatically detects whether the file contains server or
// client metrics. For server metrics, it also distinguishes between the
// version 2 and 3 file formats.
func (e *OpenVPNExporter) collectStatusFromReader(statusPath string, file io.Reader, ch chan<- prometheus.Metric) error {
	reader := bufio.NewReader(file)
	buf, _ := reader.Peek(18)
	if bytes.HasPrefix(buf, []byte("TITLE,")) {
		// Server statistics, using format version 2.
		return e.collectServerStatusFromReader(statusPath, reader, ch, ",")
	} else if bytes.HasPrefix(buf, []byte("TITLE\t")) {
		// Server statistics, using format version 3. The only
		// difference compared to version 2 is that it uses tabs
		// instead of spaces.
		return e.collectServerStatusFromReader(statusPath, reader, ch, "\t")
	} else if bytes.HasPrefix(buf, []byte("OpenVPN CLIENT")) {
		// Server statistics, using format version 3. The only
		// difference compared to version 2 is that it uses tabs
		// instead of spaces.
		return e.collectServerStatusFromReader(statusPath, reader, ch, ",")
	} else if bytes.HasPrefix(buf, []byte("OpenVPN STATISTICS")) {
		// Client statistics.
		return e.collectClientStatusFromReader(statusPath, reader, ch)
	} else {
		return fmt.Errorf("unexpected file contents: %q", buf)
	}
}

// Converts OpenVPN server status information into Prometheus metrics.
func (e *OpenVPNExporter) collectServerStatusFromReader(statusPath string, file io.Reader, ch chan<- prometheus.Metric, separator string) error {
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	headersFound := map[string][]string{}
	// counter of connected client
	numberConnectedClient := 0

	recordedMetrics := map[OpenvpnServerHeaderField][]string{}

	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), separator)
		if (fields[0] == "END" && len(fields) == 1) || (fields[0] == "GLOBAL_STATS" || fields[0] == "GLOBAL STATS") || (strings.HasPrefix(fields[0], "Max bcast")) || (fields[0] == "OpenVPN CLIENT LIST") || (fields[0] == "ROUTING TABLE") {
			// Skip
			continue
		} else if fields[0] == "TITLE" && len(fields) == 2 {
			// Skip
			// OpenVPN version number.
			continue
		} else if fields[0] == "Common Name" && len(fields) > 2 {
			// Column names for CLIENT_LIST and ROUTING_TABLE.
			headersFound["CLIENT_LIST"] = fields[:]
			continue
		} else if fields[0] == "Virtual Address" && len(fields) > 2 {
			headersFound["ROUTING_TABLE"] = fields[:]
			continue
		} else if fields[0] == "Updated" && len(fields) == 2 {
			timeStartStats, err := transferDateStringToFloat64(fields[1])
			if err != nil {
				return err
			}
			ch <- prometheus.MustNewConstMetric(
				e.openvpnStatusUpdateTimeDesc,
				prometheus.GaugeValue,
				timeStartStats,
				statusPath,
			)
			continue
		}
		//  else {
		// 	return fmt.Errorf("unsupported key: %q", fields[0])
		// }
		{

			columnKey := "CLIENT_LIST"
			if isIPV4(fields[0]) {
				numberConnectedClient++
				columnKey = "ROUTING_TABLE"
			}

			if isIPV6(fields[0]) {
				numberConnectedClient++
				columnKey = "ROUTING_TABLE"
			}

			header, ok := e.openvpnServerHeaders[columnKey]
			if !ok {
				return fmt.Errorf("unsupported key: %q %v", fields[0], columnKey)
			}

			// Entry that depends on a preceding HEADERS directive.
			columnNames, ok := headersFound[columnKey]
			if !ok {
				// return fmt.Errorf("%s should be preceded by HEADERS", columnKey)
				continue
			}
			// if len(fields) != len(columnNames)+1 {
			// 	return fmt.Errorf("HEADER for %s describes a different number of columns", columnKey)
			// }

			// Store entry values in a map indexed by column name.
			columnValues := map[string]string{}
			for _, column := range header.LabelColumns {
				columnValues[column] = ""
			}
			for i, column := range columnNames {
				// columnValues[column] = fields[i+1]
				columnValues[column] = fields[i]
			}

			// Extract columns that should act as entry labels.
			labels := []string{statusPath}
			for _, column := range header.LabelColumns {
				labels = append(labels, columnValues[column])
			}

			// Export relevant columns as individual metrics.
			for _, metric := range header.Metrics {
				if columnValue, ok := columnValues[metric.Column]; ok {
					if l, _ := recordedMetrics[metric]; !subslice(labels, l) {
						value, err := strconv.ParseFloat(columnValue, 64)
						if err != nil {
							value, err = transferDateStringToFloat64(columnValue)
							if err != nil {
								return err
							}
						}
						ch <- prometheus.MustNewConstMetric(
							metric.Desc,
							metric.ValueType,
							value,
							labels...,
						)
						recordedMetrics[metric] = append(recordedMetrics[metric], labels...)
					} else {
						log.Printf("Metric entry with same labels: %s, %s", metric.Column, labels)
					}
				}
			}
		}
	}

	// add the number of connected client
	ch <- prometheus.MustNewConstMetric(
		e.openvpnConnectedClientsDesc,
		prometheus.GaugeValue,
		float64(numberConnectedClient),
		statusPath,
	)
	return scanner.Err()
}

// Does slice contain string
func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// Is a sub-slice of slice
func subslice(sub []string, main []string) bool {
	if len(sub) > len(main) {
		return false
	}
	for _, s := range sub {
		if !contains(main, s) {
			return false
		}
	}
	return true
}

// Converts OpenVPN client status information into Prometheus metrics.
func (e *OpenVPNExporter) collectClientStatusFromReader(statusPath string, file io.Reader, ch chan<- prometheus.Metric) error {
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ",")
		if fields[0] == "END" && len(fields) == 1 {
			// Stats footer.
		} else if fields[0] == "OpenVPN STATISTICS" && len(fields) == 1 {
			// Stats header.
		} else if fields[0] == "Updated" && len(fields) == 2 {
			// Time at which the statistics were updated.
			location, _ := time.LoadLocation("Local")
			timeParser, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", fields[1], location)
			if err != nil {
				return err
			}
			ch <- prometheus.MustNewConstMetric(
				e.openvpnStatusUpdateTimeDesc,
				prometheus.GaugeValue,
				float64(timeParser.Unix()),
				statusPath)
		} else if desc, ok := e.openvpnClientDescs[fields[0]]; ok && len(fields) == 2 {
			// Traffic counters.
			value, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				return err
			}
			ch <- prometheus.MustNewConstMetric(
				desc,
				prometheus.CounterValue,
				value,
				statusPath)
		} else {
			return fmt.Errorf("unsupported key: %q", fields[0])
		}
	}
	return scanner.Err()
}

func (e *OpenVPNExporter) collectStatusFromFile(statusPath string, ch chan<- prometheus.Metric) error {
	conn, err := os.Open(statusPath)
	defer conn.Close()
	if err != nil {
		return err
	}
	return e.collectStatusFromReader(statusPath, conn, ch)
}

func (e *OpenVPNExporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.openvpnUpDesc
}

func (e *OpenVPNExporter) Collect(ch chan<- prometheus.Metric) {
	for _, statusPath := range e.statusPaths {
		err := e.collectStatusFromFile(statusPath, ch)
		if err == nil {
			ch <- prometheus.MustNewConstMetric(
				e.openvpnUpDesc,
				prometheus.GaugeValue,
				1.0,
				statusPath)
		} else {
			log.Printf("Failed to scrape showq socket: %s", err)
			ch <- prometheus.MustNewConstMetric(
				e.openvpnUpDesc,
				prometheus.GaugeValue,
				0.0,
				statusPath)
		}
	}
}

func transferDateStringToFloat64(ds string) (float64, error) {
	t, err := time.Parse(time.DateTime, ds)
	if err != nil {
		return 0, err
	}

	return float64(t.Unix()), nil
}

func isIPV4(ipStr string) bool {
	return ipv4Regex.MatchString(ipStr)
}

func isIPV6(ipStr string) bool {
	return ipv6Regex.MatchString(ipStr)
}
