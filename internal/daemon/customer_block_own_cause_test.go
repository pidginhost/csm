package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
)

// The cause's customer must be excluded before counting and sampling a
// subnet, even when that login falls outside the displayed examples.
func TestCustomerBlockSubnetExcludesOwnCauseBeforeSampling(t *testing.T) {
	for _, causeIndex := range []int{0, 6} {
		t.Run(fmt.Sprintf("cause_at_%d", causeIndex), func(t *testing.T) {
			at := time.Now().Add(-time.Hour)
			d := &Daemon{knownCustomers: newKnownCustomers(time.Now)}
			var customers []blockdigest.CustomerHit
			for i := range 7 {
				ip := fmt.Sprintf("198.51.100.%d", i+1)
				account := fmt.Sprintf("user%d@example.com", i+1)
				loginAt := at.Add(time.Duration(i) * time.Minute)
				d.knownCustomers.Note(ip, knownCustomerIMAP, account, loginAt, syslogFed)
				customers = append(customers, blockdigest.CustomerHit{IP: ip, Kind: knownCustomerIMAP, Account: account, At: loginAt})
			}
			own := customers[causeIndex]
			finding := alert.Finding{Check: "mail_account_compromised", Severity: alert.Critical,
				SourceIP: own.IP, Mailbox: own.Account, Timestamp: own.At,
				Message: "Mail account compromise: " + own.Account + " from " + own.IP}
			cause := alert.CauseOf(finding)
			notice := alert.Finding{Check: "auto_block", Severity: alert.Critical, Cause: &cause,
				Message: "AUTO-NETBLOCK: 198.51.100.0/24 blocked"}
			blocks := d.customerBlocks([]alert.Finding{finding, notice})
			if len(blocks) != 1 {
				t.Fatalf("customer blocks = %+v, want the other customers alerted", blocks)
			}
			b := blocks[0]
			if len(b.Hits) != 5 || b.More != 1 {
				t.Fatalf("customer block = %+v, want five examples and one more customer", b)
			}
			position := 0
			for i := len(customers) - 1; i >= 0 && position < len(b.Hits); i-- {
				if i == causeIndex {
					continue
				}
				if b.Hits[position] != customers[i] {
					t.Errorf("example %d = %+v, want %+v", position, b.Hits[position], customers[i])
				}
				position++
			}
		})
	}
}
