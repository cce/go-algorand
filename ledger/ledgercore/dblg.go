package ledgercore

import (
	"fmt"
	"os"
	"strings"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
)

var addressesToLog = map[basics.Address]bool{}
var dbLogger = logging.Base()

func init() {
	for _, addr := range strings.Split(os.Getenv("LOG_ADDRESSES"), ",") {
		a, err := basics.UnmarshalChecksumAddress(addr)
		if err != nil {
			fmt.Println("ignoring invalid LOG_ADDRESSES address", addr)
			continue
		}
		addressesToLog[a] = true
	}
}

func DBlog(fn string, addr basics.Address, args ...interface{}) {
	if !addressesToLog[addr] {
		return
	}

	if len(args)%2 != 0 {
		panic(fmt.Sprintf("DBlog called with odd number of args: %+v", args))
	}

	kvs := logging.Fields{"addr": addr.String()}
	for i := 0; i < len(args); i += 2 {
		k := args[i].(string) // msut be a string
		kvs[k] = args[i+1]
	}
	dbLogger.WithFields(kvs).Warn(fn)
}
