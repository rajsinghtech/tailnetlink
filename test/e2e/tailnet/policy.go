package tailnet

import _ "embed"

// Policy is the tailnet policy every CI tailnet gets. It defines the tags
// the tests use, lets tailnetlink reach test backends, lets test clients
// reach services tailnetlink creates (they carry tag:tailnetlink), and
// auto-approves tailnetlink nodes as hosts for those services.
//
//go:embed policy.hujson
var Policy []byte
