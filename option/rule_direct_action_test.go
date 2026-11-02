package option

import (
	"context"
	"testing"

	"github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/require"
)

func TestRemovedDirectRuleIsRejected(t *testing.T) {
	for _, content := range []string{
		`{"action":"direct"}`,
		`{"action":"direct","fallback_delay":"500ms"}`,
		`{"action":"direct","udp_timeout":"10s"}`,
		`{"action":"direct","fallback_delay":500}`,
		`{"type":"logical","mode":"and","rules":[{"action":"direct","fallback_delay":"500ms"}]}`,
	} {
		var rule Rule
		require.Error(t, json.UnmarshalContext(context.Background(), []byte(content), &rule))
	}
}
