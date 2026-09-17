package option

import (
	"context"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/require"
)

func TestDirectRuleKeepsDurationFallbackDelay(t *testing.T) {
	for _, content := range []string{
		`{"action":"direct","fallback_delay":"500ms","network_strategy":"fallback"}`,
		`{"type":"logical","mode":"and","rules":[{"domain":"example.com"}],"action":"direct","fallback_delay":"500ms","network_strategy":"fallback"}`,
	} {
		var rule Rule
		err := json.UnmarshalContext(context.Background(), []byte(content), &rule)
		require.NoError(t, err)
		action := rule.DefaultOptions.RuleAction
		if rule.Type == C.RuleTypeLogical {
			action = rule.LogicalOptions.RuleAction
		}
		require.Equal(t, C.RuleActionTypeDirect, action.Action)
		require.Equal(t, 500*time.Millisecond, time.Duration(action.DirectOptions.FallbackDelay))
	}
}

func TestDirectRuleStillRejectsUnsupportedAndNestedOptions(t *testing.T) {
	for _, content := range []string{
		`{"action":"direct","detour":"other"}`,
		`{"action":"direct","udp_timeout":"10s"}`,
		`{"action":"direct","fallback_delay":500}`,
		`{"type":"logical","mode":"and","rules":[{"action":"direct","fallback_delay":"500ms"}]}`,
	} {
		var rule Rule
		require.Error(t, json.UnmarshalContext(context.Background(), []byte(content), &rule))
	}
}
