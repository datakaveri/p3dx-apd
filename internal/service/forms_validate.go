package service

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/cdpg/dx/apd-go/internal/domain"
)

// ValidateTrainingParams range-checks an FL output-owner submission's
// training parameters before it is stored. The ranges match the UI form
// (p3dx-auth-ui FederatedLearning.jsx) and gov_layer's
// contract.FLRunConfig.Validate, so a submission APD accepts always builds a
// valid contract: num_server_rounds 1-100, local_epochs 1-5 and batch_size
// 1-1024 (integers), 0 < learning_rate <= 1, and min_vcpus (optional) an
// integer >= 1.
func ValidateTrainingParams(body domain.CreateFormSubmissionBody) error {
	checks := []struct {
		field    string
		v        interface{}
		required bool
		integer  bool
		ok       func(float64) bool
		want     string
	}{
		{"num_server_rounds", body.NumServerRounds, true, true, func(n float64) bool { return n >= 1 && n <= 100 }, "an integer between 1 and 100"},
		{"local_epochs", body.LocalEpochs, true, true, func(n float64) bool { return n >= 1 && n <= 5 }, "an integer between 1 and 5"},
		{"learning_rate", body.LearningRate, true, false, func(n float64) bool { return n > 0 && n <= 1 }, "a number greater than 0 and at most 1"},
		{"batch_size", body.BatchSize, true, true, func(n float64) bool { return n >= 1 && n <= 1024 }, "an integer between 1 and 1024"},
		{"min_vcpus", body.MinVCPUs, false, true, func(n float64) bool { return n >= 1 }, "an integer of at least 1"},
	}
	for _, c := range checks {
		n, present, err := paramNumber(c.v)
		if !present {
			if c.required {
				return fmt.Errorf("%s is required (%s)", c.field, c.want)
			}
			continue
		}
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) ||
			(c.integer && n != math.Trunc(n)) || !c.ok(n) {
			return fmt.Errorf("%s must be %s, got %v", c.field, c.want, c.v)
		}
	}
	return nil
}

// paramNumber reads a JSON number or numeric string. present is false for an
// absent/null field or an empty string.
func paramNumber(v interface{}) (n float64, present bool, err error) {
	switch t := v.(type) {
	case nil:
		return 0, false, nil
	case float64:
		return t, true, nil
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0, false, nil
		}
		n, err := strconv.ParseFloat(s, 64)
		return n, true, err
	default:
		return 0, true, fmt.Errorf("not a number")
	}
}
