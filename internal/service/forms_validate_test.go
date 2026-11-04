package service

import (
	"strings"
	"testing"

	"github.com/cdpg/dx/apd-go/internal/domain"
)

func validBody() domain.CreateFormSubmissionBody {
	return domain.CreateFormSubmissionBody{
		NumServerRounds: float64(10), LocalEpochs: float64(1),
		LearningRate: 0.01, BatchSize: float64(32),
	}
}

func TestValidateTrainingParams(t *testing.T) {
	if err := ValidateTrainingParams(validBody()); err != nil {
		t.Fatalf("valid body rejected: %v", err)
	}
	edge := validBody()
	edge.NumServerRounds, edge.LocalEpochs, edge.LearningRate, edge.BatchSize, edge.MinVCPUs = "100", float64(5), float64(1), float64(1024), float64(1)
	if err := ValidateTrainingParams(edge); err != nil {
		t.Fatalf("edge values rejected: %v", err)
	}

	cases := []struct {
		field string
		set   func(*domain.CreateFormSubmissionBody)
	}{
		{"num_server_rounds", func(b *domain.CreateFormSubmissionBody) { b.NumServerRounds = float64(0) }},
		{"num_server_rounds", func(b *domain.CreateFormSubmissionBody) { b.NumServerRounds = float64(101) }},
		{"num_server_rounds", func(b *domain.CreateFormSubmissionBody) { b.NumServerRounds = 2.5 }},
		{"num_server_rounds", func(b *domain.CreateFormSubmissionBody) { b.NumServerRounds = nil }},
		{"local_epochs", func(b *domain.CreateFormSubmissionBody) { b.LocalEpochs = float64(99) }},
		{"learning_rate", func(b *domain.CreateFormSubmissionBody) { b.LearningRate = float64(5) }},
		{"learning_rate", func(b *domain.CreateFormSubmissionBody) { b.LearningRate = float64(0) }},
		{"learning_rate", func(b *domain.CreateFormSubmissionBody) { b.LearningRate = "abc" }},
		{"batch_size", func(b *domain.CreateFormSubmissionBody) { b.BatchSize = float64(0) }},
		{"batch_size", func(b *domain.CreateFormSubmissionBody) { b.BatchSize = float64(2048) }},
		{"min_vcpus", func(b *domain.CreateFormSubmissionBody) { b.MinVCPUs = float64(0) }},
		{"min_vcpus", func(b *domain.CreateFormSubmissionBody) { b.MinVCPUs = 1.5 }},
	}
	for _, c := range cases {
		b := validBody()
		c.set(&b)
		err := ValidateTrainingParams(b)
		if err == nil || !strings.HasPrefix(err.Error(), c.field) {
			t.Errorf("want %s error, got %v", c.field, err)
		}
	}
}
