// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"time"
)

// Pipeline is a stored, re-runnable ETL definition (spec is the raw JSON body).
type Pipeline struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Spec    string `json:"spec"`
	Created int64  `json:"created"`
	Updated int64  `json:"updated"`
}

// PipelineRun is one execution of a pipeline.
type PipelineRun struct {
	ID       string `json:"id"`
	Pipeline string `json:"pipeline_id"`
	Status   string `json:"status"` // running | success | failed | error
	Started  int64  `json:"started"`
	Finished int64  `json:"finished"`
	Tables   int    `json:"tables"`
	Tests    string `json:"tests"`         // JSON array of results
	Log      string `json:"log,omitempty"` // captured run log
}

func (s *Store) CreatePipeline(userID int64, name, spec string) (Pipeline, error) {
	id := randToken(8)
	now := time.Now().Unix()
	if _, err := s.db.Exec(`INSERT INTO pipelines(id,user_id,name,spec,created,updated) VALUES(?,?,?,?,?,?)`,
		id, userID, name, spec, now, now); err != nil {
		return Pipeline{}, err
	}
	return Pipeline{ID: id, Name: name, Spec: spec, Created: now, Updated: now}, nil
}

func (s *Store) ListPipelines(userID int64) ([]Pipeline, error) {
	rows, err := s.db.Query(`SELECT id,name,spec,created,updated FROM pipelines WHERE user_id=? ORDER BY updated DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Pipeline
	for rows.Next() {
		var p Pipeline
		if err := rows.Scan(&p.ID, &p.Name, &p.Spec, &p.Created, &p.Updated); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetPipeline(id string, userID int64) (Pipeline, bool) {
	var p Pipeline
	err := s.db.QueryRow(`SELECT id,name,spec,created,updated FROM pipelines WHERE id=? AND user_id=?`, id, userID).
		Scan(&p.ID, &p.Name, &p.Spec, &p.Created, &p.Updated)
	if err != nil {
		return Pipeline{}, false
	}
	return p, true
}

func (s *Store) UpdatePipeline(id string, userID int64, name, spec string) error {
	res, err := s.db.Exec(`UPDATE pipelines SET name=?, spec=?, updated=? WHERE id=? AND user_id=?`,
		name, spec, time.Now().Unix(), id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("pipeline not found")
	}
	return nil
}

func (s *Store) DeletePipeline(id string, userID int64) error {
	_, err := s.db.Exec(`DELETE FROM pipelines WHERE id=? AND user_id=?`, id, userID)
	return err
}

// StartRun records a run in progress and returns its id.
func (s *Store) StartRun(pipelineID string, userID int64) (string, error) {
	id := randToken(8)
	_, err := s.db.Exec(`INSERT INTO pipeline_runs(id,pipeline_id,user_id,status,started) VALUES(?,?,?,?,?)`,
		id, pipelineID, userID, "running", time.Now().Unix())
	return id, err
}

// FinishRun records a run's terminal state.
func (s *Store) FinishRun(id, status string, tables int, tests, log string) error {
	_, err := s.db.Exec(`UPDATE pipeline_runs SET status=?, finished=?, tables=?, tests=?, log=? WHERE id=?`,
		status, time.Now().Unix(), tables, tests, log, id)
	return err
}

func (s *Store) ListRuns(pipelineID string, userID int64) ([]PipelineRun, error) {
	rows, err := s.db.Query(`SELECT id,pipeline_id,status,started,COALESCE(finished,0),tables,tests `+
		`FROM pipeline_runs WHERE pipeline_id=? AND user_id=? ORDER BY started DESC LIMIT 50`, pipelineID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PipelineRun
	for rows.Next() {
		var r PipelineRun
		if err := rows.Scan(&r.ID, &r.Pipeline, &r.Status, &r.Started, &r.Finished, &r.Tables, &r.Tests); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// A pipeline run replaces its target branch, so it may only replace a branch
// it made. pipeline_targets records which pipeline made which branch: without
// it, naming a pipeline after someone else's branch and running it deleted that
// branch.

// ClaimPipelineTarget records that pipelineID's runs write to branch. It fails
// when another pipeline already holds that branch.
func (s *Store) ClaimPipelineTarget(pipelineID, branch string) error {
	res, err := s.db.Exec(`INSERT INTO pipeline_targets(branch, pipeline_id) VALUES(?,?)
		ON CONFLICT(branch) DO UPDATE SET pipeline_id=excluded.pipeline_id WHERE pipeline_targets.pipeline_id=excluded.pipeline_id`,
		branch, pipelineID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("that branch belongs to another pipeline")
	}
	return nil
}

// PipelineOwnsTarget reports whether pipelineID's runs made branch.
func (s *Store) PipelineOwnsTarget(pipelineID, branch string) bool {
	var owner string
	err := s.db.QueryRow(`SELECT pipeline_id FROM pipeline_targets WHERE branch=?`, branch).Scan(&owner)
	return err == nil && owner == pipelineID
}
