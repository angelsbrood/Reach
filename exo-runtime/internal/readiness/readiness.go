// Package readiness validates the exact two-rank EXO state admitted by S47.
package readiness

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"reach.dev/exo-runtime/internal/authority"
)

type State struct {
	Topology       Topology                              `json:"topology"`
	NodeIdentities map[string]NodeIdentity               `json:"nodeIdentities"`
	NodeBackends   map[string][]string                   `json:"nodeBackends"`
	NodeNetwork    map[string]NodeNetwork                `json:"nodeNetwork"`
	Instances      map[string]json.RawMessage            `json:"instances"`
	Runners        map[string]map[string]json.RawMessage `json:"runners"`
	Tasks          map[string]json.RawMessage            `json:"tasks"`
}

type Topology struct {
	Nodes       []string                                 `json:"nodes"`
	Connections map[string]map[string][]SocketConnection `json:"connections"`
}

type NodeIdentity struct {
	FriendlyName string `json:"friendlyName"`
}

type NodeNetwork struct {
	Interfaces []NetworkInterface `json:"interfaces"`
}

type NetworkInterface struct {
	Name      string `json:"name"`
	IPAddress string `json:"ipAddress"`
}

type SocketConnection struct {
	Sink MultiAddress `json:"sinkMultiaddr"`
}

type MultiAddress struct {
	AddressType string `json:"address_type"`
	IPAddress   string `json:"ip_address"`
	Port        int    `json:"port"`
}

type ExpectedCluster struct {
	CoordinatorName    string
	WorkerName         string
	CoordinatorAddress string
	WorkerAddress      string
	Interface          string
	CoordinatorRange   LayerRange
	WorkerRange        LayerRange
}

type LayerRange struct {
	Start int
	End   int
}

type Result struct {
	CoordinatorNodeID string
	WorkerNodeID      string
	InstanceID        string
	RunnerIDs         []string
	StateSHA256       string
}

type ringInstance struct {
	InstanceID       string           `json:"instanceId"`
	ShardAssignments shardAssignments `json:"shardAssignments"`
}

type shardAssignments struct {
	ModelID       string                      `json:"modelId"`
	RunnerToShard map[string]map[string]shard `json:"runnerToShard"`
	NodeToRunner  map[string]string           `json:"nodeToRunner"`
}

type shard struct {
	DeviceRank int `json:"deviceRank"`
	WorldSize  int `json:"worldSize"`
	StartLayer int `json:"startLayer"`
	EndLayer   int `json:"endLayer"`
	NLayers    int `json:"nLayers"`
}

func Decode(data []byte) (State, error) {
	var state State
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&state); err != nil {
		return State{}, err
	}
	return state, nil
}

func Baseline(state State, expected ExpectedCluster) (map[string]string, error) {
	nodes, err := exactNodes(state, expected)
	if err != nil {
		return nil, err
	}
	if err := exactConnections(state, nodes, expected); err != nil {
		return nil, err
	}
	if len(state.Instances) != 0 || len(state.Runners) != 0 || len(state.Tasks) != 0 {
		return nil, errors.New("fresh baseline contains instance, runner, or task state")
	}
	return nodes, nil
}

func Ready(data []byte, expected ExpectedCluster, requireNoGeneration bool) (Result, error) {
	return validate(data, expected, requireNoGeneration, false)
}

// Live validates an already-published epoch while admitting the one
// generation Reach's provider slot may own. EXO moves each exact runner from
// RunnerReady to RunnerRunning during prefill and decode; that transition is
// work, not topology drift. Structural authority remains exact, unknown runner
// states refuse, and a second active generation withdraws publication.
func Live(data []byte, expected ExpectedCluster) (Result, error) {
	return validate(data, expected, false, true)
}

func validate(data []byte, expected ExpectedCluster, requireNoGeneration, allowRunning bool) (Result, error) {
	state, err := Decode(data)
	if err != nil {
		return Result{}, err
	}
	nodes, err := exactNodes(state, expected)
	if err != nil {
		return Result{}, err
	}
	if err := exactConnections(state, nodes, expected); err != nil {
		return Result{}, err
	}
	if len(state.Instances) != 1 {
		return Result{}, fmt.Errorf("instance count is %d, want 1", len(state.Instances))
	}
	if len(state.Runners) != 2 {
		return Result{}, fmt.Errorf("runner count is %d, want 2", len(state.Runners))
	}
	for id, status := range state.Runners {
		if len(status) != 1 {
			return Result{}, fmt.Errorf("runner %s has ambiguous status", id)
		}
		_, ready := status["RunnerReady"]
		_, running := status["RunnerRunning"]
		if !ready && !(allowRunning && running) {
			return Result{}, fmt.Errorf("runner %s is neither ready nor admitted running", id)
		}
	}
	activeGenerations := 0
	for id, raw := range state.Tasks {
		var tagged map[string]json.RawMessage
		if err := json.Unmarshal(raw, &tagged); err != nil || len(tagged) != 1 {
			return Result{}, fmt.Errorf("epoch task %s has invalid tagged representation", id)
		}
		if _, ok := tagged["TextGeneration"]; ok {
			activeGenerations++
			if requireNoGeneration {
				return Result{}, fmt.Errorf("fresh epoch task %s contains prior generation work", id)
			}
		}
	}
	if activeGenerations > 1 {
		return Result{}, fmt.Errorf("active generation task count is %d, want at most 1", activeGenerations)
	}
	var instanceID string
	var instance ringInstance
	for id, raw := range state.Instances {
		instanceID = id
		var tagged map[string]json.RawMessage
		if err := json.Unmarshal(raw, &tagged); err != nil || len(tagged) != 1 {
			return Result{}, errors.New("instance has invalid tagged representation")
		}
		ring, ok := tagged["MlxRingInstance"]
		if !ok {
			return Result{}, errors.New("instance is not MlxRingInstance")
		}
		if err := json.Unmarshal(ring, &instance); err != nil {
			return Result{}, err
		}
	}
	if instance.InstanceID != instanceID || instance.ShardAssignments.ModelID != authority.ModelID {
		return Result{}, errors.New("instance identity or model does not match authority")
	}
	assignments := instance.ShardAssignments
	if len(assignments.NodeToRunner) != 2 || len(assignments.RunnerToShard) != 2 {
		return Result{}, errors.New("instance must own exactly two node and runner assignments")
	}
	shardExpected := map[string]struct{ rank, start, end int }{
		nodes[expected.CoordinatorName]: {rank: expected.CoordinatorRange.Start / 14, start: expected.CoordinatorRange.Start, end: expected.CoordinatorRange.End},
		nodes[expected.WorkerName]:      {rank: expected.WorkerRange.Start / 14, start: expected.WorkerRange.Start, end: expected.WorkerRange.End},
	}
	runnerIDs := make([]string, 0, 2)
	for nodeID, expectation := range shardExpected {
		runnerID, ok := assignments.NodeToRunner[nodeID]
		if !ok {
			return Result{}, fmt.Errorf("node %s has no runner", nodeID)
		}
		tagged, ok := assignments.RunnerToShard[runnerID]
		if !ok || len(tagged) != 1 {
			return Result{}, fmt.Errorf("runner %s has no exact shard", runnerID)
		}
		value, ok := tagged["PipelineShardMetadata"]
		if !ok {
			return Result{}, fmt.Errorf("runner %s is not pipeline sharded", runnerID)
		}
		if value.DeviceRank != expectation.rank || value.WorldSize != 2 || value.StartLayer != expectation.start || value.EndLayer != expectation.end || value.NLayers != authority.ModelLayerCount {
			return Result{}, fmt.Errorf("runner %s has wrong global range", runnerID)
		}
		runnerIDs = append(runnerIDs, runnerID)
	}
	sort.Strings(runnerIDs)
	digest := sha256.Sum256(data)
	return Result{
		CoordinatorNodeID: nodes[expected.CoordinatorName],
		WorkerNodeID:      nodes[expected.WorkerName],
		InstanceID:        instanceID,
		RunnerIDs:         runnerIDs,
		StateSHA256:       hex.EncodeToString(digest[:]),
	}, nil
}

func exactNodes(state State, expected ExpectedCluster) (map[string]string, error) {
	if len(state.Topology.Nodes) != 2 || len(state.NodeIdentities) != 2 || len(state.NodeBackends) != 2 {
		return nil, errors.New("state does not contain exactly two topology identities and backends")
	}
	wanted := map[string]bool{expected.CoordinatorName: false, expected.WorkerName: false}
	nodes := make(map[string]string, 2)
	seenTopology := make(map[string]bool, 2)
	for _, id := range state.Topology.Nodes {
		if id == "" || seenTopology[id] {
			return nil, errors.New("topology node identifiers are empty or duplicated")
		}
		seenTopology[id] = true
		identity, ok := state.NodeIdentities[id]
		if !ok {
			return nil, fmt.Errorf("node %s lacks identity", id)
		}
		if _, ok := wanted[identity.FriendlyName]; !ok || wanted[identity.FriendlyName] {
			return nil, fmt.Errorf("unexpected or duplicate friendly name %q", identity.FriendlyName)
		}
		wanted[identity.FriendlyName] = true
		nodes[identity.FriendlyName] = id
		backends, ok := state.NodeBackends[id]
		if !ok || len(backends) != 1 || backends[0] != authority.Backend {
			return nil, fmt.Errorf("node %s backend is not exactly %s", id, authority.Backend)
		}
	}
	return nodes, nil
}

func exactConnections(state State, nodes map[string]string, expected ExpectedCluster) error {
	if len(state.NodeNetwork) != 2 || len(state.Topology.Connections) != 2 {
		return errors.New("state does not contain exactly two node-network and connection sources")
	}
	type endpoint struct {
		sourceName string
		sinkName   string
		sinkIPv4   string
	}
	for _, pair := range []endpoint{
		{sourceName: expected.CoordinatorName, sinkName: expected.WorkerName, sinkIPv4: expected.WorkerAddress},
		{sourceName: expected.WorkerName, sinkName: expected.CoordinatorName, sinkIPv4: expected.CoordinatorAddress},
	} {
		sourceID, sinkID := nodes[pair.sourceName], nodes[pair.sinkName]
		outbound, ok := state.Topology.Connections[sourceID]
		if !ok || len(outbound) != 1 {
			return fmt.Errorf("node %s does not have one exact topology sink", sourceID)
		}
		edges, ok := outbound[sinkID]
		if !ok || len(edges) == 0 {
			return fmt.Errorf("node %s lacks an edge to exact peer %s", sourceID, sinkID)
		}
		advertised := make(map[string]bool)
		for _, value := range state.NodeNetwork[sinkID].Interfaces {
			if value.Name == expected.Interface {
				advertised[value.IPAddress] = true
			}
		}
		if !advertised[pair.sinkIPv4] {
			return fmt.Errorf("node %s does not advertise configured private address", sinkID)
		}
		foundIPv4 := false
		for _, edge := range edges {
			if edge.Sink.Port != authority.ProviderAPIPort || !advertised[edge.Sink.IPAddress] {
				return fmt.Errorf("node %s has a widened or drifted topology edge", sourceID)
			}
			if edge.Sink.AddressType != "ip4" && edge.Sink.AddressType != "ip6" {
				return fmt.Errorf("node %s has an invalid topology address type", sourceID)
			}
			if edge.Sink.AddressType == "ip4" && edge.Sink.IPAddress == pair.sinkIPv4 {
				foundIPv4 = true
			}
		}
		if !foundIPv4 {
			return fmt.Errorf("node %s lacks the configured private IPv4 topology edge", sourceID)
		}
	}
	return nil
}
