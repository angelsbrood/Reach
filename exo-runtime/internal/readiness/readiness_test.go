package readiness

import (
	"encoding/json"
	"testing"

	"reach.dev/exo-runtime/internal/authority"
)

func readyFixture() []byte {
	state := map[string]any{
		"topology": map[string]any{
			"nodes": []string{"node-a-id", "node-b-id"},
			"connections": map[string]any{
				"node-a-id": map[string]any{"node-b-id": []any{map[string]any{"sinkMultiaddr": map[string]any{"address_type": "ip4", "ip_address": "192.168.108.3", "port": 52415}}}},
				"node-b-id": map[string]any{"node-a-id": []any{map[string]any{"sinkMultiaddr": map[string]any{"address_type": "ip4", "ip_address": "192.168.108.2", "port": 52415}}}},
			},
		},
		"nodeIdentities": map[string]any{
			"node-a-id": map[string]any{"friendlyName": "reach-exo-a"},
			"node-b-id": map[string]any{"friendlyName": "reach-exo-b"},
		},
		"nodeBackends": map[string]any{"node-a-id": []string{"MlxCpu"}, "node-b-id": []string{"MlxCpu"}},
		"nodeNetwork": map[string]any{
			"node-a-id": map[string]any{"interfaces": []any{map[string]any{"name": "eth0", "ipAddress": "192.168.108.2"}}},
			"node-b-id": map[string]any{"interfaces": []any{map[string]any{"name": "eth0", "ipAddress": "192.168.108.3"}}},
		},
		"instances": map[string]any{
			"instance-1": map[string]any{"MlxRingInstance": map[string]any{
				"instanceId": "instance-1",
				"shardAssignments": map[string]any{
					"modelId":      authority.ModelID,
					"nodeToRunner": map[string]any{"node-a-id": "runner-a", "node-b-id": "runner-b"},
					"runnerToShard": map[string]any{
						"runner-a": map[string]any{"PipelineShardMetadata": map[string]any{"deviceRank": 1, "worldSize": 2, "startLayer": 14, "endLayer": 28, "nLayers": 28}},
						"runner-b": map[string]any{"PipelineShardMetadata": map[string]any{"deviceRank": 0, "worldSize": 2, "startLayer": 0, "endLayer": 14, "nLayers": 28}},
					},
				},
			}},
		},
		"runners": map[string]any{"runner-a": map[string]any{"RunnerReady": map[string]any{}}, "runner-b": map[string]any{"RunnerReady": map[string]any{}}},
		"tasks": map[string]any{
			"warmup-a": map[string]any{"StartWarmup": map[string]any{"taskStatus": "Complete"}},
			"setup-a":  map[string]any{"CreateRunner": map[string]any{"modelCard": map[string]any{"tasks": []string{"TextGeneration"}}}},
		},
	}
	data, _ := json.Marshal(state)
	return data
}

func expectedFixture() ExpectedCluster {
	return ExpectedCluster{
		CoordinatorName: "reach-exo-a", WorkerName: "reach-exo-b",
		CoordinatorAddress: "192.168.108.2", WorkerAddress: "192.168.108.3", Interface: "eth0",
		CoordinatorRange: LayerRange{Start: 14, End: 28}, WorkerRange: LayerRange{Start: 0, End: 14},
	}
}

func TestReadyExactTopology(t *testing.T) {
	result, err := Ready(readyFixture(), expectedFixture(), true)
	if err != nil {
		t.Fatal(err)
	}
	if result.InstanceID != "instance-1" || len(result.RunnerIDs) != 2 || result.StateSHA256 == "" {
		t.Fatalf("unexpected result %#v", result)
	}
}

func TestReadyRefusesDrift(t *testing.T) {
	tests := map[string]func(map[string]any){
		"one node": func(v map[string]any) { v["topology"].(map[string]any)["nodes"] = []string{"node-a-id"} },
		"extra backend": func(v map[string]any) {
			v["nodeBackends"].(map[string]any)["node-a-id"] = []string{"MlxCpu", "MlxCuda"}
		},
		"wrong identity": func(v map[string]any) {
			v["nodeIdentities"].(map[string]any)["node-b-id"].(map[string]any)["friendlyName"] = "extra"
		},
		"missing directed edge": func(v map[string]any) {
			delete(v["topology"].(map[string]any)["connections"].(map[string]any), "node-b-id")
		},
		"wrong peer edge": func(v map[string]any) {
			edge := v["topology"].(map[string]any)["connections"].(map[string]any)["node-a-id"].(map[string]any)["node-b-id"].([]any)[0].(map[string]any)["sinkMultiaddr"].(map[string]any)
			edge["ip_address"] = "192.168.108.99"
		},
		"wrong API port": func(v map[string]any) {
			edge := v["topology"].(map[string]any)["connections"].(map[string]any)["node-a-id"].(map[string]any)["node-b-id"].([]any)[0].(map[string]any)["sinkMultiaddr"].(map[string]any)
			edge["port"] = 52416
		},
		"running runner": func(v map[string]any) {
			v["runners"].(map[string]any)["runner-a"] = map[string]any{"RunnerRunning": map[string]any{}}
		},
		"prior generation": func(v map[string]any) {
			v["tasks"].(map[string]any)["generation"] = map[string]any{"TextGeneration": map[string]any{"taskStatus": "Complete"}}
		},
		"wrong range": func(v map[string]any) {
			instance := v["instances"].(map[string]any)["instance-1"].(map[string]any)["MlxRingInstance"].(map[string]any)
			instance["shardAssignments"].(map[string]any)["runnerToShard"].(map[string]any)["runner-b"].(map[string]any)["PipelineShardMetadata"].(map[string]any)["startLayer"] = 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			var state map[string]any
			if err := json.Unmarshal(readyFixture(), &state); err != nil {
				t.Fatal(err)
			}
			mutate(state)
			data, _ := json.Marshal(state)
			if _, err := Ready(data, expectedFixture(), true); err == nil {
				t.Fatal("drift was accepted")
			}
		})
	}
}

func TestLiveAdmitsOneRunningGenerationOnly(t *testing.T) {
	var state map[string]any
	if err := json.Unmarshal(readyFixture(), &state); err != nil {
		t.Fatal(err)
	}
	runners := state["runners"].(map[string]any)
	runners["runner-a"] = map[string]any{"RunnerRunning": map[string]any{}}
	runners["runner-b"] = map[string]any{"RunnerRunning": map[string]any{}}
	tasks := state["tasks"].(map[string]any)
	tasks["generation-1"] = map[string]any{"TextGeneration": map[string]any{"commandId": "command-1"}}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Live(data, expectedFixture()); err != nil {
		t.Fatalf("one active generation was refused: %v", err)
	}
	if _, err := Ready(data, expectedFixture(), false); err == nil {
		t.Fatal("initial readiness admitted a running generation")
	}

	tasks["generation-2"] = map[string]any{"TextGeneration": map[string]any{"commandId": "command-2"}}
	data, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Live(data, expectedFixture()); err == nil {
		t.Fatal("two active generations were admitted")
	}
}

func TestLiveRefusesUnknownRunnerState(t *testing.T) {
	var state map[string]any
	if err := json.Unmarshal(readyFixture(), &state); err != nil {
		t.Fatal(err)
	}
	state["runners"].(map[string]any)["runner-a"] = map[string]any{"RunnerLoading": map[string]any{}}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Live(data, expectedFixture()); err == nil {
		t.Fatal("unknown runner state was admitted")
	}
}

func TestBaselineRequiresZeroObjects(t *testing.T) {
	state, err := Decode(readyFixture())
	if err != nil {
		t.Fatal(err)
	}
	state.Instances = nil
	state.Runners = nil
	state.Tasks = nil
	if _, err := Baseline(state, expectedFixture()); err != nil {
		t.Fatal(err)
	}
	state.Tasks = map[string]json.RawMessage{"unexpected": json.RawMessage(`{}`)}
	if _, err := Baseline(state, expectedFixture()); err == nil {
		t.Fatal("nonzero baseline succeeded")
	}
}
