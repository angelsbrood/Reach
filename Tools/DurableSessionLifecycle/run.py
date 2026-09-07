#!/usr/bin/env python3
"""Offline native check of the local Reach-owned encrypted durable session lifecycle candidate; retain logs, clean owned copies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True
PINS = {
    "mlx-swift-lm": "83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8",
    "mlx-swift": "0bb916c67f4b9e5c682cbe02a42c701c93ab5021",
    "swift-numerics": "0c0290ff6b24942dadb83a929ffaaa1481df04a2",
    "swift-argument-parser": "6a52f3251125d74daf04fcbd5e6f08a75d074382",
}
METALLIB = "reachd/.build/out/Products/Debug/mlx-swift_Cmlx.bundle/Contents/Resources/default.metallib"
METALLIB_SHA = "684ec284ab6f1f0a4089acfc3f91c1bde801747626c28f69defb65c1193db8a5"
PREREQUISITES = {
  "MLXResumableTokenDriver": {
    "run.py": "fc3845b52716faf3b981ec6000b92c0af6f56a81be6b56b60f29cf74f03aadff",
    "README.md": "75797167434fb5cbc7d8926f4e025e986f715daa796e2443c63591c3078e05d4",
    "Package.swift": "4d907ac7995b5fe958f6bf0971fdfcdeedc7abe01953da8b67b69ca8137abee1",
    "mlx-swift-lm.patch": "35a3be79e989c39ae568f97a70baf8bdb5b75f3161919803cc8a1530a0db63ab",
    "Sources/CheckpointWorker/main.swift": "8ba70b7a70471e3f82ac72d641d1192950356a12d5cedc9c82104f46e4fa6c32"
  },
  "MLXResumableTextOutput": {
    "run.py": "d7a365afdc5f3b5b83e5ac7e0ad419d608f55e2e69f6cb3f9e0771f5ff4b34b7",
    "README.md": "54c5ae748a5209ad4d01ac53d6c0ab2c45e410724eedb32c36174090b83c7d1d",
    "Package.swift": "f13bbe3d644b90d359abd7def34102167e63035c093f2d3222be9e265b5b3d63",
    "mlx-swift-lm.patch": "bd3fb02e7fab42887593512599de64ecb4d7c7c242d91359d37158d2a8227113",
    "Sources/TextOutputWorker/main.swift": "e816055c544bf83f313bb63bb2adfc4135b69d92f7a180d3eea2929246fdf7d3"
  },
  "MLXResumableGuidedGeneration": {
    "run.py": "e8c7c66940901bed9188d2b4e65038fb6bdada0514d2fa5cc55a7bc7fcfa287c",
    "README.md": "fac2f59780c043456bac74ff1b1783d00ba4cd8348a03476078896da4d9a67c2",
    "Package.swift": "57bacbcd8ffd471b26efeddb97cc8040096657be77cd35f58f2cc58902c2e51a",
    "mlx-swift-lm.patch": "91a056cc2094496c1f62a082d718abdd3f2f15de601c0954c79c886af076aa4b",
    "Sources/GuidedCheckpointWorker/main.swift": "fbb61f11007e3fa7f552bc4e7ce26f44bdf774b74c5ee255b4fc10375ce044fa"
  },
  "MLXResumableToolCallParsing": {
    "run.py": "94af8c47103c5194a3373a8706f3f5ba7135ae75723f3ffe8b394fa07fe0adbe",
    "README.md": "786cfb47a6ac16d89d85e45a634610563928113d8030740162f41b1cb20b1a10",
    "Package.swift": "838b5b14c13f342609c8325da103a0db9bee8a7213b82484a6bdd11903575bf4",
    "mlx-swift-lm.patch": "c7ae60342894f77b58e3b5cb51a11b0a1251db95a7bbc9386307eb17cec27ffd",
    "Sources/ToolCallCheckpointWorker/main.swift": "a29281ac94988a2f32f5b1fab43470e1917f27a553548c04e0548aa1c583c6b3"
  },
  "MLXResumableToolGeneration": {
    "run.py": "a4c6dd6aaf638b693b3c8ad4204bee2da3251ab09d6dfaf94725d0c3f005d600",
    "README.md": "fa63dc7d76a3ed9f67cf3bb5604b63570ca9ebaa04f5c1a0c33152cae07efdc9",
    "Package.swift": "f68d06761b9ee923fe1d137fe58119498be728491c6dad4bf1fe60f994c60278",
    "mlx-swift-lm.patch": "c70b2e6f86a7288020ca5383c609a11c30d135a0c7541c0ab17fd1a18e73e22b",
    "Sources/ToolGenerationWorker/main.swift": "aa219fe5061fc5a6420227552d254a5972b3d9d9c07a4eefc71be5feb34eca06"
  },
  "MLXResumableStructuralGuidance": {
    "run.py": "ee74421f95bfb54e14d0f92d440c527e3ffbbd874950ba2d1d70adf33a39fde9",
    "README.md": "6d3c2df2a6e99d12f5bad0959235230f4813a32c04bba910109b52f5282b7a10",
    "Package.swift": "a121a67e0cc30776bbcbb657678233c99865c74e7f197000eb5c6c882792dd7c",
    "mlx-swift-lm.patch": "53cde6d3e6bf4448a90e64261b5eff1116f7d6f8c47abeed7aa14d4533ad3a8b",
    "Sources/StructuralGuidanceWorker/main.swift": "c03d918c70ff140e16e5573db11a6ea2076b516e5cb5d2febc0c641c8e702e70"
  },
  "ResumableRequiredToolCoordinator": {
    "run.py": "8fa1118a16d3ac024f85086277ac088d5a753357ae65d3d488c4158675cccfb7",
    "README.md": "106b15f53d406ffdf3f4d32adfa22995a223327255a0fe9301996f643722c2de",
    "Package.swift": "566cc76a62e023bef96bce070077d468ddb80f4a838b753b9e63226228d3c60b",
    "mlx-swift-lm.patch": "228ce85cebf2804c1c588d36a25fcdcf36716746d83c8bc44cc5cb0a20f00477",
    "Sources/RequiredToolCoordinator/RequiredToolContract.swift": "11ba767efcb648daa0e245ad5ca25ce80b7ca19186c298382f360895bcbb9a5f",
    "Sources/RequiredToolCoordinator/RequiredToolCoordinator.swift": "c69bcb50e68bdd14f07782aad03d2c25d85c19947b320683927c25bf9960a23b",
    "Sources/RequiredToolCoordinator/RequiredToolCheckpoint.swift": "04ccf94de43cfaf6f48d1ba0b9a4f57c13e1b1ef31baf0d2dbbb7310d19e941b",
    "Sources/RequiredToolFixtures/Fixtures.swift": "3a0be937ab69520fec1fe670d4ffaa658f7fbdfbde4e72745255f080578fd10b",
    "Sources/RequiredToolWorker/main.swift": "61e5c8bb61f3a0037ef7c834768e6ed82da9b1c117b7a8b9b7e76618dbd0b4e7",
    "Tests/RequiredToolCoordinatorTests/RequiredToolCoordinatorTests.swift": "171892269efb21936a699a39295ce116ee12e6c424e24c56caabaaea23f7f22f",
    "Tests/RequiredToolCoordinatorTests/RequiredToolCheckpointTests.swift": "239c78d30bcf4963b6744ae034a149ed1d73697bb881ae85a62239b88d76c23b"
  },
  "ResumableAllowedToolCoordinator": {
    "run.py": "63dda024cfc42538d49b2008e197f52b58effd7eae5b5f0a5c9ea6b2994db666",
    "README.md": "37ebd52ffdaa3cc41b7c5a680552cbc5470dba4f2bcae87fc843134b124af646",
    "Package.swift": "9d4e5458f8065dcf2d3bf7918aa6fb8befdb3d553a1483905114b31d449957e9",
    "mlx-swift-lm.patch": "b2577a6925b3efe641617117228dfbb05b1d3597d11db5d03b77515cd2b3078e",
    "Sources/AllowedToolFixtures/Fixtures.swift": "2e823f93bae368a7dc91d9a0a7f9b991ae1a88eae284fcfd5a31ee1b27e8600b",
    "Sources/AllowedToolWorker/main.swift": "0cb83b7154a1afe19801d9857b09a9d43d9935cc3a5753d4191ba6ca99f8ddb1",
    "Sources/AllowedToolCoordinator/AllowedToolContract.swift": "eb1a4a76c7f2ef284bdf6b8205b9dffd420289a12a2b5609d20b755610536b20",
    "Sources/AllowedToolCoordinator/AllowedToolReplayInput.swift": "203a8302f2c5aa9b7028a7296aea1eea5badc71736dedc2c2796dd4d34b17d1b",
    "Sources/AllowedToolCoordinator/AllowedToolCoordinator.swift": "a1dbef4bfefaaf920aa0d1913643b9ce309408d999334840b09c6e622304e56b",
    "Sources/AllowedToolCoordinator/AllowedToolCheckpoint.swift": "72e62b4ffa96e1584c6cda0786ca82b968567268997add1c7afecf9cbdbb1d87",
    "Tests/AllowedToolCoordinatorTests/AllowedToolCoordinatorTests.swift": "65d6f65516cffab46f9f55c1d26f35565557fb4e4c661721ec18d8f85296d8cf",
    "Tests/AllowedToolCoordinatorTests/AllowedToolCheckpointTests.swift": "e1b4d50f5d87586f7d3597891d40291cc6013790cdc2422d48917d52d7f97d4f"
  },
  "ResumableMLXProvider": {
    "run.py": "aa09d27cdbaf95d87e845b67207de34c97bf6ef338cfbfd4a9707dcec1be7dce",
    "README.md": "6cb5f67f8d2878b63b319c2a54c31900f05005d9f2efea491313a1af3f280247",
    "Package.swift": "3d0dd8c823345e8fe36490b9fe72238c0f6bc963357783bf5befda2d774cf3d2",
    "Sources/ResumableMLXProvider/ProviderEvents.swift": "41f6d799ac2f40e7689b23b130b655c5adccdd6e9f1e5f32532c198d7f4f44dd",
    "Sources/ResumableMLXProvider/ProviderContract.swift": "90747e4363c163e5934c382afb78a57291839486104e8d3cfe3053954a436a4c",
    "Sources/ResumableMLXProvider/ProviderCheckpoint.swift": "f864a17bb33e5a9781cc9a72025c1681a6f6361b42a8ed552b6f6c73f8e8a14c",
    "Sources/ResumableMLXProvider/ProviderRoutes.swift": "11aa8af2fc07a1c825c5f64b95230c7aa9c9bfe35da14849478c84bce9663ed2",
    "Sources/ResumableMLXProvider/ResumableMLXProvider.swift": "2733136e383e556dd2c84e9ec1a47d1523ba3995fed30985be5e0ef52b8a10b4",
    "Sources/ProviderFixtures/Fixtures.swift": "3719568ff76ec08b3507f7cff9787e32984b7bddabcd3cc42ad1e9ecc8b4185a",
    "Sources/ProviderWorker/main.swift": "3f3fecf99eefd20820fd8866da7e4c2119d2504f0edac4b9dfac4c1746a0ea13",
    "Tests/ResumableMLXProviderTests/ProviderTests.swift": "f3d66afb701752fd56f0cfd9192ca1d412a7b8cf3c108bff66db4601cc5c96ba",
    "Tests/ResumableMLXProviderTests/ProviderCheckpointTests.swift": "289caa1d62c0590b1dd0aa217a5057f8f229ed07981bbd8f082d71f56f7d660e"
  },
  "DurableHostStore": {
    "run.py": "d0a9a8ab187d4fd8ca6c3c4d5c268ec09776e3a9200036f12de42fea2a810c46",
    "README.md": "0d84692527022b5278b390ed360e3f5f23b12ba6ecfbf815e6adf00516669d39",
    "Package.swift": "38d48e682e530a170bbd6fbb19ed9a9189ae5bd742c6f981a95db01bf1f39b96",
    "Sources/StoreWorker/main.swift": "67ba7f28810a3f44bd31119e86201e08efa8c2aa1e5a4d8afbe536e3ac67df00",
    "Sources/StoreFixtures/Fixtures.swift": "b9e3ca108b00a524c98e7a537dadf51b993efcb6598544a84a298b50463ec0db",
    "Sources/DurableHostStore/DurableGeneration.swift": "88994e971a53ff450c7ffbf96bf19195c0b103f32544926f3f3126a747c2f520",
    "Sources/DurableHostStore/StoreCrypto.swift": "cdfa6d591b2dd87bf2aaf4cea9565d194f5400cfec3b2d4d329a1a4511abd640",
    "Sources/DurableHostStore/StoreFileSystem.swift": "9751cd88480a36a9d486d74bf56f8335e385085ff79a36af59fb164bfb95dfb7",
    "Sources/DurableHostStore/StoreManifest.swift": "08ae56f5c284e2a1c7e3ef8dea3d111818c9a1e19d949984faa56e1568327221",
    "Sources/DurableHostStore/StoreContract.swift": "6c676e8775f4c6ac176519a56f25f44632ee4fbaf6e5104a831a2812a439dcde",
    "Sources/DurableHostStore/DurableHostStore.swift": "f333f6401dc1581e2553dc35e832a70b858d72574019816053a1b3b3479731da",
    "Tests/DurableHostStoreTests/StoreRecoveryTests.swift": "9a4a8ef8af80aab96e61e0b56438bbf3bcb8bb2d3f96bb07f7d214f0b9b91595",
    "Tests/DurableHostStoreTests/StoreNativeTests.swift": "af66f11810fe534de745d4cfba978cedcb4dd6dfa56a87d95a9b5178484095da",
    "Tests/DurableHostStoreTests/StoreTests.swift": "93643cd7039f6ccb7782cfc568c6d6e31cab396e4c9e572302db7abe1f902a95"
  }
}
PRIOR_OUTPUTS = {'Libraries/MLXGuidedGeneration/ResumableGrammarState.swift': '11ce2127530d66979584fbdf96cfd25b4ffca970847b7799c0ddb497e9435a9e',
 'Libraries/MLXGuidedGeneration/ResumableGuidedCheckpoint.swift': '55a8383083b80e4951e2ae96a55f7daf56160696bc653c7d9e0399c76c9fecfa',
 'Libraries/MLXGuidedGeneration/ResumableGuidedGeneration.swift': 'df708ca383a3b79ace8a85effda8fe8723c7f83b6709a71310b69ea558fb2a0e',
 'Libraries/MLXGuidedGeneration/ResumableGuidedTextState.swift': '71360e0b2b0ac73882c83b46d4532eee2ee1cf1529c30d8ef76a2a6bb396d2ef',
 'Libraries/MLXGuidedGeneration/WhitespaceRunTracker.swift': '4326e12dd2500574256f467f56741776928e81432facc6c3a22d5e6e555318ad',
 'Libraries/MLXGuidedGeneration/XGrammarBridge.swift': '3c76fa4d976324cde0574f373d7947fcbbebe50f05537c9fc28c752784a04aae',
 'Libraries/MLXLMCommon/Evaluate.swift': 'af561a3707edaf84afb2235085a0a581a05feb502ae915c30217060334fa16b3',
 'Libraries/MLXLMCommon/LanguageModel.swift': '95edafd10e744b909c2c1f3b7355ff684612d83c49fa9f4515138ac2f7c2c572',
 'Libraries/MLXLMCommon/ResumableGuidedModelState.swift': 'c6df59921c588a870d76eedffebf512e4504e614369e0195d649b5a6dea5d640',
 'Libraries/MLXLMCommon/ResumableTextCheckpoint.swift': 'd29f98e28f418891ad6dbc7b52e9ac1fa1d17ab0b1c54188cfcf61ee3bc3aad1',
 'Libraries/MLXLMCommon/ResumableTextOutput.swift': '6a09466699e95edc57318ff21049e2df8f7cf653d8f1524c6721211908d5e76a',
 'Libraries/MLXLMCommon/ResumableTokenCheckpoint.swift': 'e0eefce17c271d43bcf95ba2083079c3d6c83a6361a7fc8d97b0351fca194b75',
 'Libraries/MLXLMCommon/ResumableTokenDriver.swift': '63ebcbaf0123d2da6a8221ead9f7918686a140501e215aaafa73f9adda2e0909',
 'Libraries/MLXLMCommon/ResumableToolGeneration.swift': '1f6108350dc1ed02c4ea143c51572b852fac325a72c6e0184846199d281ead01',
 'Libraries/MLXLMCommon/ResumableToolGenerationCheckpoint.swift': '77798d45680268ccfabf2db8549d297add05d5ae1d61573305a21ae5debdb45c',
 'Libraries/MLXLMCommon/Tool/ResumableToolCallCheckpoint.swift': '8c2ac93dd8639290c74ce760f10424c0b8213908c0f409c915461a9a90cb3e86',
 'Libraries/MLXLMCommon/Tool/ResumableToolCallProcessor.swift': '6f516e23174eab3cc55a1deac9b10de3e4e858ac5a86706f25a1891b05438b8f',
 'Libraries/MLXLMCommon/Tool/ToolCallProcessor.swift': '18d392604bf09e5119e56c9378c0d2df8e8a22b01ef8969dace19c15c5ed5515',
 'Tests/MLXGuidedGenerationTests/ResumableGrammarStateTests.swift': '35813e02415a90396ac5d719c6bfd3f3928e7b0dc8bc1d7a07f361f3112b9b9e',
 'Tests/MLXGuidedGenerationTests/ResumableGuidedCheckpointTests.swift': '907ff4fea1a52f1c33c1d0136aac37116cc059475671da4c0616d26ad710dc3e',
 'Tests/MLXGuidedGenerationTests/ResumableGuidedGenerationTests.swift': '6d58cbd8bbabc94dd9c7a303d9e540fd2fa0fe706f785f9e9612c0ca13179960',
 'Tests/MLXGuidedGenerationTests/ResumableGuidedTextStateTests.swift': '5f8ee1b8615c8387d9864745109dbc8a4974037bdbbffd3c667b732b9df04123',
 'Tests/MLXLMTests/ResumableGuidedModelStateTests.swift': '44bb4787f469577dba7f628a865afcf50ef0af07ff21a0cff4d9ff5646c13da2',
 'Tests/MLXLMTests/ResumableTextCheckpointTests.swift': '3c52d5129701ad70381a2ad0192d8506597c3677b5fe186cbaf007ff03c27933',
 'Tests/MLXLMTests/ResumableTextOutputTests.swift': '71273018e4bd2b23d26164a4c1e6bd2eb0fa4cd38efa1a5d814ae4a59d6f902d',
 'Tests/MLXLMTests/ResumableTokenCheckpointTests.swift': 'd7c3208ff12c79e510fef407cd3f67908b9eae3539c8c4947d942b31e62fdc72',
 'Tests/MLXLMTests/ResumableTokenDriverTests.swift': '02218c0a143f5552eb018a79bc0497ac510805972ce63a5f4ab29fb80ebf8b67',
 'Tests/MLXLMTests/ResumableToolCallCheckpointTests.swift': '6a5c1158c1523b64b7dfe8310ac9e74b8d1babe0ef34f6dc138a26378a1e2862',
 'Tests/MLXLMTests/ResumableToolCallProcessorTests.swift': '2124e82a03341cb7f1483b1674182944dc16c30527f4c1fa084feda6097c0253',
 'Tests/MLXLMTests/ResumableToolGenerationCheckpointTests.swift': '7f3096f6d2dbf3b7548a1d9f2a43b94478a3fb29e97a3afdf35e56794f6046df',
 'Tests/MLXLMTests/ResumableToolGenerationTests.swift': '96cc94d14c48d64aadffb53c82a598161940c3e7c5925848d9be3eb12351b2ac',
 'Tests/MLXGuidedGenerationTests/ResumableStructuralGuidanceCheckpointTests.swift': '61c5815dc2f7d57e37fc050fbd02c29ec7f0fac3223b63cfe4ea8709c21790bc',
 'Tests/MLXGuidedGenerationTests/ResumableStructuralGuidanceTests.swift': '20ca2624652e52575e1d0d1fb8ded57d39b88f650cd42f7c2fcb1a3e816ce7a5',
 'Libraries/MLXGuidedGeneration/ResumableGuidedCheckpointView.swift': 'a6c343139a9509d51dbd6cbfbf488e7305e6cf47f4e4b1bd10084c430a11d405',
 'Libraries/MLXLMCommon/ResumableToolGenerationCheckpointView.swift': '3ffb459a2dc8aebda4e37121e699c103106cf343db8cda2b03ed2b288e595ca2'}
SELECTED_SOURCES = {
  "docs/generation-durability-design.md": "0f68e141ae444779c2877399113f80baae4b970cf5aa442a39a7e69d74f2e513",
  "reachd/Sources/ReachDaemon/MLXFilling.swift": "7cf06be82f7e79b61f071f82e76cc8bfbb6fd54c03a4db6beeb1fed308638e0a",
  "reachd/Sources/ReachDaemon/ToolGuidance.swift": "879ffae453a39244e850e7e78057116ce7c2b5f3d5c55e79c9347a1f5f055b33",
  "reachd/Sources/ReachDaemon/ResponseGuidance.swift": "c03e9f862d33aa9922410f89e630b35e74c46ce95124c9d99b96d3330386247a",
  "reachd/Tests/ReachDaemonTests/ToolGuidanceTests.swift": "6fe7f54b5aa106168b1e22176106bbe6213b378bc950f5d698825cc774f4de1a",
  "ReachKit/Sources/ReachWire/WireEvent.swift": "2ea861fd3dd7624ca4c8895fb0c917db11cb15ce80d01d1646efea3fc3466007",
  "reachd/Package.resolved": "d59cc18521a61c30919700f4470b5af14c3b95000193b09337f78815c7f1f194",
  "AGENTS.md": "43e98f073cebd424e9110d714afde2c44dc8129b601edc9c28790c891a3b9f72",
  "reachd/Sources/ReachDaemon/SlotFilling.swift": "fa3cc59c20071ad61eff73e3dbea5e186393d49eb5844821ac1986c96744564f",
  "reachd/Sources/ReachDaemon/MeshIntent.swift": "7c6694218085416c76369e5fb7644c3bdb0a602b65df625f7d5c23b1915fb88c",
  "reachd/Sources/ReachDaemon/SessionRegistry.swift": "74905b89d6fead6ba9c0a5eea1ef0563b031f9bd5186e01a7bc28fdd5fb1674b",
  "reachd/Sources/ReachDaemon/SlotAdmission.swift": "93145c6466e8cf9d6f1d60a53aee5f85bc7800e062d7a9ae269cdc65093bc912"
}
PRODUCT_PATHS = set(["run.py","README.md","Package.swift","Sources/DurableSessionLifecycle/LifecycleContract.swift","Sources/DurableSessionLifecycle/SessionTicket.swift","Sources/DurableSessionLifecycle/LifecycleFileSystem.swift","Sources/DurableSessionLifecycle/LifecycleCrypto.swift","Sources/DurableSessionLifecycle/LifecycleCatalog.swift","Sources/DurableSessionLifecycle/DurableSessionLifecycle.swift","Sources/DurableSessionLifecycle/LifecycleGeneration.swift","Sources/DurableSessionLifecycle/LifecycleRetirement.swift","Sources/LifecycleFixtures/Fixtures.swift","Sources/LifecycleWorker/main.swift","Tests/DurableSessionLifecycleTests/LifecycleTests.swift","Tests/DurableSessionLifecycleTests/LifecycleRecoveryTests.swift","Tests/DurableSessionLifecycleTests/LifecycleNativeTests.swift"])
TEST_SOURCES = ['LifecycleTests.swift', 'LifecycleRecoveryTests.swift', 'LifecycleNativeTests.swift']

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(repo, *args):
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def export_git(source, target, revision, records):
    """Export tracked bytes and each already-present pinned submodule, without fetching."""
    if git(source, "rev-parse", "HEAD") != revision or git(source, "status", "--porcelain", "--untracked-files=no"):
        raise RuntimeError(f"source revision/cleanliness mismatch: {source}")
    target.mkdir(parents=True, exist_ok=True)
    archive = target.parent / (target.name + ".tar")
    subprocess.run(["git", "archive", "--format=tar", "--output=" + str(archive), revision], cwd=source, check=True)
    with tarfile.open(archive) as data:
        data.extractall(target, filter="data")
    archive.unlink()
    records[str(source)] = revision
    entries = subprocess.check_output(["git", "ls-tree", "-r", "-z", revision], cwd=source).split(b"\0")
    for entry in entries:
        if entry.startswith(b"160000 "):
            header, relative = entry.decode().split("\t", 1)
            export_git(source / relative, target / relative, header.split()[2], records)



class Worker:
    """Owned sequential process; keys only in an inherited anonymous pipe."""
    def __init__(self, binary, harness, env, logs, label, mode, path, incarnation, keys, ticket=b'', cut='none', action='complete', cursor=0, clock=1_000_000_000, final_clock=1_000_000_000):
        import base64
        read_fd, write_fd = os.pipe()
        self.log = (logs/(label+'-'+str(time.time_ns())+'.log')).open('wb')
        self.buffer = b''
        self.joined = False
        try:
            self.process = subprocess.Popen([str(binary), mode, str(path), incarnation, str(read_fd), cut, action, str(cursor), str(clock), str(final_clock)],
                cwd=harness, env=env, pass_fds=(read_fd,), close_fds=True, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=self.log, start_new_session=True)
        except BaseException:
            os.close(write_fd); self.log.close(); raise
        finally:
            os.close(read_fd)
        try:
            payload = keys+ticket
            if len(keys) != 64 or len(ticket) > 4096: raise RuntimeError('injection bound')
            while payload:
                written = os.write(write_fd, payload)
                if written <= 0: raise RuntimeError('key pipe short write')
                payload = payload[written:]
        except BaseException:
            self.join(kill=True)
            raise
        finally:
            os.close(write_fd)

    def row(self):
        import select
        deadline = time.monotonic()+60
        while b'\n' not in self.buffer:
            remaining = deadline-time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise RuntimeError('worker protocol timeout')
            data = os.read(self.process.stdout.fileno(), 65536)
            if not data: raise RuntimeError('worker protocol EOF; inspect sanitized stderr')
            self.buffer += data
            if len(self.buffer) > 24*1024**2: raise RuntimeError('bounded worker protocol')
        line, self.buffer = self.buffer.split(b'\n', 1)
        return json.loads(line)

    def ack(self, cursor):
        self.process.stdin.write((str(cursor)+'\n').encode()); self.process.stdin.flush()

    def join(self, kill=False):
        if self.joined: return self.process.returncode
        try:
            if kill and self.process.poll() is None: os.killpg(self.process.pid, signal.SIGKILL)
            code = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL); self.process.wait(); raise
        finally:
            self.joined = True
            self.log.write((json.dumps({'owned_pid':self.process.pid, 'exit_code':self.process.returncode, 'joined':True})+'\n').encode())
            self.process.stdin.close(); self.process.stdout.close(); self.log.close()
        if not kill and code != 0: raise RuntimeError('worker refused: '+str(code))
        return code

class Client:
    """Survives worker death, but is deliberately not a durable client receipt."""
    def __init__(self):
        self.cursor, self.received = 0, {}
        self.duplicates = 0

    def accept(self, row, limit=None):
        import base64
        raw = base64.b64decode(row['bytes'], validate=True)
        events = json.loads(raw)
        first, count, skip = row['first'], row['count'], row['skip']
        if count != len(events) or not 0 <= skip < count or first < 1: raise RuntimeError('client framing')
        indices = list(range(skip, count))
        if limit is not None: indices = indices[:limit]
        for index in indices:
            seq = first+index
            value = (row['commit'], raw, index)
            if seq <= self.cursor:
                if self.received.get(seq) != value: raise RuntimeError('changed duplicate')
                self.duplicates += 1
            else:
                if seq != self.cursor+1: raise RuntimeError('client sequence gap')
                self.received[seq] = value; self.cursor = seq

    def projection(self):
        return [(raw, index) for _, raw, index in self.received.values()]

def new_keys():
    keys = os.urandom(64)
    if keys[:32] == keys[32:]: raise RuntimeError('independent random key collision')
    return keys

def client_gate():
    import base64
    good = {'first':1, 'count':2, 'skip':0, 'commit':'a'*64, 'bytes':base64.b64encode(b'[1,2]').decode()}
    client = Client(); client.accept(good, limit=1)
    client.accept(dict(good, skip=1))
    client.accept(good)
    if client.cursor != 2 or client.duplicates != 2: raise RuntimeError('client exact prefix/duplicate')
    for wrong in (dict(good, first=4), dict(good, commit='b'*64), dict(good, bytes=base64.b64encode(b'[1,3]').decode())):
        try: client.accept(wrong)
        except RuntimeError: pass
        else: raise RuntimeError('client gap/changed duplicate accepted')

def drive(worker, client):
    import base64
    recovery, ticket = None, None
    try:
        while True:
            row = worker.row()
            if row['kind'] == 'ticket':
                if ticket is not None: raise RuntimeError('duplicate ticket issuance')
                ticket = base64.b64decode(row['bytes'], validate=True)
                if not 0 < len(ticket) <= 4096: raise RuntimeError('ticket bound')
            elif row['kind'] == 'cut':
                code = worker.join(kill=True)
                if code != -signal.SIGKILL: raise RuntimeError('cut did not kill worker')
                return {'death':row,'exit_code':code,'recovery':recovery}, ticket
            elif row['kind'] == 'recovered':
                if row['restore_calls'] or row['restore_factories']: raise RuntimeError('reopen invoked model')
                recovery = row
            elif row['kind'] == 'frame':
                client.accept(row); worker.ack(client.cursor)
            elif row['kind'] == 'done':
                worker.join()
                if row['prefills'] or row['mlx_peak_bytes'] > 128*1024**2:
                    raise RuntimeError('worker native bounds')
                if row['phase'] == 'terminal' and row['high'] != client.cursor:
                    raise RuntimeError('terminal publication high')
                return {'done':row,'recovery':recovery}, ticket
            else: raise RuntimeError('unexpected worker protocol')
    finally:
        worker.join(kill=True)

def lock_gate(binary,harness,env,fixtures,logs,resources):
    import uuid
    path, incarnation, keys = fixtures/'root-lock',str(uuid.uuid4()),new_keys()
    owner, rows = None,[]
    def start(label,mode):
        return Worker(binary,harness,env,logs,label,mode,path,incarnation,keys)
    try:
        owner = start('lock-owner','lock-init'); row = owner.row()
        if row['kind'] != 'locked' or row['epoch'] != 1 or row['factories']: raise RuntimeError('initial root ownership')
        rows.append(row)
        contender = start('lock-contender','contender')
        try:
            row = contender.row()
            if row['kind'] != 'busy' or row['factories']: raise RuntimeError('live root owner exclusion')
            rows.append(row); contender.join()
        finally: contender.join(kill=True)
        code = owner.join(kill=True)
        if code != -signal.SIGKILL: raise RuntimeError('owner death')
        rows.append({'kind':'killed-and-joined','pid':owner.process.pid,'exit_code':code})
        successor = start('lock-successor','contender')
        try:
            row = successor.row()
            if row['kind'] != 'locked' or row['epoch'] != 2 or row['factories']: raise RuntimeError('joined successor')
            rows.append(row); successor.join()
        finally: successor.join(kill=True)
        resources('root-lock')
        return {'result':'PASS','observations':rows,'claim':'New wrapper stable root exclusion and joined-death takeover; unchanged S81 child lock proof reused'}
    finally:
        if owner: owner.join(kill=True)
        if path.exists(): shutil.rmtree(path)

def lifecycle_matrix(binary,harness,env,fixtures,logs,resources,evidence):
    import uuid
    client_gate()
    write_json(evidence/'lock.json',lock_gate(binary,harness,env,fixtures,logs,resources))
    reference_path, incarnation, keys = fixtures/'ordinary-reference',str(uuid.uuid4()),new_keys()
    reference = Client()
    try:
        reference_row,_ = drive(Worker(binary,harness,env,logs,'ordinary-reference','initialize',reference_path,incarnation,keys),reference)
        reference_traces = reference_row['done']['traces']
        if reference_row['done']['native_calls'] <= 0: raise RuntimeError('ordinary native reference')
    finally:
        if reference_path.exists(): shutil.rmtree(reference_path)
        del keys
    resources('ordinary-reference')
    # All actual SIGKILLs below are separate from the empty-child setup IO stop.
    cases = [
        ('allocation-intent','afterAllocating','complete','inspect','allocating'),
        ('allocation-directory','afterDirectoryCreated','complete','inspect','allocating'),
        ('empty-child','afterEmptyChild','complete','inspect','preparing'),
        ('accepted-c0','afterC0','complete','complete','active'),
        ('committed-terminal','afterChildTerminal','complete','replay','terminal'),
        ('before-retirement','beforeRetirementIntent','cancel-empty','cancel','preparing'),
        ('retirement-intent','afterRetirementIntent','cancel-empty','inspect','tombstone'),
        ('content-deletion','duringContentDeletion','cancel-empty','inspect','tombstone'),
        ('before-tombstone','afterContentDeletion','cancel-empty','inspect','tombstone'),
        ('after-tombstone','afterTombstone','cancel-empty','inspect','tombstone'),
    ]
    results=[]
    for label,cut,action,recover_action,expected in cases:
        path,incarnation,keys = fixtures/label,str(uuid.uuid4()),new_keys()
        client=Client(); ticket=None
        resources(label+'-before')
        try:
            first,ticket = drive(Worker(binary,harness,env,logs,label+'-producer','initialize',path,incarnation,keys,cut=cut,action=action),client)
            if 'death' not in first or ticket is None: raise RuntimeError('declared lifecycle death not reached: '+label)
            recovered,_ = drive(Worker(binary,harness,env,logs,label+'-restore','recover',path,incarnation,keys,ticket=ticket,
                action=recover_action,cursor=client.cursor,clock=61_000_000_000),client)
            rec,done=recovered['recovery'],recovered['done']
            if rec['phase'] != expected or rec['epoch'] != 2: raise RuntimeError('recovered lifecycle phase: '+label)
            if label == 'accepted-c0' and (done['native_calls'] <= 0 or not rec['resumable']):
                raise RuntimeError('ordinary active native continuation')
            if label != 'accepted-c0' and (done['native_calls'] or done['factories']):
                raise RuntimeError('non-native recovery acquired model')
            if label in ('accepted-c0','committed-terminal'):
                if client.projection() != reference.projection(): raise RuntimeError('exact original event/ID/usage bytes')
                # Reference suffix is inspected only after actual continuation.
                for trace in done['traces']:
                    matches=[t for t in reference_traces if all(t[k]==trace[k] for k in ('kind','index','inputDigest','weights'))]
                    if len(matches)!=1 or not trace['inputs']: raise RuntimeError('native suffix identity')
                    count=len(trace['inputs'])
                    if any(trace[k]!=matches[0][k][-count:] for k in ('inputs','offsets','logits')):
                        raise RuntimeError('native continuation suffix')
                # C0 recovery commits its terminal at 61s; the lost-terminal-
                # promotion case already committed at 1s. Use those original
                # transition bounds, never the expiry worker's reopen time.
                terminal_bound = 661_000_000_000 if label == 'accepted-c0' else 601_000_000_000
                expiry,_=drive(Worker(binary,harness,env,logs,label+'-expiry','recover',path,incarnation,keys,ticket=ticket,
                    action='expire',cursor=client.cursor,clock=62_000_000_000,final_clock=terminal_bound),client)
                if expiry['done']['phase']!='tombstone' or expiry['done']['native_calls'] or expiry['done']['factories']:
                    raise RuntimeError('original terminal retention or zero-model expiry')
            if expected=='tombstone' or label in ('before-retirement','accepted-c0','committed-terminal'):
                if any((path/'children').iterdir()) or any((path/'requests').iterdir()):
                    raise RuntimeError('retired content remains')
            # Synthetic root keys never appear in any retained store ciphertext.
            for file in path.rglob('*'):
                if file.is_file():
                    data=file.read_bytes()
                    if keys[:32] in data or keys[32:] in data: raise RuntimeError('root keys in store')
                    if file.name!='lock' and not data.startswith((b'S82GCM01',b'S81GCM01')):
                        raise RuntimeError('plaintext store role')
            digest=hashlib.sha256()
            for raw,index in client.projection(): digest.update(raw);digest.update(index.to_bytes(4,'big'))
            results.append({'case':label,'result':'PASS','death':first['death'],'exit_code':first['exit_code'],
                'recovered_pid':done['pid'],'recovered_epoch':rec['epoch'],'selected_phase':rec['phase'],
                'restore_model_calls':rec['restore_calls'],'restore_factories':rec['restore_factories'],
                'continuation_model_calls':done['native_calls'],'client_events':client.cursor,
                'event_projection_sha256':digest.hexdigest(),'mlx_peak_bytes':max(done['mlx_peak_bytes'],first['death']['mlx_peak_bytes']),
                'assertion_storage':'Exact events and native suffix compared in supervisor memory after continuation; raw arrays not retained'})
            write_json(evidence/'matrix.json',results)
            print(label+': real death/recovery PASS',flush=True); resources(label+'-after')
        finally:
            if path.exists(): shutil.rmtree(path)
            del keys,ticket
    return results

def main():
    if sys.version_info < (3, 12): raise RuntimeError('Python 3.12 or newer is required for safe local archive extraction')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reach', type=Path, required=True)
    parser.add_argument('--companion-root', type=Path, help='Owned S82 development scratch included in observations')
    args = parser.parse_args()
    reach, candidate = args.reach.resolve(), Path(__file__).resolve().parent
    companion = args.companion_root
    if companion:
        if companion.is_symlink() or companion.parent != Path('/private/tmp') or not companion.name.startswith('reach-s82.'):
            raise RuntimeError('unexpected companion root')
        info = companion.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700:
            raise RuntimeError('companion ownership/mode')
    os.umask(0o077)
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    root = Path(tempfile.mkdtemp(prefix='reach-durable-session-lifecycle.', dir='/private/tmp')).resolve()
    private, logs, evidence = (root / p for p in ('private', 'logs', 'evidence'))
    for path in (private, logs, evidence): path.mkdir(mode=0o700)
    for name in ('tmp', 'fixtures'): (private / name).mkdir()
    fixtures = private / 'fixtures'
    print(f'Evidence: {root}', flush=True)
    commands, observations, revisions = [], [], {}
    outcome = {'result': 'FAIL', 'proof': 'S82 same-boot encrypted lifecycle catalog and bounded native joins',
        'reused': 'Accepted S72-S81 native campaigns including S79/S74 RC1 and tiny Llama recurrence; no prior suite or old-binary rerun'}
    started = time.monotonic()
    env = dict(os.environ)
    for name in ('MLX_SWIFT_BUILD_DOC', 'SPI_GENERATE_DOCS'): env.pop(name, None)
    env.update(CLANG_MODULE_CACHE_PATH=str(private/'clang-cache'), SWIFTPM_MODULECACHE_OVERRIDE=str(private/'swift-cache'),
        XDG_CACHE_HOME=str(private/'xdg-cache'), TMPDIR=str(private/'tmp'), PYTHONDONTWRITEBYTECODE='1')

    def resources(label):
        roots = [root] + ([companion] if companion else [])
        allocated = sum(int(subprocess.check_output(['du', '-sk', str(p)], text=True).split()[0])*1024 for p in roots)
        fixture_bytes = sum(p.stat().st_size for r in roots for role in ('fixtures', 'tmp')
            for p in (r/'private'/role).rglob('*') if p.is_file())
        free = shutil.disk_usage(root).free
        if any(p.stat().st_size > 192*1024**2 for role in (logs,evidence) for p in role.rglob('*') if p.is_file()):
            raise RuntimeError('individual evidence file ceiling')
        observations.append({'after': label, 'combined_allocated_bytes': allocated, 'fixture_bytes': fixture_bytes, 'free_bytes': free})
        if allocated > 16*1024**3 or fixture_bytes > 3*1024**3 or free < 20*1024**3:
            raise RuntimeError('S82 resource ceiling/floor')

    def command(label, cmd, cwd, timeout=900):
        started_command = time.monotonic()
        resources(label+'-before')
        with (logs/(label+'.log')).open('w') as log:
            process = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except BaseException:
                try: os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError: pass
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); process.wait()
                commands.append({'label': label, 'command': cmd, 'pid': process.pid, 'exit_code': process.returncode, 'interrupted': True})
                write_json(evidence/'commands.json', commands)
                raise
        commands.append({'label': label, 'command': cmd, 'pid': process.pid, 'exit_code': code, 'seconds': time.monotonic()-started_command})
        write_json(evidence/'commands.json', commands)
        resources(label+'-after')
        if code: raise RuntimeError(f'{label} exited {code}; see {logs/(label+".log")}')
        return (logs/(label+'.log')).read_text()

    def authenticate():
        for name, files in PREREQUISITES.items():
            if {p: sha(reach/'Tools'/name/p) for p in files} != files:
                raise RuntimeError('accepted prerequisite changed: '+name)
        if {p: sha(reach/p) for p in SELECTED_SOURCES} != SELECTED_SOURCES:
            raise RuntimeError('selected Reach/design/wire source binding changed')

    try:
        resources('opening')
        authenticate()
        developer = subprocess.check_output(['xcode-select', '-p'], text=True).strip()
        swift = subprocess.check_output(['xcrun', 'swift', '--version'], text=True, stderr=subprocess.STDOUT).strip()
        if developer != '/Applications/Xcode-beta.app/Contents/Developer' or 'swiftlang-6.4.0.33.1' not in swift:
            raise RuntimeError('selected toolchain mismatch')
        resolved = {p['identity']: p['state']['revision'] for p in json.loads((reach/'reachd/Package.resolved').read_text())['pins']}
        if any(resolved.get(k) != v for k, v in PINS.items()) or sha(reach/METALLIB) != METALLIB_SHA:
            raise RuntimeError('pin/Metal library mismatch')
        if any(p.is_symlink() for p in candidate.rglob('*')): raise RuntimeError('candidate symlink')
        files = {str(p.relative_to(candidate)): sha(p) for p in candidate.rglob('*') if p.is_file()}
        if set(files) != PRODUCT_PATHS: raise RuntimeError('sixteen-product ceiling')
        write_json(evidence/'inputs.json', {'reach_head': git(reach, 'rev-parse', 'HEAD'), 'prerequisite_products': PREREQUISITES,
            'candidate_sha256': files, 'selected_source_sha256': SELECTED_SOURCES, 'pins': PINS,
            'metallib_sha256': METALLIB_SHA, 'developer': developer, 'swift': swift, 'python': sys.version})
        harness = private/'harness'
        harness.mkdir()
        for name, revision in PINS.items():
            target = harness/name if name == 'mlx-swift-lm' else private/name
            export_git(reach/'reachd/.build/checkouts'/name, target, revision, revisions)
        write_json(evidence/'source-revisions.json', revisions)
        manifest = private/'mlx-swift/Package.swift'
        text = manifest.read_text()
        for name in ('swift-numerics', 'swift-argument-parser'):
            original = f'.package(url: "https://github.com/apple/{name}", from: "1.0.0")'
            if text.count(original) != 1: raise RuntimeError('local manifest overlay mismatch')
            text = text.replace(original, f'.package(path: "../{name}")')
        manifest.write_text(text)
        lm, stack = harness/'mlx-swift-lm', []
        for index, name in enumerate(PREREQUISITES, 72):
            if 'mlx-swift-lm.patch' not in PREREQUISITES[name]: continue
            patch = reach/'Tools'/name/'mlx-swift-lm.patch'
            command(f's{index}-patch-check', ['git', 'apply', '--check', str(patch)], lm, 30)
            command(f's{index}-patch-apply', ['git', 'apply', str(patch)], lm, 30)
            stack.append({'slice': f'S{index}', 'patch_sha256': sha(patch)})
        if len(PRIOR_OUTPUTS) != 35 or {p: sha(lm/p) for p in PRIOR_OUTPUTS} != PRIOR_OUTPUTS:
            raise RuntimeError('35 unchanged composition output bindings')
        write_json(evidence/'composition.json', {'result': 'PASS', 'ordered_prerequisites': stack,
            'unchanged_35_outputs': PRIOR_OUTPUTS, 'new_dependency_outputs': 0,
            'claim': 'Unchanged S72-S79 composition; eighteen exact S78/S79/S80/S81 coordinator/provider/store sources; exact WireEvent; lifecycle wrapper only'})
        write_json(evidence/'patched-source-sha256.json', PRIOR_OUTPUTS)
        shutil.copytree(candidate/'Sources', harness/'Sources')
        shutil.copytree(candidate/'Tests', harness/'Tests')
        (harness/'Sources/ReachWire').mkdir()
        shutil.copy2(reach/'ReachKit/Sources/ReachWire/WireEvent.swift', harness/'Sources/ReachWire/WireEvent.swift')
        if sha(harness/'Sources/ReachWire/WireEvent.swift') != SELECTED_SOURCES['ReachKit/Sources/ReachWire/WireEvent.swift']:
            raise RuntimeError('actual WireEvent copy mismatch')
        helper_count = 0
        for name, target_name in [('ResumableRequiredToolCoordinator', 'RequiredToolCoordinator'), ('ResumableAllowedToolCoordinator', 'AllowedToolCoordinator'), ('ResumableMLXProvider', 'ResumableMLXProvider'), ('DurableHostStore', 'DurableHostStore')]:
            paths = [p for p in PREREQUISITES[name] if p.startswith('Sources/'+target_name+'/')]
            for p in paths:
                target = harness/p; target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(reach/'Tools'/name/p, target)
                if sha(target) != PREREQUISITES[name][p]: raise RuntimeError('unchanged coordinator copy mismatch')
                helper_count += 1
        if helper_count != 18: raise RuntimeError('eighteen unchanged coordinator/provider/store sources')
        (harness/'TinyLlama').mkdir()
        for path in ('LLMModel.swift', 'Models/Llama.swift'):
            shutil.copy2(lm/'Libraries/MLXLLM'/path, harness/'TinyLlama'/Path(path).name)
        shutil.copy2(candidate/'Package.swift', harness/'Package.swift')
        build = private/'build'
        flags = ['--package-path', str(harness), '--scratch-path', str(build), '--cache-path', str(private/'spm-cache'),
            '--config-path', str(private/'spm-config'), '--security-path', str(private/'spm-security'), '--disable-sandbox',
            '--disable-netrc', '--disable-keychain', '--disable-dependency-cache', '--disable-prefetching', '--skip-update',
            '--disable-index-store', '--build-system', 'native', '--jobs', '4']
        path_output = command('binary-path', ['xcrun', 'swift', 'build', *flags, '--show-bin-path'], harness, 60)
        paths = [line.strip() for line in path_output.splitlines() if line.strip().startswith(str(build)+'/')]
        if len(paths) != 1: raise RuntimeError('native binary path observation')
        bin_path = Path(paths[0]); bin_path.mkdir(parents=True, exist_ok=True)
        binary = bin_path/'LifecycleWorker'
        shutil.copy2(reach/METALLIB, bin_path/'mlx.metallib'); shutil.copy2(reach/METALLIB, harness/'default.metallib')
        command('candidate-build', ['xcrun', 'swift', 'build', *flags, '--build-tests'], harness)
        for bundle in build.rglob('*.xctest'):
            target = bundle/'Contents/MacOS'; target.mkdir(parents=True, exist_ok=True)
            shutil.copy2(reach/METALLIB, target/'mlx.metallib')
        # Non-model product platform gates precede every native campaign.
        gate_log = command('platform-tests', ['xcrun', 'swift', 'test', *flags, '--skip-build', '--no-parallel', '--filter', 'DurableSessionLifecycleTests.LifecycleTests|DurableSessionLifecycleTests.LifecycleRecoveryTests'], harness, 600)
        clock_rows = [json.loads(command('clock-'+str(i), [str(binary), 'clock'], harness, 30)) for i in range(3)]
        if len({r['pid'] for r in clock_rows}) != 3 or not 0 < clock_rows[0]['clock'] <= clock_rows[1]['clock'] <= clock_rows[2]['clock']:
            raise RuntimeError('cross-process product clock')
        write_json(evidence/'clock.json', {'result':'PASS','observations':clock_rows})
        test_log = gate_log + command('native-tests', ['xcrun', 'swift', 'test', *flags, '--skip-build', '--no-parallel', '--filter', 'DurableSessionLifecycleTests.LifecycleNativeTests'], harness, 600)
        test_peaks = [int(v) for v in re.findall(r'S82 native MLX peak bytes: (\d+)', test_log)]
        native_methods = re.findall(r'func (test\w+)\(', (candidate/'Tests/DurableSessionLifecycleTests/LifecycleNativeTests.swift').read_text())
        if len(test_peaks) != len(native_methods) or not test_peaks or max(test_peaks) > 128*1024**2: raise RuntimeError('native XCTest MLX observation')
        selected = sorted(re.findall(r'func (test\w+)\(', ''.join((candidate/'Tests/DurableSessionLifecycleTests'/n).read_text() for n in TEST_SOURCES)))
        passed = sorted(re.findall(r"Test Case '-\[DurableSessionLifecycleTests\.\w+ (test\w+)\]' passed", test_log))
        started_methods = sorted(re.findall(r"Test Case '-\[DurableSessionLifecycleTests\.\w+ (test\w+)\]' started", test_log))
        if not selected or selected != started_methods or selected != passed:
            raise RuntimeError('focused test enumeration/result mismatch')
        write_json(evidence/'tests.json', {'result': 'PASS', 'selected_methods': selected, 'started_methods': started_methods, 'passed_methods': passed, 'count': len(passed)})
        print(f'{len(passed)} focused tests PASS', flush=True)
        matrix = lifecycle_matrix(binary, harness, env, fixtures, logs, resources, evidence)
        if {p: sha(lm/p) for p in PRIOR_OUTPUTS} != PRIOR_OUTPUTS:
            raise RuntimeError('final composition changed')
        authenticate()
        for source, revision in revisions.items():
            if git(source, 'rev-parse', 'HEAD') != revision or git(source, 'status', '--porcelain', '--untracked-files=no'):
                raise RuntimeError('shared dependency source changed')
        if {str(p.relative_to(candidate)): sha(p) for p in candidate.rglob('*') if p.is_file()} != files:
            raise RuntimeError('candidate changed during run')
        outcome.update(result='PASS', new_xctest_methods=len(passed), real_death_cases=len(matrix),
            worker_binary_sha256=sha(binary), maximum_mlx_peak_bytes=max(test_peaks+[x['mlx_peak_bytes'] for x in matrix]),
            clock_gate='PASS', lifecycle_recovery='PASS')
        print(f'{len(matrix)} real process-death cases PASS', flush=True)
    except Exception as error:
        outcome.update(result='FAIL', error=str(error)); print(str(error), file=sys.stderr)
    finally:
        outcome['seconds'] = time.monotonic()-started
        outcome['supervision'] = 'At most four build jobs; one build/test or worker at a time; owned commands joined. No exhaustive opaque descendant claim.'
        write_json(evidence/'resources.json', {'observations': observations, 'companion_root': str(companion) if companion else None,
            'note': 'Command-boundary observations, not continuous peaks or RSS.'})
        shutil.rmtree(private)
        outcome['owned_source_build_fixture_copies_removed'] = not private.exists()
        write_json(evidence/'results.json', outcome)
        print(json.dumps(outcome, indent=2))
    return 0 if outcome['result'] == 'PASS' else 1

if __name__ == '__main__':
    sys.exit(main())
