package packageupdate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"reach.dev/exo-runtime/internal/authority"
)

const (
	journalSchema = 2
	maxJournal    = 32 * 1024
)

var ErrInjected = errors.New("injected transaction interruption")

type Paths struct {
	RootPrefix      string
	TransactionRoot string
	LockPath        string
	GuardPath       string
	ExpectedOwner   int
}

func DefaultPaths() Paths {
	return Paths{
		RootPrefix:      "/",
		TransactionRoot: authorityPath("/", "/var/lib/reach-exo-transaction"),
		LockPath:        authorityPath("/", "/run/lock/reach-exo-package.lock"),
		GuardPath:       authorityPath("/", "/etc/systemd/system/reach-exo-node.service.d/90-package-transaction.conf"),
		ExpectedOwner:   0,
	}
}

func TestPaths(root string) Paths {
	return Paths{
		RootPrefix:      root,
		TransactionRoot: authorityPath(root, "/var/lib/reach-exo-transaction"),
		LockPath:        authorityPath(root, "/run/lock/reach-exo-package.lock"),
		GuardPath:       authorityPath(root, "/etc/systemd/system/reach-exo-node.service.d/90-package-transaction.conf"),
		ExpectedOwner:   os.Geteuid(),
	}
}

type Service interface {
	Intent() (enabled bool, active bool, err error)
	Stop() error
	SetEnabled(bool) error
	Start() error
	Reload() error
}

type SystemdService struct{}

func (SystemdService) Intent() (bool, bool, error) {
	enabled, err := systemctlPredicate("is-enabled")
	if err != nil {
		return false, false, err
	}
	active, err := systemctlPredicate("is-active")
	return enabled, active, err
}

func (SystemdService) Stop() error {
	if err := runSystemctl("stop", "reach-exo-node.service"); err != nil {
		return err
	}
	return runSystemctl("stop", "reach-exo-relay.service")
}

func (SystemdService) SetEnabled(enabled bool) error {
	verb := "disable"
	if enabled {
		verb = "enable"
	}
	return runSystemctl(verb, "reach-exo-node.service")
}

func (SystemdService) Start() error  { return runSystemctl("start", "reach-exo-node.service") }
func (SystemdService) Reload() error { return runSystemctl("daemon-reload") }

func systemctlPredicate(verb string) (bool, error) {
	command := exec.Command("systemctl", verb, "reach-exo-node.service")
	err := command.Run()
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() != 0 {
		return false, nil
	}
	return false, err
}

func runSystemctl(arguments ...string) error {
	command := exec.Command("systemctl", arguments...)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

type Request struct {
	Operation               string
	Candidate               *Artifact
	Parent                  *Artifact
	Service                 Service
	Paths                   Paths
	InterruptAfterPhase     string
	skipAuthorityValidation bool
}

type journal struct {
	Schema                  int    `json:"schema"`
	Operation               string `json:"operation"`
	Phase                   string `json:"phase"`
	SourceVersion           string `json:"source_version"`
	TargetVersion           string `json:"target_version"`
	CandidateRoot           string `json:"candidate_root"`
	CandidateArchive        string `json:"candidate_archive"`
	CandidateArchiveSHA256  string `json:"candidate_archive_sha256"`
	CandidatePayloadSHA256  string `json:"candidate_payload_sha256"`
	CandidateMetadataSHA256 string `json:"candidate_metadata_sha256"`
	ParentRoot              string `json:"parent_root"`
	ParentArchive           string `json:"parent_archive"`
	ParentArchiveSHA256     string `json:"parent_archive_sha256"`
	ParentPayloadSHA256     string `json:"parent_payload_sha256"`
	ParentMetadataSHA256    string `json:"parent_metadata_sha256"`
	WasEnabled              bool   `json:"was_enabled"`
	WasActive               bool   `json:"was_active"`
}

var durablePhases = []string{
	"authenticated", "guarded", "stopped", "program", "node-unit", "relay-unit",
	"sysusers", "tmpfiles", "receipt", "verified", "intent", "committed", "settled",
}

func Execute(request Request) error {
	if request.Service == nil {
		request.Service = SystemdService{}
	}
	if request.Operation != "update" && request.Operation != "rollback" {
		return errors.New("operation must be update or rollback")
	}
	if request.Candidate == nil || request.Parent == nil {
		return errors.New("both candidate B and exact parent A are required")
	}
	if !request.skipAuthorityValidation {
		if err := request.Candidate.ValidateCandidate(); err != nil {
			return err
		}
		if err := request.Parent.ValidateParent(); err != nil {
			return err
		}
	}
	lock, err := acquireLock(request.Paths)
	if err != nil {
		return err
	}
	defer releaseLock(lock)
	if _, err := discardUnpublishedStaging(request.Paths); err != nil {
		return err
	}
	if transactionEvidenceExists(request.Paths) {
		return errors.New("incomplete or completed transaction requires recovery")
	}

	source, target := request.Parent, request.Candidate
	if request.Operation == "rollback" {
		source, target = request.Candidate, request.Parent
	}
	if err := VerifyInstalled(request.Paths, source); err != nil {
		return fmt.Errorf("authenticate installed %s: %w", source.Metadata.BundleVersion, err)
	}
	enabled, active, err := request.Service.Intent()
	if err != nil {
		return err
	}
	state := journal{
		Schema: journalSchema, Operation: request.Operation, Phase: "authenticated",
		SourceVersion: source.Metadata.BundleVersion, TargetVersion: target.Metadata.BundleVersion,
		CandidateRoot: request.Candidate.Root, CandidateArchive: request.Candidate.Archive,
		CandidateArchiveSHA256: request.Candidate.ArchiveSHA256, CandidatePayloadSHA256: request.Candidate.PayloadSHA, CandidateMetadataSHA256: request.Candidate.MetadataSHA,
		ParentRoot: request.Parent.Root, ParentArchive: request.Parent.Archive,
		ParentArchiveSHA256: request.Parent.ArchiveSHA256, ParentPayloadSHA256: request.Parent.PayloadSHA, ParentMetadataSHA256: request.Parent.MetadataSHA,
		WasEnabled: enabled, WasActive: active,
	}
	if err := beginJournal(request, state); err != nil {
		return err
	}
	return continueTransaction(request, state, target)
}

func Recover(paths Paths, service Service, expectedCandidateRoot, expectedCandidateArchive string, expectedCandidate ArtifactDigests, expectedParentRoot, expectedParentArchive string, expectedParent ArtifactDigests, interruptAfter string) error {
	if service == nil {
		service = SystemdService{}
	}
	lock, err := acquireLock(paths)
	if err != nil {
		return err
	}
	defer releaseLock(lock)
	discarded, err := discardUnpublishedStaging(paths)
	if err != nil {
		return err
	}
	if discarded {
		return recoverUnstarted(paths, expectedCandidateRoot, expectedCandidateArchive, expectedCandidate, expectedParentRoot, expectedParentArchive, expectedParent)
	}
	if err := promoteStagedJournal(paths); err != nil {
		return err
	}
	state, fromCompletion, err := readRecoveryJournal(paths)
	if err != nil {
		return err
	}
	if state.candidateDigests() != expectedCandidate || state.parentDigests() != expectedParent {
		return errors.New("recovery artifact digests differ from durable journal")
	}
	if state.CandidateRoot != filepath.Clean(expectedCandidateRoot) || state.CandidateArchive != filepath.Clean(expectedCandidateArchive) || state.ParentRoot != filepath.Clean(expectedParentRoot) || state.ParentArchive != filepath.Clean(expectedParentArchive) {
		return errors.New("recovery artifact paths differ from durable journal")
	}
	candidate, err := LoadArtifact(state.CandidateRoot, state.CandidateArchive, expectedCandidate, paths.ExpectedOwner)
	if err != nil {
		return err
	}
	parent, err := LoadArtifact(state.ParentRoot, state.ParentArchive, expectedParent, paths.ExpectedOwner)
	if err != nil {
		return err
	}
	if err := candidate.ValidateCandidate(); err != nil {
		return err
	}
	if err := parent.ValidateParent(); err != nil {
		return err
	}
	return recoverLoaded(paths, service, candidate, parent, state, fromCompletion, interruptAfter, false)
}

func recoverUnstarted(paths Paths, expectedCandidateRoot, expectedCandidateArchive string, expectedCandidate ArtifactDigests, expectedParentRoot, expectedParentArchive string, expectedParent ArtifactDigests) error {
	candidate, candidateErr := LoadArtifact(expectedCandidateRoot, expectedCandidateArchive, expectedCandidate, paths.ExpectedOwner)
	parent, parentErr := LoadArtifact(expectedParentRoot, expectedParentArchive, expectedParent, paths.ExpectedOwner)
	if candidateErr != nil || parentErr != nil {
		return errors.New("unpublished transaction artifacts cannot be authenticated")
	}
	if err := candidate.ValidateCandidate(); err != nil {
		return err
	}
	if err := parent.ValidateParent(); err != nil {
		return err
	}
	if err := VerifyInstalled(paths, candidate); err == nil {
		return nil
	}
	if err := VerifyInstalled(paths, parent); err == nil {
		return nil
	}
	return errors.New("unpublished transaction did not leave exact A or exact B")
}

func recoverLoaded(paths Paths, service Service, candidate, parent *Artifact, state journal, fromCompletion bool, interruptAfter string, skipAuthorityValidation bool) error {
	request := Request{Operation: state.Operation, Candidate: candidate, Parent: parent, Service: service, Paths: paths, InterruptAfterPhase: interruptAfter}
	request.skipAuthorityValidation = skipAuthorityValidation
	target := candidate
	if state.Operation == "rollback" {
		target = parent
	}
	if fromCompletion {
		return finishCommitted(request, state, target)
	}
	return continueTransaction(request, state, target)
}

func continueTransaction(request Request, state journal, target *Artifact) error {
	if err := phaseAction(request, &state, "authenticated", func() error { return nil }); err != nil {
		return err
	}
	if err := establishWithdrawal(request, &state); err != nil {
		return err
	}
	if err := phaseAction(request, &state, "stopped", request.Service.Stop); err != nil {
		return err
	}
	targets := []struct{ phase, relative, absolute string }{
		{"program", "root/opt/reach-exo", "/opt/reach-exo"},
		{"node-unit", "root/usr/lib/systemd/system/reach-exo-node.service", "/usr/lib/systemd/system/reach-exo-node.service"},
		{"relay-unit", "root/usr/lib/systemd/system/reach-exo-relay.service", "/usr/lib/systemd/system/reach-exo-relay.service"},
		{"sysusers", "root/usr/lib/sysusers.d/reach-exo.conf", "/usr/lib/sysusers.d/reach-exo.conf"},
		{"tmpfiles", "root/usr/lib/tmpfiles.d/reach-exo.conf", "/usr/lib/tmpfiles.d/reach-exo.conf"},
	}
	for _, item := range targets {
		item := item
		if err := phaseAction(request, &state, item.phase, func() error {
			return replaceInstalledPath(request.Paths, filepath.Join(target.Root, filepath.FromSlash(item.relative)), authorityPath(request.Paths.RootPrefix, item.absolute))
		}); err != nil {
			return err
		}
	}
	if err := phaseAction(request, &state, "receipt", func() error {
		return writeReceipt(request.Paths, target, request.InterruptAfterPhase)
	}); err != nil {
		return err
	}
	if err := phaseAction(request, &state, "verified", func() error { return VerifyInstalled(request.Paths, target) }); err != nil {
		return err
	}
	if err := phaseAction(request, &state, "intent", func() error { return request.Service.SetEnabled(state.WasEnabled) }); err != nil {
		return err
	}
	if err := phaseAction(request, &state, "committed", func() error { return commitJournal(request.Paths, state) }); err != nil {
		return err
	}
	return finishCommitted(request, state, target)
}

func finishCommitted(request Request, state journal, target *Artifact) error {
	if err := VerifyInstalled(request.Paths, target); err != nil {
		return fmt.Errorf("committed generation is not complete: %w", err)
	}
	if err := removeGuard(request.Paths); err != nil {
		return err
	}
	if err := injectAt(request, "guard-removed"); err != nil {
		return err
	}
	if err := request.Service.Reload(); err != nil {
		return err
	}
	if err := injectAt(request, "guard-removal-reloaded"); err != nil {
		return err
	}
	if state.WasActive {
		if err := request.Service.Start(); err != nil {
			return err
		}
	}
	state.Phase = "settled"
	if request.InterruptAfterPhase == "settled" {
		return ErrInjected
	}
	return clearTransaction(request.Paths)
}

func establishWithdrawal(request Request, state *journal) error {
	if phaseIndex(state.Phase) > phaseIndex("guarded") {
		return nil
	}
	if phaseIndex(state.Phase) < phaseIndex("guarded") {
		if err := installGuard(request.Paths); err != nil {
			return err
		}
		if err := injectAt(request, "guard-published"); err != nil {
			return err
		}
		if err := request.Service.Reload(); err != nil {
			return err
		}
		if err := injectAt(request, "guard-reloaded"); err != nil {
			return err
		}
		pending := pendingJournalPath(request.Paths)
		if _, err := os.Lstat(pending); err == nil {
			if _, journalErr := os.Lstat(journalPath(request.Paths)); journalErr == nil || !os.IsNotExist(journalErr) {
				return errors.New("pending and active transaction journals are ambiguous")
			}
			if err := os.Rename(pending, journalPath(request.Paths)); err != nil {
				return err
			}
			if err := syncDirectory(request.Paths.TransactionRoot); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		} else if err := verifyAuthorityFileTuple(journalPath(request.Paths), request.Paths.ExpectedOwner, 0600); err != nil {
			return errors.New("authenticated transaction journal is absent after withdrawal")
		}
		if err := injectAt(request, "journal-promoted"); err != nil {
			return err
		}
		state.Phase = "guarded"
		if err := writeJournal(request.Paths, journalPath(request.Paths), *state); err != nil {
			return err
		}
	}
	return injectAt(request, "guarded")
}

func injectAt(request Request, edge string) error {
	if request.InterruptAfterPhase == edge {
		return ErrInjected
	}
	return nil
}

func phaseAction(request Request, state *journal, phase string, action func() error) error {
	if phaseIndex(state.Phase) > phaseIndex(phase) {
		return nil
	}
	if phaseIndex(state.Phase) < phaseIndex(phase) {
		if err := action(); err != nil {
			return err
		}
		state.Phase = phase
		if phase != "committed" {
			if err := writeJournal(request.Paths, journalPath(request.Paths), *state); err != nil {
				return err
			}
		}
	}
	if request.InterruptAfterPhase == phase {
		return ErrInjected
	}
	return nil
}

func phaseIndex(phase string) int {
	for index, value := range durablePhases {
		if value == phase {
			return index
		}
	}
	return -1
}

func VerifyInstalled(paths Paths, artifact *Artifact) error {
	return verifyInstalled(paths, artifact, true)
}

func verifyInstalled(paths Paths, artifact *Artifact, verifyAccountReceipt bool) error {
	if artifact == nil {
		return errors.New("installed authority is absent")
	}
	for relative, entry := range artifact.Entries {
		if !strings.HasPrefix(relative, "root/") {
			continue
		}
		installed := authorityPath(paths.RootPrefix, "/"+strings.TrimPrefix(relative, "root/"))
		info, err := os.Lstat(installed)
		if err != nil {
			return fmt.Errorf("installed path %s absent", installed)
		}
		kind := "file"
		if info.Mode()&os.ModeSymlink != 0 {
			kind = "symlink"
		}
		expectedMode := entry.Mode
		if entry.Kind == "file" && strings.HasPrefix(relative, "root/opt/reach-exo/") {
			expectedMode &^= 0222
		}
		if kind != entry.Kind || info.Mode().Perm() != expectedMode || info.Size() != entry.Bytes || ownerID(info) != paths.ExpectedOwner || linkCount(info) != 1 {
			return fmt.Errorf("installed path %s tuple differs", installed)
		}
		digest, err := pathDigest(installed)
		if err != nil || digest != entry.SHA256 {
			return fmt.Errorf("installed path %s digest differs", installed)
		}
	}
	expectedProgram := make(map[string]bool)
	for relative := range artifact.Entries {
		if strings.HasPrefix(relative, "root/opt/reach-exo/") {
			expectedProgram[filepath.Clean(authorityPath(paths.RootPrefix, "/"+strings.TrimPrefix(relative, "root/")))] = true
		}
	}
	programRoot := authorityPath(paths.RootPrefix, "/opt/reach-exo")
	seenProgram := make(map[string]bool, len(expectedProgram))
	if err := filepath.WalkDir(programRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if ownerID(info) != paths.ExpectedOwner {
			return fmt.Errorf("installed program path %s ownership differs", path)
		}
		if entry.IsDir() {
			if info.Mode().Perm() != 0555 {
				return fmt.Errorf("installed program directory %s mode differs", path)
			}
			return nil
		}
		if !expectedProgram[filepath.Clean(path)] {
			return fmt.Errorf("installed program contains unmanifested path %s", path)
		}
		seenProgram[filepath.Clean(path)] = true
		return nil
	}); err != nil {
		return err
	}
	if len(seenProgram) != len(expectedProgram) {
		return errors.New("installed program inventory is incomplete")
	}
	marker := authorityPath(paths.RootPrefix, "/var/lib/reach-exo/.bundle-created-account")
	markerInfo, statErr := os.Lstat(marker)
	if statErr != nil || !markerInfo.Mode().IsRegular() || markerInfo.Mode().Perm() != 0600 || ownerID(markerInfo) != paths.ExpectedOwner || linkCount(markerInfo) != 1 {
		return errors.New("installed account receipt tuple differs")
	}
	if verifyAccountReceipt {
		data, err := readBounded(marker, 4096)
		if err != nil {
			return errors.New("installed account receipt is absent")
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 3 || lines[0] != "reach-exo-lifecycle/"+artifact.Metadata.BundleVersion || !strings.HasPrefix(lines[1], "uid=") || !strings.HasPrefix(lines[2], "gid=") {
			return errors.New("installed account receipt differs")
		}
		if paths.RootPrefix == "/" {
			account, lookupErr := user.Lookup(authority.ServiceUser)
			uid, uidErr := strconv.Atoi(strings.TrimPrefix(lines[1], "uid="))
			gid, gidErr := strconv.Atoi(strings.TrimPrefix(lines[2], "gid="))
			if lookupErr != nil || uidErr != nil || gidErr != nil || account.Uid != strconv.Itoa(uid) || account.Gid != strconv.Itoa(gid) || account.HomeDir != authority.StateRoot {
				return errors.New("installed service account identity differs")
			}
		}
	}
	if artifact.Metadata.BundleVersion == authority.BundleVersion {
		receiptRoot := authorityPath(paths.RootPrefix, "/var/lib/reach-exo/receipts")
		for name, digest := range map[string]string{"PAYLOAD-MANIFEST.tsv": artifact.PayloadSHA, "package.json": artifact.MetadataSHA} {
			got, hashErr := fileSHA256(filepath.Join(receiptRoot, name), maxManifestBytes)
			if hashErr != nil || got != digest {
				return fmt.Errorf("installed receipt %s differs", name)
			}
		}
		archiveDigest, readErr := readBounded(filepath.Join(receiptRoot, "archive.sha256"), 128)
		if readErr != nil || strings.TrimSpace(string(archiveDigest)) != artifact.ArchiveSHA256 {
			return errors.New("installed archive receipt differs")
		}
	}
	if artifact.Metadata.BundleVersion == authority.ParentBundleVersion {
		if _, err := os.Lstat(authorityPath(paths.RootPrefix, "/var/lib/reach-exo/receipts")); err == nil || !os.IsNotExist(err) {
			return errors.New("B receipt survived exact-parent installation")
		}
	}
	return nil
}

// VerifyRuntimeAuthority is the installed B service-start boundary. It trusts
// only the root-owned receipt written after whole-product replacement, then
// rehashes every installed software payload object before provider creation.
func VerifyRuntimeAuthority(paths Paths) error {
	return verifyRuntimeAuthority(paths, true)
}

// VerifyServiceRuntimeAuthority repeats B's runtime payload and transaction
// checks after systemd's root ExecStartPre. The service account can authenticate
// the exact root-owned 0600 account-marker tuple but cannot read its contents;
// the privileged preflight owns that content and account-identity check.
func VerifyServiceRuntimeAuthority(paths Paths) error {
	return verifyRuntimeAuthority(paths, false)
}

func verifyRuntimeAuthority(paths Paths, verifyAccountReceipt bool) error {
	if _, err := os.Lstat(paths.GuardPath); err == nil || !os.IsNotExist(err) {
		return errors.New("package transaction guard is present or ambiguous")
	}
	if _, err := os.Lstat(stagedJournalRoot(paths)); err == nil || !os.IsNotExist(err) {
		return errors.New("staged package transaction is present or ambiguous")
	}
	var recognizedCompletion *journal
	if _, err := os.Lstat(paths.TransactionRoot); err == nil {
		state, completion, readErr := readRecoveryJournal(paths)
		if readErr != nil || !completion || state.Operation != "update" || state.TargetVersion != authority.BundleVersion {
			return errors.New("package transaction is incomplete or unrecognized")
		}
		recognizedCompletion = &state
	} else if !os.IsNotExist(err) {
		return errors.New("package transaction root is ambiguous")
	}
	receiptRoot := authorityPath(paths.RootPrefix, "/var/lib/reach-exo/receipts")
	metadataBytes, err := readBounded(filepath.Join(receiptRoot, "package.json"), 64*1024)
	if err != nil {
		return errors.New("installed B metadata receipt is absent")
	}
	var metadata Metadata
	decoder := json.NewDecoder(strings.NewReader(string(metadataBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return errors.New("installed B metadata receipt is invalid")
	}
	payloadPath := filepath.Join(receiptRoot, "PAYLOAD-MANIFEST.tsv")
	payloadBytes, err := readBounded(payloadPath, maxManifestBytes)
	if err != nil {
		return errors.New("installed B payload receipt is absent")
	}
	entries, err := parsePayloadRows(payloadBytes, "")
	if err != nil {
		return err
	}
	metadataDigest := sha256Bytes(metadataBytes)
	payloadDigest := sha256Bytes(payloadBytes)
	archiveBytes, err := readBounded(filepath.Join(receiptRoot, "archive.sha256"), 128)
	if err != nil || !validSHA(strings.TrimSpace(string(archiveBytes))) {
		return errors.New("installed B archive receipt is invalid")
	}
	artifact := &Artifact{Metadata: metadata, MetadataSHA: metadataDigest, PayloadSHA: payloadDigest, ArchiveSHA256: strings.TrimSpace(string(archiveBytes)), Entries: entries, authenticated: true}
	if err := artifact.validateCommon(); err != nil {
		return err
	}
	if err := artifact.ValidateCandidate(); err != nil {
		return err
	}
	if recognizedCompletion != nil && artifact.Digests() != recognizedCompletion.candidateDigests() {
		return errors.New("installed B receipts differ from committed transaction authority")
	}
	return verifyInstalled(paths, artifact, verifyAccountReceipt)
}

func CheckIdle(paths Paths) error {
	lock, err := acquireLock(paths)
	if err != nil {
		return err
	}
	defer releaseLock(lock)
	if transactionEvidenceExists(paths) {
		return errors.New("package transaction is incomplete")
	}
	return nil
}

func CheckNoTransaction(paths Paths) error {
	if transactionEvidenceExists(paths) {
		return errors.New("package transaction is incomplete")
	}
	return nil
}

func writeReceipt(paths Paths, artifact *Artifact, interruptAfter string) error {
	stateRoot := authorityPath(paths.RootPrefix, "/var/lib/reach-exo")
	marker := filepath.Join(stateRoot, ".bundle-created-account")
	data, err := readBounded(marker, 4096)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		return errors.New("account receipt is malformed")
	}
	markerData := []byte("reach-exo-lifecycle/" + artifact.Metadata.BundleVersion + "\n" + lines[1] + "\n" + lines[2] + "\n")
	if err := atomicWrite(marker, markerData, 0600); err != nil {
		return err
	}
	receiptRoot := filepath.Join(stateRoot, "receipts")
	if artifact.Metadata.BundleVersion == authority.ParentBundleVersion {
		if err := os.RemoveAll(receiptRoot); err != nil {
			return err
		}
		if interruptAfter == "receipt-removed" {
			return ErrInjected
		}
		if err := syncDirectory(stateRoot); err != nil {
			return err
		}
		if interruptAfter == "receipt-remove-parent-synced" {
			return ErrInjected
		}
		return nil
	}
	if err := os.MkdirAll(receiptRoot, 0755); err != nil {
		return err
	}
	if err := verifyAuthorityDirectoryTuple(receiptRoot, paths.ExpectedOwner, 0755); err != nil {
		return err
	}
	if interruptAfter == "receipt-created" {
		return ErrInjected
	}
	if err := syncDirectory(stateRoot); err != nil {
		return err
	}
	if interruptAfter == "receipt-create-parent-synced" {
		return ErrInjected
	}
	for name, source := range map[string]string{
		"PAYLOAD-MANIFEST.tsv": filepath.Join(artifact.Root, "PAYLOAD-MANIFEST.tsv"),
		"package.json":         filepath.Join(artifact.Root, "metadata", "package.json"),
	} {
		data, readErr := readBounded(source, maxManifestBytes)
		if readErr != nil {
			return readErr
		}
		if err := atomicWrite(filepath.Join(receiptRoot, name), data, 0644); err != nil {
			return err
		}
	}
	return atomicWrite(filepath.Join(receiptRoot, "archive.sha256"), []byte(artifact.ArchiveSHA256+"\n"), 0644)
}

func replaceInstalledPath(paths Paths, source, target string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	newPath := target + ".reach-exo-transaction-new"
	oldPath := target + ".reach-exo-transaction-old"
	_ = removeReplacementPath(newPath)
	_ = removeReplacementPath(oldPath)
	if info.IsDir() {
		readOnly := filepath.Clean(target) == filepath.Clean(authorityPath(paths.RootPrefix, "/opt/reach-exo"))
		if err := copyTree(source, newPath, paths.ExpectedOwner, readOnly); err != nil {
			return err
		}
	} else {
		if err := copyObject(source, newPath, info, paths.ExpectedOwner); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(target); err == nil {
		if err := os.Rename(target, oldPath); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(newPath, target); err != nil {
		_ = os.Rename(oldPath, target)
		return err
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	if err := removeReplacementPath(oldPath); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func removeReplacementPath(path string) error {
	if err := filepath.WalkDir(path, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			return os.Chmod(current, info.Mode().Perm()|0200)
		}
		return nil
	}); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.RemoveAll(path)
}

func copyTree(source, target string, owner int, readOnly bool) error {
	rootInfo, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if err := os.Mkdir(target, rootInfo.Mode().Perm()); err != nil {
		return err
	}
	err = filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == source {
			return nil
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.Mkdir(destination, info.Mode().Perm())
		}
		if err := copyObject(path, destination, info, owner); err != nil {
			return err
		}
		if readOnly && info.Mode().IsRegular() {
			return os.Chmod(destination, info.Mode().Perm()&^0222)
		}
		return nil
	})
	if err != nil {
		return err
	}
	var directories []string
	if err := filepath.WalkDir(target, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			directories = append(directories, path)
		}
		return nil
	}); err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if readOnly {
			info, err := os.Lstat(directories[index])
			if err != nil {
				return err
			}
			if err := os.Chmod(directories[index], info.Mode().Perm()&^0222); err != nil {
				return err
			}
		}
		if err := syncDirectory(directories[index]); err != nil {
			return err
		}
	}
	return nil
}

func copyObject(source, target string, info os.FileInfo, owner int) error {
	if info.Mode()&os.ModeSymlink != 0 {
		value, err := os.Readlink(source)
		if err != nil {
			return err
		}
		return os.Symlink(value, target)
	}
	if !info.Mode().IsRegular() {
		return errors.New("package contains unsupported installed object")
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err = io.Copy(output, input); err == nil {
		err = output.Sync()
	}
	closeErr := output.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func beginJournal(request Request, state journal) error {
	paths := request.Paths
	staging := stagedJournalRoot(paths)
	if err := os.MkdirAll(filepath.Dir(paths.TransactionRoot), 0755); err != nil {
		return err
	}
	if err := os.Mkdir(staging, 0700); err != nil {
		return err
	}
	if err := injectAt(request, "journal-staging-created"); err != nil {
		return err
	}
	if err := writeJournal(paths, filepath.Join(staging, "pending.json"), state); err != nil {
		return err
	}
	if err := injectAt(request, "journal-staged"); err != nil {
		return err
	}
	if err := os.Rename(staging, paths.TransactionRoot); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(paths.TransactionRoot)); err != nil {
		return err
	}
	return injectAt(request, "journal-published")
}

func discardUnpublishedStaging(paths Paths) (bool, error) {
	staging := stagedJournalRoot(paths)
	if _, err := os.Lstat(staging); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, errors.New("staged transaction journal is ambiguous")
	}
	if _, err := os.Lstat(paths.TransactionRoot); err == nil || !os.IsNotExist(err) {
		return false, errors.New("staged and published transaction journals are ambiguous")
	}
	if _, guardErr := os.Lstat(paths.GuardPath); guardErr == nil || !os.IsNotExist(guardErr) {
		return false, errors.New("unpublished transaction unexpectedly has a service guard")
	}
	if err := verifyAuthorityDirectoryTuple(staging, paths.ExpectedOwner, 0700); err != nil {
		return false, err
	}
	entries, err := os.ReadDir(staging)
	if err != nil {
		return false, err
	}
	switch {
	case len(entries) == 0:
	case len(entries) == 1 && entries[0].Name() == "pending.json.tmp":
		if err := verifyAuthorityFileTuple(filepath.Join(staging, entries[0].Name()), paths.ExpectedOwner, 0600); err != nil {
			return false, err
		}
	case len(entries) == 1 && entries[0].Name() == "pending.json":
		return false, nil
	default:
		return false, errors.New("staged transaction journal is absent or ambiguous")
	}
	if err := os.RemoveAll(staging); err != nil {
		return false, err
	}
	if err := syncDirectory(filepath.Dir(paths.TransactionRoot)); err != nil {
		return false, err
	}
	return true, nil
}

func promoteStagedJournal(paths Paths) error {
	staging := stagedJournalRoot(paths)
	if _, err := os.Lstat(staging); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return errors.New("staged transaction journal is ambiguous")
	}
	if _, err := os.Lstat(paths.TransactionRoot); err == nil || !os.IsNotExist(err) {
		return errors.New("staged and published transaction journals are ambiguous")
	}
	if err := verifyAuthorityDirectoryTuple(staging, paths.ExpectedOwner, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(staging)
	if err != nil || len(entries) != 1 || entries[0].Name() != "pending.json" {
		return errors.New("staged transaction journal is absent or ambiguous")
	}
	pending := filepath.Join(staging, "pending.json")
	if err := verifyAuthorityFileTuple(pending, paths.ExpectedOwner, 0600); err != nil {
		return err
	}
	if _, guardErr := os.Lstat(paths.GuardPath); guardErr == nil || !os.IsNotExist(guardErr) {
		return errors.New("staged transaction unexpectedly has a service guard")
	}
	data, err := readBounded(pending, maxJournal)
	if err != nil {
		return err
	}
	state, err := decodeJournal(data, "pending.json")
	if err != nil || state.Phase != "authenticated" {
		return errors.New("staged transaction journal is corrupt or unsupported")
	}
	if err := os.Rename(staging, paths.TransactionRoot); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(paths.TransactionRoot))
}

func installGuard(paths Paths) error {
	if err := os.MkdirAll(filepath.Dir(paths.GuardPath), 0755); err != nil {
		return err
	}
	return atomicWrite(paths.GuardPath, []byte("[Service]\nExecStartPre=/usr/bin/false\n"), 0644)
}

func removeGuard(paths Paths) error {
	if err := os.Remove(paths.GuardPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = os.Remove(filepath.Dir(paths.GuardPath))
	return syncDirectory(filepath.Dir(filepath.Dir(paths.GuardPath)))
}

func commitJournal(paths Paths, state journal) error {
	state.Phase = "committed"
	if err := writeJournal(paths, journalPath(paths), state); err != nil {
		return err
	}
	if err := os.Rename(journalPath(paths), completionPath(paths)); err != nil {
		return err
	}
	return syncDirectory(paths.TransactionRoot)
}

func clearTransaction(paths Paths) error {
	if err := os.RemoveAll(paths.TransactionRoot); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(paths.TransactionRoot))
}

func transactionEvidenceExists(paths Paths) bool {
	for _, path := range []string{paths.TransactionRoot, stagedJournalRoot(paths), paths.GuardPath} {
		if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
			return true
		}
	}
	return false
}

func readRecoveryJournal(paths Paths) (journal, bool, error) {
	rootInfo, err := os.Lstat(paths.TransactionRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0700 || ownerID(rootInfo) != paths.ExpectedOwner {
		return journal{}, false, errors.New("transaction recovery root is absent or has an invalid tuple")
	}
	entries, err := os.ReadDir(paths.TransactionRoot)
	if err != nil || len(entries) != 1 {
		return journal{}, false, errors.New("transaction recovery evidence is absent or ambiguous")
	}
	name := entries[0].Name()
	path := filepath.Join(paths.TransactionRoot, name)
	completion := false
	switch name {
	case "pending.json", "journal.json":
	case "completion.json":
		completion = true
	default:
		return journal{}, false, errors.New("transaction recovery evidence is unrecognized")
	}
	if err := verifyAuthorityFileTuple(path, paths.ExpectedOwner, 0600); err != nil {
		return journal{}, false, err
	}
	data, err := readBounded(path, maxJournal)
	if err != nil {
		return journal{}, false, err
	}
	state, err := decodeJournal(data, name)
	if err != nil {
		return journal{}, false, err
	}
	if _, guardErr := os.Lstat(paths.GuardPath); guardErr == nil {
		if err := verifyAuthorityFileTuple(paths.GuardPath, paths.ExpectedOwner, 0644); err != nil {
			return journal{}, false, err
		}
		guard, readErr := readBounded(paths.GuardPath, 1024)
		if readErr != nil || string(guard) != "[Service]\nExecStartPre=/usr/bin/false\n" {
			return journal{}, false, errors.New("transaction service guard differs")
		}
	} else if !os.IsNotExist(guardErr) || (!completion && name != "pending.json") {
		return journal{}, false, errors.New("transaction service guard is absent or ambiguous")
	}
	return state, completion, nil
}

func decodeJournal(data []byte, sourceName string) (journal, error) {
	var state journal
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return journal{}, errors.New("transaction journal is corrupt or unsupported")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return journal{}, errors.New("transaction journal contains trailing data")
	}
	if err := validateJournal(state, sourceName); err != nil {
		return journal{}, err
	}
	return state, nil
}

func (state journal) candidateDigests() ArtifactDigests {
	return ArtifactDigests{ArchiveSHA256: state.CandidateArchiveSHA256, PayloadSHA256: state.CandidatePayloadSHA256, MetadataSHA256: state.CandidateMetadataSHA256}
}

func (state journal) parentDigests() ArtifactDigests {
	return ArtifactDigests{ArchiveSHA256: state.ParentArchiveSHA256, PayloadSHA256: state.ParentPayloadSHA256, MetadataSHA256: state.ParentMetadataSHA256}
}

func validateJournal(state journal, sourceName string) error {
	if state.Schema != journalSchema || (state.Operation != "update" && state.Operation != "rollback") || phaseIndex(state.Phase) < 0 || state.Phase == "settled" {
		return errors.New("transaction journal is corrupt or unsupported")
	}
	if sourceName == "pending.json" && state.Phase != "authenticated" {
		return errors.New("pending transaction phase is invalid")
	}
	if sourceName == "completion.json" && state.Phase != "committed" {
		return errors.New("completion transaction phase is invalid")
	}
	for _, path := range []string{state.CandidateRoot, state.CandidateArchive, state.ParentRoot, state.ParentArchive} {
		if path == "" || !filepath.IsAbs(path) || path != filepath.Clean(path) {
			return errors.New("transaction artifact path relation is invalid")
		}
	}
	if state.CandidateRoot == state.ParentRoot || state.CandidateArchive == state.ParentArchive || !validArtifactDigests(state.candidateDigests()) || !validArtifactDigests(state.parentDigests()) {
		return errors.New("transaction artifact authority relation is invalid")
	}
	exactParent := ArtifactDigests{ArchiveSHA256: authority.ParentPackageSHA256, PayloadSHA256: authority.ParentPayloadSHA256, MetadataSHA256: authority.ParentMetadataSHA256}
	if state.parentDigests() != exactParent {
		return errors.New("transaction parent authority is not exact accepted A")
	}
	wantSource, wantTarget := authority.ParentBundleVersion, authority.BundleVersion
	if state.Operation == "rollback" {
		wantSource, wantTarget = authority.BundleVersion, authority.ParentBundleVersion
	}
	if state.SourceVersion != wantSource || state.TargetVersion != wantTarget {
		return errors.New("transaction operation/source/target relation is invalid")
	}
	return nil
}

func verifyAuthorityFileTuple(path string, owner int, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || ownerID(info) != owner || linkCount(info) != 1 {
		return errors.New("transaction authority file tuple differs")
	}
	return nil
}

func verifyAuthorityDirectoryTuple(path string, owner int, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != mode || ownerID(info) != owner {
		return errors.New("transaction authority directory tuple differs")
	}
	return nil
}

func writeJournal(paths Paths, path string, state journal) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(data)+1 > maxJournal {
		return errors.New("transaction journal exceeds bound")
	}
	return atomicWrite(path, append(data, '\n'), 0600)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if os.IsExist(err) {
		_ = os.Remove(temporary)
		file, err = os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	}
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func acquireLock(paths Paths) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(paths.LockPath), 0755); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(paths.LockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), paths.LockPath)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("transaction lock descriptor is unavailable")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || ownerID(info) != paths.ExpectedOwner || linkCount(info) != 1 {
		_ = file.Close()
		return nil, errors.New("transaction lock descriptor tuple differs")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("another package operation owns the transaction lock")
	}
	return file, nil
}

func releaseLock(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func journalPath(paths Paths) string { return filepath.Join(paths.TransactionRoot, "journal.json") }
func pendingJournalPath(paths Paths) string {
	return filepath.Join(paths.TransactionRoot, "pending.json")
}
func stagedJournalRoot(paths Paths) string { return paths.TransactionRoot + ".new" }
func completionPath(paths Paths) string {
	return filepath.Join(paths.TransactionRoot, "completion.json")
}

func authorityPath(root, absolute string) string {
	if root == "/" {
		return filepath.Clean(absolute)
	}
	return filepath.Join(root, strings.TrimPrefix(filepath.Clean(absolute), "/"))
}
