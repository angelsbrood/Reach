package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"

	"reach.dev/exo-runtime/internal/authority"
	"reach.dev/exo-runtime/internal/packageupdate"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: reach-exo-package (update|recover|rollback|verify-installed|assert-idle) [options]")
	}
	if os.Geteuid() != 0 {
		return errors.New("package operations require root")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "arm64" {
		return errors.New("package operations require Linux/arm64")
	}
	paths := packageupdate.DefaultPaths()
	switch arguments[0] {
	case "assert-idle":
		return packageupdate.CheckIdle(paths)
	case "assert-no-transaction":
		return packageupdate.CheckNoTransaction(paths)
	case "verify-installed":
		return packageupdate.VerifyRuntimeAuthority(paths)
	case "update", "rollback", "recover":
		return runTransaction(arguments[0], arguments[1:], paths)
	default:
		return fmt.Errorf("unknown package operation %q", arguments[0])
	}
}

func runTransaction(operation string, arguments []string, paths packageupdate.Paths) error {
	flags := flag.NewFlagSet(operation, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	candidateRoot := flags.String("candidate-root", "", "absolute extracted B bundle root")
	candidateArchive := flags.String("candidate-archive", "", "absolute B package archive")
	candidateSHA := flags.String("candidate-sha256", "", "authenticated B archive SHA-256")
	candidatePayloadSHA := flags.String("candidate-payload-sha256", "", "authenticated B payload-manifest SHA-256")
	candidateMetadataSHA := flags.String("candidate-metadata-sha256", "", "authenticated B metadata SHA-256")
	parentRoot := flags.String("parent-root", "", "absolute extracted exact A bundle root")
	parentArchive := flags.String("parent-archive", "", "absolute exact A package archive")
	parentSHA := flags.String("parent-sha256", authority.ParentPackageSHA256, "authenticated exact A archive SHA-256")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *candidateRoot == "" || *candidateArchive == "" || *candidateSHA == "" || *candidatePayloadSHA == "" || *candidateMetadataSHA == "" || *parentRoot == "" || *parentArchive == "" {
		return errors.New("candidate root/archive/archive-SHA/payload-SHA/metadata-SHA and parent root/archive are required")
	}
	if *parentSHA != authority.ParentPackageSHA256 {
		return errors.New("parent SHA-256 is not exact accepted A")
	}
	candidateDigests := packageupdate.ArtifactDigests{ArchiveSHA256: *candidateSHA, PayloadSHA256: *candidatePayloadSHA, MetadataSHA256: *candidateMetadataSHA}
	parentDigests := packageupdate.ArtifactDigests{ArchiveSHA256: *parentSHA, PayloadSHA256: authority.ParentPayloadSHA256, MetadataSHA256: authority.ParentMetadataSHA256}
	if operation == "recover" {
		return packageupdate.Recover(paths, nil, *candidateRoot, *candidateArchive, candidateDigests, *parentRoot, *parentArchive, parentDigests, "")
	}
	candidate, err := packageupdate.LoadArtifact(*candidateRoot, *candidateArchive, candidateDigests, paths.ExpectedOwner)
	if err != nil {
		return err
	}
	parent, err := packageupdate.LoadArtifact(*parentRoot, *parentArchive, parentDigests, paths.ExpectedOwner)
	if err != nil {
		return err
	}
	return packageupdate.Execute(packageupdate.Request{Operation: operation, Candidate: candidate, Parent: parent, Paths: paths})
}
