import Darwin
import Foundation

public struct NotarizedReleaseResult: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let submissionID: String
  public let p3SHA256: String
  public let p5Package: String
  public let p5SHA256: String
  public let provenance: String
  public let journal: String
}

private struct RecoveredSubmissionEvidence: Codable, Equatable {
  let schemaVersion: Int
  let submissionID: String
  let p3SHA256: String
  let archiveName: String
  let notaryLogSHA256: String
  let recoveryKind: String
}

private struct NestedSignatureEvidence: Codable, Equatable {
  let schemaVersion: Int
  let packageSHA256: String
  let p3ParentSHA256: String
  let applicationCertificateSHA1: String
  let installerCertificateSHA1: String
  let leafSHA256: [String]
  let teamID: String
  let trustedInstallerSignature: Bool
  let nestedSignaturesValid: Bool
}

private struct SignedPackageVerificationInputs {
  let configurationURL: URL
  let noticeAuthorityURL: URL
  let dependencyDepot: URL
}

public struct ReleaseNotarizer {
  private let runner: ProcessRunner

  public init(runner: ProcessRunner = .init()) {
    self.runner = runner
  }

  static func notarytoolEnvironment() -> [String: String] {
    ["HOME": FileManager.default.homeDirectoryForCurrentUser.path]
  }

  public func notarize(
    signedAuthority: URL,
    configurationURL: URL,
    noticeAuthorityURL: URL,
    dependencyDepot: URL,
    keychainProfile: String,
    stateURL: URL,
    outputRoot: URL,
    recoverSubmission: String? = nil
  ) throws -> NotarizedReleaseResult {
    try validateProfile(keychainProfile)
    let profileBinding = Digests.sha256(Data(keychainProfile.utf8))
    let outputRoot = try ReleasePathAuthority.mutableRoot(
      outputRoot, label: "notarized release output root")
    let store = NotarizationJournalStore(url: stateURL)
    return try store.withExclusiveLock {
      try SecureFiles.createPrivateDirectory(outputRoot)
      let signedProvenanceURL = signedAuthority.appendingPathComponent("release-provenance.json")
      let signedProvenance = try SignedReleaseProvenance.load(from: signedProvenanceURL)
      let verificationInputs = SignedPackageVerificationInputs(
        configurationURL: configurationURL,
        noticeAuthorityURL: noticeAuthorityURL,
        dependencyDepot: dependencyDepot)
      guard signedProvenance.p4 == nil, signedProvenance.p5 == nil else {
        throw ReleasePackageError.verification("signed authority is not the immutable P3 parent")
      }
      let p3 = signedAuthority.appendingPathComponent(
        signedProvenance.p3.signedContainer.path)
      let p3SHA256 = try Digests.sha256(file: p3)
      guard p3SHA256 == signedProvenance.p3.signedContainer.sha256 else {
        throw ReleasePackageError.verification("P3 changed before notarization")
      }
      let p3Verification = try SignedPackageStaticPreflight(runner: runner)
        .verifyP3BeforeSubmission(
          package: p3,
          provenance: signedProvenance,
          authorityRoot: signedAuthority,
          configurationURL: configurationURL,
          noticeAuthorityURL: noticeAuthorityURL,
          dependencyDepot: dependencyDepot,
          scratch: stateURL.deletingLastPathComponent().appendingPathComponent(
            "p3-preflight-\(UUID().uuidString.lowercased())"))
      let p3VerificationSHA256 = try retainP3VerificationReport(
        p3Verification, below: stateURL.deletingLastPathComponent())

      var journal = try loadOrPrepare(
        store: store,
        p3SHA256: p3SHA256,
        p3VerificationSHA256: p3VerificationSHA256,
        archiveName: p3.lastPathComponent,
        profileBinding: profileBinding)
      guard journal.p3SHA256 == p3SHA256,
        journal.p3VerificationSHA256 == p3VerificationSHA256,
        journal.archiveName == p3.lastPathComponent,
        journal.profileBindingSHA256 == profileBinding
      else {
        throw ReleasePackageError.verification(
          "notarization journal belongs to a different package or profile")
      }
      try validateProfileAuthentication(
        keychainProfile, logRoot: stateURL.deletingLastPathComponent())

      switch try NotarizationStateMachine.nextAction(
        journal, recoverSubmission: recoverSubmission)
      {
      case .submit:
        journal = try NotarizationStateMachine.submitting(journal, at: timestampUTC(Date()))
        try store.write(journal)
        journal = try submit(
          p3: p3, profile: keychainProfile, journal: journal, store: store,
          logRoot: stateURL.deletingLastPathComponent())
      case .recover(let submissionID):
        journal = try recover(
          submissionID: submissionID,
          p3: p3,
          profile: keychainProfile,
          journal: journal,
          store: store,
          logRoot: stateURL.deletingLastPathComponent())
      case .wait, .staple, .finished:
        break
      }

      if journal.phase == .submitted {
        journal = try waitForAcceptance(
          p3: p3,
          profile: keychainProfile,
          journal: journal,
          store: store,
          logRoot: stateURL.deletingLastPathComponent())
      }
      if journal.phase == .accepted,
        let recoveredP5 = try recoverCompletedP5IfPresent(
          outputRoot: outputRoot,
          signedAuthority: signedAuthority,
          signedProvenance: signedProvenance,
          journal: journal,
          verificationInputs: verificationInputs,
          logRoot: stateURL.deletingLastPathComponent())
      {
        journal = recoveredP5
        try store.write(journal)
      }
      guard journal.phase == .accepted || journal.phase == .stapled,
        let submissionID = journal.submissionID
      else {
        throw ReleasePackageError.verification("P3 has not earned accepted notarization authority")
      }

      if journal.phase == .accepted {
        let p5Attempt = stateURL.deletingLastPathComponent().appendingPathComponent(
          "p5-attempt-\(UUID().uuidString.lowercased())")
        try SecureFiles.createPrivateDirectory(p5Attempt)
        try materializeAcceptedAuthority(
          source: signedAuthority, destination: outputRoot,
          signedProvenance: signedProvenance,
          journal: journal,
          logRoot: stateURL.deletingLastPathComponent())
        let p5Scratch = p5Attempt.appendingPathComponent("Reach-0.0.1.pkg")
        try SecureFiles.copyRegularFile(from: p3, to: p5Scratch, mode: 0o600)
        let staple = try runner.run(
          "/usr/bin/xcrun", ["stapler", "staple", p5Scratch.path],
          logURL: p5Attempt.appendingPathComponent("stapler.log"))
        let validate = try runner.run(
          "/usr/bin/xcrun", ["stapler", "validate", p5Scratch.path],
          logURL: p5Attempt.appendingPathComponent("stapler-validate.log"))
        let inspector = CodeSignatureInspector(runner: runner)
        _ = try inspector.inspectInstallerPackage(
          p5Scratch,
          expectedCertificate: signedProvenance.p3.installerCertificate,
          logDirectory: p5Attempt)
        let preflight = try SignedPackageStaticPreflight(runner: runner).verify(
          package: p5Scratch,
          provenance: signedProvenance,
          authorityRoot: signedAuthority,
          configurationURL: configurationURL,
          noticeAuthorityURL: noticeAuthorityURL,
          dependencyDepot: dependencyDepot,
          scratch: p5Attempt.appendingPathComponent("preflight"),
          requireP3Hash: false)
        let assessment = try runner.run(
          "/usr/sbin/spctl",
          ["--assess", "--type", "install", "--verbose=4", p5Scratch.path],
          logURL: p5Attempt.appendingPathComponent("spctl-p5.log"))
        let nested = NestedSignatureEvidence(
          schemaVersion: 1,
          packageSHA256: try Digests.sha256(file: p5Scratch),
          p3ParentSHA256: p3SHA256,
          applicationCertificateSHA1: signedProvenance.p2.applicationCertificate.certificateSHA1,
          installerCertificateSHA1: signedProvenance.p3.installerCertificate.certificateSHA1,
          leafSHA256: signedProvenance.p2.signedLeaves.map(\.artifact.sha256).sorted(),
          teamID: signedProvenance.p2.applicationCertificate.teamID,
          trustedInstallerSignature: true,
          nestedSignaturesValid: preflight.hostFiles == 50 && preflight.helperFiles == 6)
        let nestedScratch = p5Attempt.appendingPathComponent("nested-verification.json")
        try SecureFiles.atomicWrite(try CanonicalJSON.encode(nested), to: nestedScratch)
        let p5Directory = outputRoot.appendingPathComponent("p5")
        try SecureFiles.createDirectory(p5Directory, mode: 0o700)
        let nestedURL = p5Directory.appendingPathComponent("nested-verification.json")
        try SecureFiles.copyRegularFile(from: nestedScratch, to: nestedURL, mode: 0o600)
        let p5 = outputRoot.appendingPathComponent("Reach-0.0.1.pkg")
        try SecureFiles.copyRegularFile(from: p5Scratch, to: p5, mode: 0o600)

        let currentProvenance = try SignedReleaseProvenance.load(
          from: outputRoot.appendingPathComponent("release-provenance.json"))
        let p5Provenance = SignedReleaseProvenance(
          schemaVersion: currentProvenance.schemaVersion,
          p0: currentProvenance.p0,
          p1: currentProvenance.p1,
          u1: currentProvenance.u1,
          p2: currentProvenance.p2,
          p3: currentProvenance.p3,
          p4: currentProvenance.p4,
          p5: .init(
            name: "P5-stapled-candidate",
            p3ParentSHA256: p3SHA256,
            stapledContainer: try artifact(path: "Reach-0.0.1.pkg", url: p5),
            stapleValidation: try retainedStapleValidation(
              staple: staple, validate: validate, directory: p5Directory),
            nestedVerification: try artifact(
              path: "p5/nested-verification.json", url: nestedURL),
            localAssessment: assessmentAuthority(assessment))
        )
        try p5Provenance.validate()
        try SecureFiles.atomicWrite(
          try CanonicalJSON.encode(p5Provenance),
          to: outputRoot.appendingPathComponent("release-provenance.json"))
        try writeSHA256SUMS(outputRoot)
        journal = try NotarizationStateMachine.stapled(
          journal, p5SHA256: try Digests.sha256(file: p5))
        try store.write(journal)
      }
      let p5 = outputRoot.appendingPathComponent("Reach-0.0.1.pkg")
      guard let p5SHA256 = journal.p5SHA256,
        try Digests.sha256(file: p5) == p5SHA256
      else {
        throw ReleasePackageError.verification("stapled candidate changed after acceptance")
      }
      _ = try verifyCompletedP5(
        outputRoot: outputRoot,
        signedAuthority: signedAuthority,
        signedProvenance: signedProvenance,
        expectedSubmissionID: submissionID,
        expectedP5SHA256: p5SHA256,
        verificationInputs: verificationInputs,
        logRoot: stateURL.deletingLastPathComponent())
      return NotarizedReleaseResult(
        schemaVersion: 1,
        submissionID: submissionID,
        p3SHA256: p3SHA256,
        p5Package: p5.path,
        p5SHA256: p5SHA256,
        provenance: outputRoot.appendingPathComponent("release-provenance.json").path,
        journal: stateURL.path)
    }
  }

  private func loadOrPrepare(
    store: NotarizationJournalStore,
    p3SHA256: String,
    p3VerificationSHA256: String,
    archiveName: String,
    profileBinding: String
  ) throws -> NotarizationJournal {
    if let existing = try store.load() { return existing }
    let value = try NotarizationStateMachine.prepared(
      p3SHA256: p3SHA256,
      p3VerificationSHA256: p3VerificationSHA256,
      archiveName: archiveName,
      profileBindingSHA256: profileBinding,
      at: timestampUTC(Date()))
    try store.write(value)
    return value
  }

  private func validateProfileAuthentication(_ profile: String, logRoot: URL) throws {
    let attempt = logRoot.appendingPathComponent(
      "profile-validation-\(UUID().uuidString.lowercased())")
    try SecureFiles.createPrivateDirectory(attempt)
    let version = try runner.run(
      "/usr/bin/xcrun", ["notarytool", "--version"],
      environment: Self.notarytoolEnvironment(), timeout: 30,
      logURL: attempt.appendingPathComponent("version.log"))
    let history = try runner.run(
      "/usr/bin/xcrun",
      ["notarytool", "history", "--keychain-profile", profile, "--output-format", "json"],
      environment: Self.notarytoolEnvironment(), timeout: 120,
      logURL: attempt.appendingPathComponent("history.json"),
      redactedArguments: [3: "<redacted-profile>"])
    struct ProfileValidation: Codable {
      let schemaVersion: Int
      let validated: Bool
      let toolVersionSHA256: String
      let historyStdoutSHA256: String
      let historyStderrSHA256: String
      let durationMilliseconds: Int64
    }
    let summary = ProfileValidation(
      schemaVersion: 1,
      validated: true,
      toolVersionSHA256: Digests.sha256(Data(version.output.utf8)),
      historyStdoutSHA256: Digests.sha256(Data(history.output.utf8)),
      historyStderrSHA256: Digests.sha256(Data(history.errorOutput.utf8)),
      durationMilliseconds: history.elapsedMilliseconds)
    try SecureFiles.atomicWrite(
      try CanonicalJSON.encode(summary),
      to: attempt.appendingPathComponent("summary.json"))
  }

  private func submit(
    p3: URL,
    profile: String,
    journal: NotarizationJournal,
    store: NotarizationJournalStore,
    logRoot: URL
  ) throws -> NotarizationJournal {
    let response = logRoot.appendingPathComponent("submit-response.json")
    guard !FileManager.default.fileExists(atPath: response.path) else {
      throw ReleasePackageError.verification(
        "submit output already exists without a durable submission identity")
    }
    do {
      _ = try runner.run(
        "/usr/bin/xcrun",
        [
          "notarytool", "submit", p3.path, "--keychain-profile", profile,
          "--output-format", "json",
        ],
        environment: Self.notarytoolEnvironment(), timeout: 1_800,
        logURL: response,
        redactedArguments: [4: "<redacted-profile>"])
    } catch {
      if let submissionID = try? NotarizationResponseValidator().submissionID(
        from: Data(contentsOf: response))
      {
        let value = try NotarizationStateMachine.submitted(
          journal,
          submissionID: submissionID,
          responseSHA256: try Digests.sha256(file: response))
        try store.write(value)
        return value
      }
      throw ReleasePackageError.verification(
        "notary upload outcome is ambiguous; preserve this lineage and recover its UUID")
    }
    let submissionID = try NotarizationResponseValidator().submissionID(
      from: Data(contentsOf: response))
    let value = try NotarizationStateMachine.submitted(
      journal,
      submissionID: submissionID,
      responseSHA256: try Digests.sha256(file: response))
    try store.write(value)
    return value
  }

  private func recover(
    submissionID: String,
    p3: URL,
    profile: String,
    journal: NotarizationJournal,
    store: NotarizationJournalStore,
    logRoot: URL
  ) throws -> NotarizationJournal {
    guard UUID(uuidString: submissionID) != nil else {
      throw ReleasePackageError.invalidArgument("recovery submission ID is not a UUID")
    }
    let logURL = logRoot.appendingPathComponent("recovery-notary-log-\(submissionID).json")
    _ = try runner.run(
      "/usr/bin/xcrun",
      [
        "notarytool", "log", submissionID, "--keychain-profile", profile,
        "--output-format", "json",
      ],
      environment: Self.notarytoolEnvironment(), timeout: 300,
      logURL: logURL,
      redactedArguments: [4: "<redacted-profile>"])
    _ = try NotarizationResponseValidator().requireAcceptedLog(
      Data(contentsOf: logURL),
      submissionID: submissionID,
      p3SHA256: try Digests.sha256(file: p3),
      archiveName: p3.lastPathComponent,
      startedAtUTC: journal.submissionStartedAtUTC)
    let evidence = RecoveredSubmissionEvidence(
      schemaVersion: 1,
      submissionID: submissionID,
      p3SHA256: journal.p3SHA256,
      archiveName: journal.archiveName,
      notaryLogSHA256: try Digests.sha256(file: logURL),
      recoveryKind: "completed-log-bound ambiguous submission")
    let evidenceURL = logRoot.appendingPathComponent("recovery-binding.json")
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(evidence), to: evidenceURL)
    let value = try NotarizationStateMachine.submitted(
      journal,
      submissionID: submissionID,
      responseSHA256: try Digests.sha256(file: evidenceURL))
    try store.write(value)
    return value
  }

  private func waitForAcceptance(
    p3: URL,
    profile: String,
    journal: NotarizationJournal,
    store: NotarizationJournalStore,
    logRoot: URL
  ) throws -> NotarizationJournal {
    let submissionID = try requireSubmissionID(journal)
    let acceptedWait = logRoot.appendingPathComponent("accepted-wait-response.json")
    if FileManager.default.fileExists(atPath: acceptedWait.path) {
      try NotarizationResponseValidator().requireAcceptedWait(
        try Self.privateArtifactData(acceptedWait), submissionID: submissionID)
    } else {
      let waitAttempt = logRoot.appendingPathComponent(
        "wait-\(UUID().uuidString.lowercased()).json")
      _ = try runner.run(
        "/usr/bin/xcrun",
        [
          "notarytool", "wait", submissionID, "--keychain-profile", profile,
          "--output-format", "json",
        ],
        environment: Self.notarytoolEnvironment(), timeout: 1_800,
        logURL: waitAttempt,
        redactedArguments: [4: "<redacted-profile>"])
      try NotarizationResponseValidator().requireAcceptedWait(
        try Self.privateArtifactData(waitAttempt), submissionID: submissionID)
      try SecureFiles.copyRegularFile(from: waitAttempt, to: acceptedWait, mode: 0o600)
    }
    let acceptedLog = logRoot.appendingPathComponent("accepted-notary-log.json")
    if FileManager.default.fileExists(atPath: acceptedLog.path) {
      _ = try NotarizationResponseValidator().requireAcceptedLog(
        try Self.privateArtifactData(acceptedLog),
        submissionID: submissionID,
        p3SHA256: try Digests.sha256(file: p3),
        archiveName: p3.lastPathComponent,
        startedAtUTC: journal.submissionStartedAtUTC)
    } else {
      let logAttempt = logRoot.appendingPathComponent(
        "notary-log-\(UUID().uuidString.lowercased()).json")
      _ = try runner.run(
        "/usr/bin/xcrun",
        [
          "notarytool", "log", submissionID, "--keychain-profile", profile,
          "--output-format", "json",
        ],
        environment: Self.notarytoolEnvironment(), timeout: 300,
        logURL: logAttempt,
        redactedArguments: [4: "<redacted-profile>"])
      _ = try NotarizationResponseValidator().requireAcceptedLog(
        try Self.privateArtifactData(logAttempt),
        submissionID: submissionID,
        p3SHA256: try Digests.sha256(file: p3),
        archiveName: p3.lastPathComponent,
        startedAtUTC: journal.submissionStartedAtUTC)
      try SecureFiles.copyRegularFile(from: logAttempt, to: acceptedLog, mode: 0o600)
    }
    let recovered = try Self.validateAcceptedArtifacts(
      waitURL: acceptedWait,
      logURL: acceptedLog,
      submissionID: submissionID,
      p3SHA256: try Digests.sha256(file: p3),
      archiveName: p3.lastPathComponent,
      startedAtUTC: journal.submissionStartedAtUTC)
    let value = try NotarizationStateMachine.accepted(
      journal,
      acceptedAtUTC: timestampUTC(Date()),
      waitResponseSHA256: recovered.waitResponseSHA256,
      notaryLogSHA256: recovered.notaryLogSHA256)
    try store.write(value)
    return value
  }

  static func validateAcceptedArtifacts(
    waitURL: URL,
    logURL: URL,
    submissionID: String,
    p3SHA256: String,
    archiveName: String,
    startedAtUTC: String?
  ) throws -> (waitResponseSHA256: String, notaryLogSHA256: String) {
    let waitData = try privateArtifactData(waitURL)
    let logData = try privateArtifactData(logURL)
    try NotarizationResponseValidator().requireAcceptedWait(
      waitData, submissionID: submissionID)
    _ = try NotarizationResponseValidator().requireAcceptedLog(
      logData,
      submissionID: submissionID,
      p3SHA256: p3SHA256,
      archiveName: archiveName,
      startedAtUTC: startedAtUTC,
      requireUploadWindow: startedAtUTC != nil)
    return (Digests.sha256(waitData), Digests.sha256(logData))
  }

  private static func privateArtifactData(_ url: URL) throws -> Data {
    var info = stat()
    guard lstat(url.path, &info) == 0,
      (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1,
      (info.st_mode & 0o7777) == 0o600
    else {
      throw ReleasePackageError.unsafePath(
        "notarization response must be a mode-0600 single-link regular file")
    }
    return try Data(contentsOf: url, options: [.mappedIfSafe])
  }

  private func materializeAcceptedAuthority(
    source: URL,
    destination: URL,
    signedProvenance: SignedReleaseProvenance,
    journal: NotarizationJournal,
    logRoot: URL
  ) throws {
    if !(try FileManager.default.contentsOfDirectory(atPath: destination.path).isEmpty) {
      let existing = try SignedReleaseProvenance.load(
        from: destination.appendingPathComponent("release-provenance.json"))
      guard existing.p0 == signedProvenance.p0,
        existing.p1 == signedProvenance.p1,
        existing.u1 == signedProvenance.u1,
        existing.p2 == signedProvenance.p2,
        existing.p3 == signedProvenance.p3,
        existing.p4 != nil,
        existing.p5 == nil,
        existing.p4?.submissionID == journal.submissionID
      else {
        throw ReleasePackageError.verification(
          "notarized output contains a different or incomplete lineage")
      }
      try verifyAcceptedArtifacts(existing, root: destination)
      return
    }
    try SecureFiles.copyTree(
      from: source, to: destination, directoryMode: 0o700, fileMode: 0o600)
    let p4Directory = destination.appendingPathComponent("p4")
    try SecureFiles.createDirectory(p4Directory, mode: 0o700)
    let submitSource = try submissionEvidence(
      matching: journal.submissionEvidenceSHA256,
      in: logRoot)
    let submitDestination = p4Directory.appendingPathComponent("submission-evidence.json")
    try SecureFiles.copyRegularFile(from: submitSource, to: submitDestination, mode: 0o600)
    let waitDestination = p4Directory.appendingPathComponent("wait-response.json")
    try SecureFiles.copyRegularFile(
      from: logRoot.appendingPathComponent("accepted-wait-response.json"),
      to: waitDestination, mode: 0o600)
    let logDestination = p4Directory.appendingPathComponent("notary-log.json")
    try SecureFiles.copyRegularFile(
      from: logRoot.appendingPathComponent("accepted-notary-log.json"),
      to: logDestination, mode: 0o600)
    let p4 = SignedReleaseProvenance(
      schemaVersion: signedProvenance.schemaVersion,
      p0: signedProvenance.p0,
      p1: signedProvenance.p1,
      u1: signedProvenance.u1,
      p2: signedProvenance.p2,
      p3: signedProvenance.p3,
      p4: .init(
        name: "P4-notary-accepted",
        signedContainerSHA256: signedProvenance.p3.signedContainer.sha256,
        submissionID: try requireSubmissionID(journal),
        status: "Accepted",
        submissionEvidence: try artifact(
          path: "p4/submission-evidence.json", url: submitDestination),
        waitResponse: try artifact(path: "p4/wait-response.json", url: waitDestination),
        notaryLog: try artifact(path: "p4/notary-log.json", url: logDestination),
        acceptedAtUTC: journal.acceptedAtUTC ?? "",
        issueCount: 0)
    )
    try p4.validate()
    try SecureFiles.atomicWrite(
      try CanonicalJSON.encode(p4),
      to: destination.appendingPathComponent("release-provenance.json"))
    try verifyAcceptedArtifacts(p4, root: destination)
    try writeSHA256SUMS(destination)
  }

  private func submissionEvidence(matching expectedSHA256: String?, in root: URL) throws -> URL {
    guard let expectedSHA256 else {
      throw ReleasePackageError.verification("accepted journal lacks submission evidence")
    }
    let candidates = ["submit-response.json", "recovery-binding.json"].map {
      root.appendingPathComponent($0)
    }.filter { FileManager.default.fileExists(atPath: $0.path) }
    let matches = try candidates.filter { try Digests.sha256(file: $0) == expectedSHA256 }
    guard matches.count == 1, let match = matches.first else {
      throw ReleasePackageError.verification(
        "submission evidence does not uniquely bind the accepted journal")
    }
    return match
  }

  private func verifyAcceptedArtifacts(
    _ provenance: SignedReleaseProvenance,
    root: URL
  ) throws {
    guard let p4 = provenance.p4, p4.submissionID != "" else {
      throw ReleasePackageError.verification("accepted output lacks P4 authority")
    }
    for value in [p4.submissionEvidence, p4.waitResponse, p4.notaryLog] {
      try verifyArtifact(value, below: root)
    }
    _ = try NotarizationResponseValidator().requireAcceptedLog(
      Data(contentsOf: root.appendingPathComponent(p4.notaryLog.path)),
      submissionID: p4.submissionID,
      p3SHA256: provenance.p3.signedContainer.sha256,
      archiveName: URL(fileURLWithPath: provenance.p3.signedContainer.path).lastPathComponent,
      startedAtUTC: nil,
      requireUploadWindow: false)
  }

  private func recoverCompletedP5IfPresent(
    outputRoot: URL,
    signedAuthority: URL,
    signedProvenance: SignedReleaseProvenance,
    journal: NotarizationJournal,
    verificationInputs: SignedPackageVerificationInputs,
    logRoot: URL
  ) throws -> NotarizationJournal? {
    let provenanceURL = outputRoot.appendingPathComponent("release-provenance.json")
    guard FileManager.default.fileExists(atPath: provenanceURL.path) else { return nil }
    let value = try SignedReleaseProvenance.load(from: provenanceURL)
    guard value.p5 != nil else { return nil }
    guard value.p0 == signedProvenance.p0,
      value.p1 == signedProvenance.p1,
      value.u1 == signedProvenance.u1,
      value.p2 == signedProvenance.p2,
      value.p3 == signedProvenance.p3,
      value.p4?.submissionID == journal.submissionID,
      let p5 = value.p5
    else {
      throw ReleasePackageError.verification("completed P5 belongs to a different lineage")
    }
    _ = try verifyCompletedP5(
      outputRoot: outputRoot,
      signedAuthority: signedAuthority,
      signedProvenance: signedProvenance,
      expectedSubmissionID: journal.submissionID ?? "",
      expectedP5SHA256: p5.stapledContainer.sha256,
      verificationInputs: verificationInputs,
      logRoot: logRoot)
    try writeSHA256SUMS(outputRoot)
    return try NotarizationStateMachine.stapled(
      journal, p5SHA256: p5.stapledContainer.sha256)
  }

  private func verifyCompletedP5(
    outputRoot: URL,
    signedAuthority: URL,
    signedProvenance: SignedReleaseProvenance,
    expectedSubmissionID: String,
    expectedP5SHA256: String,
    verificationInputs: SignedPackageVerificationInputs,
    logRoot: URL
  ) throws -> SignedReleaseProvenance {
    let provenance = try SignedReleaseProvenance.load(
      from: outputRoot.appendingPathComponent("release-provenance.json"))
    guard provenance.p0 == signedProvenance.p0,
      provenance.p1 == signedProvenance.p1,
      provenance.u1 == signedProvenance.u1,
      provenance.p2 == signedProvenance.p2,
      provenance.p3 == signedProvenance.p3,
      provenance.p4?.submissionID == expectedSubmissionID,
      let p5 = provenance.p5,
      p5.stapledContainer.sha256 == expectedP5SHA256
    else {
      throw ReleasePackageError.verification("completed P5 authority changed")
    }
    try verifyAcceptedArtifacts(provenance, root: outputRoot)
    for value in [p5.stapledContainer, p5.stapleValidation, p5.nestedVerification] {
      try verifyArtifact(value, below: outputRoot)
    }
    let p5Package = outputRoot.appendingPathComponent(p5.stapledContainer.path)
    let check = logRoot.appendingPathComponent(
      "p5-complete-check-\(UUID().uuidString.lowercased())")
    try SecureFiles.createPrivateDirectory(check)
    _ = try runner.run(
      "/usr/bin/xcrun", ["stapler", "validate", p5Package.path],
      logURL: check.appendingPathComponent("stapler-validate.log"))
    _ = try SignedPackageStaticPreflight(runner: runner).verify(
      package: p5Package,
      provenance: signedProvenance,
      authorityRoot: signedAuthority,
      configurationURL: verificationInputs.configurationURL,
      noticeAuthorityURL: verificationInputs.noticeAuthorityURL,
      dependencyDepot: verificationInputs.dependencyDepot,
      scratch: check.appendingPathComponent("preflight"),
      requireP3Hash: false)
    _ = try runner.run(
      "/usr/sbin/spctl", ["--assess", "--type", "install", "--verbose=4", p5Package.path],
      logURL: check.appendingPathComponent("spctl.log"))
    return provenance
  }

  private func retainP3VerificationReport(
    _ report: SignedReleaseVerificationReport,
    below root: URL
  ) throws -> String {
    let data = try CanonicalJSON.encode(report)
    let url = root.appendingPathComponent("p3-independent-verification.json")
    if FileManager.default.fileExists(atPath: url.path) {
      guard try Data(contentsOf: url, options: [.mappedIfSafe]) == data else {
        throw ReleasePackageError.verification(
          "retained independent P3 verification belongs to a different package")
      }
    } else {
      try SecureFiles.atomicWrite(data, to: url)
    }
    return Digests.sha256(data)
  }

  private func verifyArtifact(
    _ value: ReleaseProvenance.Artifact,
    below root: URL
  ) throws {
    try SecureFiles.validateRelativePath(value.path)
    let url = root.appendingPathComponent(value.path)
    var info = stat()
    guard lstat(url.path, &info) == 0,
      (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1,
      UInt64(info.st_size) == value.size,
      try Digests.sha256(file: url) == value.sha256
    else {
      throw ReleasePackageError.verification("retained notarization artifact changed")
    }
  }

  private func requireSubmissionID(_ journal: NotarizationJournal) throws -> String {
    guard let value = journal.submissionID, UUID(uuidString: value) != nil else {
      throw ReleasePackageError.verification("notarization journal has no submission UUID")
    }
    return value
  }

  private func validateProfile(_ value: String) throws {
    let forbidden = ["--password", "--apple-id", "--team-id", "--key", "\n", "\0"]
    guard !value.isEmpty,
      value.utf8.count <= 128,
      !forbidden.contains(where: value.contains),
      !value.hasPrefix("-"),
      !value.contains("/")
    else {
      throw ReleasePackageError.invalidArgument("notary Keychain profile label is malformed")
    }
  }

  private func timestampUTC(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: date)
  }

  private func artifact(path: String, url: URL) throws -> ReleaseProvenance.Artifact {
    try SecureFiles.validateRelativePath(path)
    var info = stat()
    guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1
    else {
      throw ReleasePackageError.unsafePath("notarized artifact is not a regular file")
    }
    return .init(
      path: path, size: UInt64(info.st_size), sha256: try Digests.sha256(file: url))
  }

  private func assessmentAuthority(_ result: CommandResult) -> AssessmentAuthority {
    .init(
      exitStatus: result.exitStatus,
      stdoutSHA256: Digests.sha256(Data(result.output.utf8)),
      stderrSHA256: Digests.sha256(Data(result.errorOutput.utf8)))
  }

  private func retainedStapleValidation(
    staple: CommandResult,
    validate: CommandResult,
    directory: URL
  ) throws -> ReleaseProvenance.Artifact {
    struct StapleValidation: Codable {
      let schemaVersion: Int
      let stapleExitStatus: Int32
      let stapleStdoutSHA256: String
      let stapleStderrSHA256: String
      let validateExitStatus: Int32
      let validateStdoutSHA256: String
      let validateStderrSHA256: String
    }
    let value = StapleValidation(
      schemaVersion: 1,
      stapleExitStatus: staple.exitStatus,
      stapleStdoutSHA256: Digests.sha256(Data(staple.output.utf8)),
      stapleStderrSHA256: Digests.sha256(Data(staple.errorOutput.utf8)),
      validateExitStatus: validate.exitStatus,
      validateStdoutSHA256: Digests.sha256(Data(validate.output.utf8)),
      validateStderrSHA256: Digests.sha256(Data(validate.errorOutput.utf8)))
    let url = directory.appendingPathComponent("staple-validation.json")
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(value), to: url)
    return try artifact(path: "p5/staple-validation.json", url: url)
  }

  private func writeSHA256SUMS(_ root: URL) throws {
    let entries = try SecureFiles.enumerateTree(root).filter { url in
      var info = stat()
      return lstat(url.path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFREG
        && url.lastPathComponent != "SHA256SUMS"
    }.sorted { $0.path < $1.path }
    let lines =
      try entries.map { url in
        let relative = String(url.path.dropFirst(root.path.count + 1))
        return "\(try Digests.sha256(file: url))  ./\(relative)"
      }.joined(separator: "\n") + "\n"
    try SecureFiles.atomicWrite(Data(lines.utf8), to: root.appendingPathComponent("SHA256SUMS"))
  }
}
