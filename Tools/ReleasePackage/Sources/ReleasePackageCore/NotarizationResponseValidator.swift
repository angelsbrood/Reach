import Foundation

struct AcceptedNotaryLog: Equatable {
  let submissionID: String
  let p3SHA256: String
  let archiveName: String
  let uploadDate: String
}

struct NotarizationResponseValidator {
  func submissionID(from data: Data) throws -> String {
    let object = try jsonObject(data)
    guard let value = object["id"] as? String, UUID(uuidString: value) != nil else {
      throw ReleasePackageError.verification("notary submit response has no durable UUID")
    }
    return value
  }

  func requireAcceptedWait(_ data: Data, submissionID: String) throws {
    let object = try jsonObject(data)
    guard object["id"] as? String == submissionID,
      let status = object["status"] as? String
    else {
      throw ReleasePackageError.verification("notary wait response is malformed")
    }
    guard status == "Accepted" else {
      throw ReleasePackageError.verification("notary service returned \(status)")
    }
  }

  func requireAcceptedLog(
    _ data: Data,
    submissionID: String,
    p3SHA256: String,
    archiveName: String,
    startedAtUTC: String?,
    now: Date = Date(),
    requireUploadWindow: Bool = true
  ) throws -> AcceptedNotaryLog {
    let object = try jsonObject(data)
    guard object["jobId"] as? String == submissionID,
      (object["sha256"] as? String)?.lowercased() == p3SHA256.lowercased(),
      object["archiveFilename"] as? String == archiveName,
      object["status"] as? String == "Accepted",
      (object["statusCode"] as? NSNumber)?.intValue == 0,
      issuesAreEmpty(object["issues"]),
      let uploadDate = object["uploadDate"] as? String,
      !requireUploadWindow
        || uploadFallsInWindow(uploadDate, startedAtUTC: startedAtUTC, now: now)
    else {
      throw ReleasePackageError.verification(
        "completed notary log does not bind the exact P3 lineage")
    }
    return AcceptedNotaryLog(
      submissionID: submissionID,
      p3SHA256: p3SHA256.lowercased(),
      archiveName: archiveName,
      uploadDate: uploadDate)
  }

  private func issuesAreEmpty(_ value: Any?) -> Bool {
    value is NSNull || (value as? [Any])?.isEmpty == true
  }

  private func jsonObject(_ data: Data) throws -> [String: Any] {
    let decoded: Any
    do {
      decoded = try JSONSerialization.jsonObject(with: data)
    } catch {
      throw ReleasePackageError.verification("notarytool response is malformed JSON")
    }
    guard let value = decoded as? [String: Any] else {
      throw ReleasePackageError.verification("notarytool response is not a JSON object")
    }
    return value
  }

  private func uploadFallsInWindow(
    _ value: String,
    startedAtUTC: String?,
    now: Date
  ) -> Bool {
    guard let startedAtUTC,
      let started = parseTimestamp(startedAtUTC),
      let uploaded = parseTimestamp(value)
    else { return false }
    return uploaded >= started.addingTimeInterval(-300)
      && uploaded <= now.addingTimeInterval(300)
  }

  private func parseTimestamp(_ value: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.date(from: value) ?? ISO8601DateFormatter().date(from: value)
  }
}
