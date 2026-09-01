# Distribution notices

The generated bundle combines independently licensed components. The exact
materialization copies all distributed license texts into
`/opt/reach-exo/share/licenses` and emits a sorted Python distribution ledger.
Materialization fails when installed distribution metadata has neither a
license expression nor an accompanying license declaration.

Top-level identities:

- Reach EXO lifecycle supervisor and connector: Reach repository license.
- EXO 0.3.70 source: the EXO license copied from the authenticated source.
- Python 3.13.7 standalone runtime: the Python license copied from the exact
  runtime input.
- Go runtime linked into the two static binaries: the Go license copied from
  the exact compiler used by the reproducible binary build.
- Python wheels and source-built distributions: individual license texts and
  `PYTHON-DISTRIBUTIONS.tsv` generated from their installed `.dist-info`
  metadata.

The Qwen model is not distributed in this bundle. The operator supplies and
retains its immutable read-only snapshot and applicable model license
separately.

