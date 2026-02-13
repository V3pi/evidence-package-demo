Start by opening divergence.csv.

============================================================
V3pi Structural Verification — Evidence Package
============================================================

Client:        V3pi Public Demo — HIPAA 164.520 Verification
Determination: INCONSISTENT
Reference:     HIPAA 164 520 Original
Evaluated:     HIPAA 164 520 Evaluated
Generated:     2026-02-13T00:25:38Z
Service tier:  6

------------------------------------------------------------
FILES IN THIS PACKAGE
------------------------------------------------------------

  summary.csv                    High-level determination and counts
  divergence.csv                 All detected differences (START HERE)
  count_deltas.csv               Detail: frequency-only changes
  location_detail.csv            Every location of every divergent form
  concordance.csv                What did NOT change (shared forms)
  witnesses_concordance.csv      Occurrence-level concordance evidence
  witnesses_divergence.csv       Occurrence-level divergence evidence
  provenance.json                Machine-readable audit trail and verification policy
  inventory.json                 Hash inventory for package verification

------------------------------------------------------------
HOW TO READ THE RESULTS
------------------------------------------------------------

divergence.csv shows every detected structural difference
between the reference and evaluated documents.

Each row is one difference. The columns are:

  difference_type       What kind of difference:
    evaluated_only      Structure found ONLY in the evaluated document
    reference_only      Structure found ONLY in the reference document
    shared_count_delta  Structure present in both but at different frequency

  surface_term          The word or phrase involved (when available)
  reference_snippet     Excerpt from the reference document
  evaluated_snippet     Excerpt from the evaluated document
  reference_count       How many times this structure appears in the reference
  evaluated_count       How many times this structure appears in the evaluated
  structural_identifier Stable fingerprint used to anchor evidence

location_detail.csv lists every location where a divergent
form was detected, one row per location per side. Each row
shows which document (side), the position within that
document (token_position, char_start, char_end), and an
excerpt. The structural_identifier links each row back to
the corresponding entry in divergence.csv.

The verification policy that governed this determination is
recorded in provenance.json under the "policy" key. It defines,
for each structural level, whether differences must match
exactly, may be flagged for review, or may be reported without
affecting the determination.

inventory.json contains a SHA-256 hash for every file in
this package. Use the V3pi verification utility to confirm
that no files have been altered, added, or removed.

------------------------------------------------------------
METHODOLOGY
------------------------------------------------------------

V3pi does not compare text, tokens, schemas, or data
structures. Its unit of analysis is proprietary and not
equivalent to any conventional document comparison approach.

All structural identifiers are computed deterministically.
Given the same inputs and configuration, V3pi produces
identical results every time.

The conformance determination is governed by an explicit
verification policy. The policy defines, for each structural
level, whether differences must match exactly, may be flagged
for review, or may be reported without affecting the
determination. The policy is included in provenance.json.

------------------------------------------------------------
WHAT THIS PACKAGE IS NOT
------------------------------------------------------------

This package does not interpret, score, or assess meaning.
It provides structural evidence for qualified professionals
to review. All identifiers are computed deterministically
and verified by cryptographic hash.

V3pi does not replace expert judgment.
It supports expert judgment with defensible evidence.
