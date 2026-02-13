# HIPAA 164.520 — Evaluated Document Change Description

**Reference:** `Dept__of_Health_and_Human_Services_164_520.txt`
**Evaluated:** `HIPAA_164_520_EVALUATED.txt`
**Purpose:** Demonstrate V3pi structural verification on a known set of changes

---

## Overview

The evaluated document is a modified copy of the HIPAA §164.520 regulation
(Notice of Privacy Practices). Eight deliberate changes were introduced to
test whether V3pi's structural verification can detect content substitutions,
negation changes, and logical operator changes in regulatory text.

All eight changes alter the legal meaning of the regulation. Some are
subtle (synonym substitution), others are severe (removing negation from
a protection clause). V3pi does not assess legal meaning — it detects
structural differences and reports them as evidence for qualified
professionals to review.

---

## Changes Made (8 total)

### Change 1 — "may" → "must" (line 10)

- **Reference:** `ered entity may rely, if such reliance is`
- **Evaluated:** `ered entity must rely, if such reliance is`
- **Legal effect:** Changes discretionary permission to mandatory obligation

### Change 2 — "may" → "should" (line 36)

- **Reference:** `covered entity may rely, if such reli-`
- **Evaluated:** `covered entity should rely, if such reli-`
- **Legal effect:** Changes permission to advisory recommendation

### Change 3 — Removed "not" (line 138)

- **Reference:** `does not have a right to notice under`
- **Evaluated:** `does have a right to notice under`
- **Legal effect:** Grants inmates a right to notice they do not currently have

### Change 4 — "and" → "or" (line 116)

- **Reference:** `tion; and`
- **Evaluated:** `tion; or`
- **Legal effect:** Changes conjunctive requirement (A AND B) to disjunctive option (A OR B)

### Change 5 — Inserted "not" (line 333)

- **Reference:** `tity is required to abide by the terms`
- **Evaluated:** `tity is not required to abide by the terms`
- **Legal effect:** Removes obligation to abide by notice terms

### Change 6 — Removed trailing "or" (line 96)

- **Reference:** `ance issuer or HMO; or`
- **Evaluated:** `ance issuer or HMO;`
- **Legal effect:** Removes the logical connector between two alternative provisions
- **Note:** The word "or" appears 85+ times in both documents. This tests whether the positional deletion is detected through frequency analysis.

### Change 7 — Removed "not" (line 357)

- **Reference:** `will not be retaliated against for filing`
- **Evaluated:** `will be retaliated against for filing`
- **Legal effect:** Inverts a core protection — states individuals will be retaliated against for filing complaints

### Change 8 — "permitted" → "allowed" (line 167)

- **Reference:** `permitted by this subpart to make for`
- **Evaluated:** `allowed by this subpart to make for`
- **Legal effect:** Semantically similar but uses a different regulatory term (synonym substitution)

---

## Summary

| # | Change | Line | Type | Legal Severity |
|---|--------|------|------|---------------|
| 1 | may → must | 10 | Word substitution | High — permission to obligation |
| 2 | may → should | 36 | Word substitution | Medium — permission to recommendation |
| 3 | Remove "not" | 138 | Negation removal | High — grants unintended right |
| 4 | and → or | 116 | Logical operator change | High — conjunctive to disjunctive |
| 5 | Insert "not" | 333 | Negation insertion | Critical — removes compliance obligation |
| 6 | Remove trailing "or" | 96 | Logical operator deletion | Medium — breaks clause linkage |
| 7 | Remove "not" | 357 | Negation removal | Critical — inverts retaliation protection |
| 8 | permitted → allowed | 167 | Synonym substitution | Low — near-synonym |

**V3pi detected all 8 changes.** The evidence package contains the complete
structural verification results. Use the V3pi verification utility to confirm the package has not been altered since generation.
