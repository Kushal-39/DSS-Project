# ABAC policy for the Zero-Trust architecture (Person 3).
#
# Contract (docs/policymaker.md, docs/division.md):
#   Query:  POST /v1/data/authz/allow  with the payload wrapped in {"input": ...}
#   Reply:  {"result": {"allow": true}} or {"result": {"allow": false}}
#
# The `allow` rule is therefore an OBJECT shaped {"allow": bool}: querying
# data.authz.allow then returns exactly the documented response body. The
# boolean decision logic lives in `authorized`. (A plain boolean `allow`
# would make /v1/data/authz/allow return {"result": true} — not the shape
# Persons 4/5 are contracted to parse.)
#
# Rule 1 — Default Deny: the default answer is always false. Malformed,
# missing, or suspicious input never matches an allow rule, so it is denied.
package authz

import rego.v1

# Tunable knobs (single line to change in review/emergency).
max_transfer_amount := 50000

# ---------------------------------------------------------------------
# Decision document served at POST /v1/data/authz/allow.
# ---------------------------------------------------------------------
default allow := {"allow": false}

allow := {"allow": true} if {
	authorized
}

# ---------------------------------------------------------------------
# Admin override: admins are trusted principals.
# Still requires the subject block to be well-formed.
# ---------------------------------------------------------------------
authorized if {
	valid_request
	is_object(input.subject)
	"admin" in input.subject.roles
}

# ---------------------------------------------------------------------
# TRANSFER: authenticated customer moving a sane amount over a
# mutually-TLS-verified connection.
#
# NOTE (input shape): docs/policymaker.md nests roles under
# input.subject.roles; docs/division.md shows a flat input.roles.
# This rule reads the contract shape (input.subject.roles). A flat
# payload simply fails to match and is denied by default — Persons 4/5
# must send the policymaker.md shape exactly.
# ---------------------------------------------------------------------
authorized if {
	valid_request
	input.action == "TRANSFER"
	is_object(input.subject)
	"customer" in input.subject.roles
	is_object(input.context)
	is_number(input.context.amount)
	input.context.amount <= max_transfer_amount
	input.context.amount > 0
	input.context.mTLS_verified == true
}

# Reading balances is sensitive too: customers may read only their own account.
authorized if {
	valid_request
	input.action == "READ_ACCOUNT"
	"customer" in input.subject.roles
	input.resource == sprintf("account_%s", [input.subject.user_id])
	input.context.mTLS_verified == true
}

# A privileged role never substitutes for an attributable, verified request.
valid_request if {
	is_object(input.subject)
	is_string(input.subject.user_id)
	input.subject.user_id != ""
	is_array(input.subject.roles)
	is_string(input.action)
	input.action != ""
	is_string(input.resource)
	input.resource != ""
	is_object(input.context)
	input.context.mTLS_verified == true
}
