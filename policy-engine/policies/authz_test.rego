# Unit tests for the authz policy. Run with:
#   opa test -v policy-engine/policies
#   (or) docker run --rm -v "$PWD/policy-engine/policies:/policies:ro" \
#     openpolicyagent/opa:1.20.2 test -v /policies
#
# The decision document served at POST /v1/data/authz/allow is the OBJECT
# {"allow": bool} — exactly the contract response body from
# docs/policymaker.md — so tests assert on the `allow` member. Every rule
# that can possibly allow a request has a positive AND a negative test.
package authz_test

import data.authz
import rego.v1

# ---------------------------------------------------------------------
# Reusable fixtures — the exact contract payload shape from
# docs/policymaker.md.
# ---------------------------------------------------------------------
customer_transfer := {
	"subject": {
		"user_id": "d0e6f1a2-3b4c-4d5e-8f90-1a2b3c4d5e6f",
		"roles": ["customer"],
	},
	"action": "TRANSFER",
	"resource": "account_987",
	"context": {
		"amount": 50.00,
		"ip_address": "192.168.1.50",
		"mTLS_verified": true,
	},
}

admin := object.union(customer_transfer, {
	"subject": {
		"user_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		"roles": ["admin"],
	},
	"action": "READ_CONFIG",
	"context": {
		"amount": 999999,
		"mTLS_verified": true,
	},
})

# ---------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------
test_customer_transfer_under_limit_allowed if {
	authz.allow.allow with input as customer_transfer
}

test_admin_override_allowed if {
	authz.allow.allow with input as admin
}

# ---------------------------------------------------------------------
# The decision document is the contract body, not a bare boolean
# ---------------------------------------------------------------------
test_decision_document_shape_is_object_with_allow_member if {
	payload := object.union(customer_transfer, {"action": "WITHDRAW"})
	authz.allow == {"allow": false} with input as payload
}

test_allowed_decision_document_shape if {
	authz.allow == {"allow": true} with input as customer_transfer
}

# ---------------------------------------------------------------------
# The fraud guardrail: threshold and sanity bounds
# ---------------------------------------------------------------------
test_transfer_over_limit_denied if {
	payload := object.union(customer_transfer, {"context": {"amount": 50000.01, "mTLS_verified": true}})
	not authz.allow.allow with input as payload
}

test_transfer_exactly_at_limit_allowed if {
	# Boundary: <= 50000 is allowed, 50000.01 is not.
	payload := object.union(customer_transfer, {"context": {"amount": 50000, "mTLS_verified": true}})
	authz.allow.allow with input as payload
}

test_transfer_zero_or_negative_amount_denied if {
	payload := object.union(customer_transfer, {"context": {"amount": 0, "mTLS_verified": true}})
	not authz.allow.allow with input as payload
}

test_transfer_negative_amount_denied if {
	payload := object.union(customer_transfer, {"context": {"amount": -50, "mTLS_verified": true}})
	not authz.allow.allow with input as payload
}

# ---------------------------------------------------------------------
# mTLS transport guarantee (Zero-Trust: no unverified channel)
# ---------------------------------------------------------------------
test_transfer_without_mtls_denied if {
	payload := object.union(customer_transfer, {"context": {"amount": 50, "mTLS_verified": false}})
	not authz.allow.allow with input as payload
}

test_transfer_missing_mtls_field_denied if {
	# NOTE: built explicitly — object.union deep-merges, so it cannot remove
	# a key from the base fixture's context.
	payload := {
		"subject": customer_transfer.subject,
		"action": customer_transfer.action,
		"resource": customer_transfer.resource,
		"context": {"amount": 50, "ip_address": "192.168.1.50"},
	}
	not authz.allow.allow with input as payload
}

# ---------------------------------------------------------------------
# Default deny: malformed, missing, or hostile input
# ---------------------------------------------------------------------
test_missing_subject_denied if {
	payload := object.union(customer_transfer, {"subject": null})
	not authz.allow.allow with input as payload
}

test_empty_input_denied if {
	not authz.allow.allow with input as {}
}

test_wrong_role_denied if {
	payload := object.union(customer_transfer, {"subject": {"user_id": "u", "roles": ["guest"]}})
	not authz.allow.allow with input as payload
}

test_unknown_action_denied if {
	payload := object.union(customer_transfer, {"action": "WITHDRAW"})
	not authz.allow.allow with input as payload
}

test_flat_roles_shape_from_division_md_denied if {
	# docs/division.md shows a flat shape ("roles" at the top level).
	# It must NOT match the contract shape and slip through.
	payload := {
		"subject": "user123",
		"roles": ["customer"],
		"action": "TRANSFER",
		"resource": "account_987",
		"context": {"ip": "192.168.1.50", "amount": 5000},
	}
	not authz.allow.allow with input as payload
}

test_missing_context_denied if {
	payload := object.union(customer_transfer, {"context": null})
	not authz.allow.allow with input as payload
}

test_amount_as_string_denied if {
	payload := object.union(customer_transfer, {"context": {"amount": "50", "mTLS_verified": true}})
	not authz.allow.allow with input as payload
}

test_customer_read_own_account_allowed if {
	payload := object.union(customer_transfer, {"action": "READ_ACCOUNT", "resource": sprintf("account_%s", [customer_transfer.subject.user_id])})
	authz.allow.allow with input as payload
}

test_customer_read_other_account_denied if {
	payload := object.union(customer_transfer, {"action": "READ_ACCOUNT", "resource": "account_someone_else"})
	not authz.allow.allow with input as payload
}

test_customer_read_without_mtls_denied if {
	payload := object.union(customer_transfer, {"action": "READ_ACCOUNT", "resource": sprintf("account_%s", [customer_transfer.subject.user_id]), "context": {"mTLS_verified": false}})
	not authz.allow.allow with input as payload
}

test_admin_without_mtls_denied if {
	payload := object.union(admin, {"context": {"mTLS_verified": false}})
	not authz.allow.allow with input as payload
}

test_admin_without_identity_denied if {
	payload := object.union(admin, {"subject": {"user_id": "", "roles": ["admin"]}})
	not authz.allow.allow with input as payload
}
