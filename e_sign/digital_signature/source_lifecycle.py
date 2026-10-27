"""
Source document lifecycle — retire signing requests for documents that can
no longer be signed.

When a tracked document is cancelled (or deleted), any signing request still
waiting on it is dead: the signer can't sign a cancelled document, yet the
request kept showing "DSC: Awaiting Signature" and its "Sign <doc>" ToDo
stayed open. Wired in hooks.py via doc_events on_cancel / on_trash, and
also called from get_signing_status as a fallback for requests left behind
before this hook existed.
"""

import frappe
from frappe.utils import now_datetime

OPEN_STATUSES = ("Pending", "In Progress", "Failed")


def on_source_cancel(doc, method=None):
	cancel_open_requests(doc.doctype, doc.name, reason=f"{doc.doctype} {doc.name} was cancelled")


def on_source_trash(doc, method=None):
	cancel_open_requests(doc.doctype, doc.name, reason=f"{doc.doctype} {doc.name} was deleted")


def cancel_open_requests(doctype, docname, reason):
	"""Cancel every open signing request on doctype/docname and close the
	signer's ToDo. Returns the names of the requests cancelled.

	Written with db.set_value like finalize, because the status transition
	rules don't allow In Progress / Failed -> Cancelled through a save.
	"""
	from e_sign.api.signing import _close_signer_todos
	from e_sign.digital_signature.audit import log_event

	names = frappe.get_all(
		"DSC Signing Request",
		filters={
			"source_doctype": doctype,
			"source_name": docname,
			"status": ["in", OPEN_STATUSES],
		},
		pluck="name",
	)
	for name in names:
		frappe.db.set_value(
			"DSC Signing Request",
			name,
			{"status": "Cancelled", "cancelled_on": now_datetime()},
		)
		log_event(name, "Request Cancelled", {"reason": reason, "automatic": True})
		_close_signer_todos(name)
	return names


def source_is_cancelled(doctype, docname):
	"""True when the source document is cancelled or no longer exists."""
	if doctype == "DSC Document Sign":
		return False
	meta = frappe.get_meta(doctype)
	if not meta.is_submittable:
		return not frappe.db.exists(doctype, docname)
	docstatus = frappe.db.get_value(doctype, docname, "docstatus")
	return docstatus is None or int(docstatus) == 2
