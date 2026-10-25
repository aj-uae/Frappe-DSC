"""
PDF Signing Engine — pyHanko integration for deferred signing.

This module handles:
1. Generating PDF from Frappe print format
2. Adding a PAdES signature placeholder with visual stamp
3. Computing the SHA-256 hash to be signed
4. Injecting the signature bytes returned by the desktop agent
5. Verifying the resulting signed PDF

Uses pyHanko's "interrupted signing" workflow:
  PdfSigner → PdfSigningSession → PdfTBSDocument → digest → inject → verify
"""

import asyncio
import base64
import dataclasses
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from io import BytesIO
from zoneinfo import ZoneInfo

import frappe
from frappe.utils import now_datetime

from e_sign.digital_signature.signature_anchor import locate_signature_anchor

from asn1crypto import algos, cms, core, x509 as asn1_x509
from pyhanko import stamp as pyhanko_stamp
from pyhanko.pdf_utils import layout as pyhanko_layout
from pyhanko.pdf_utils import text as pyhanko_text
from pyhanko.pdf_utils import generic as pdf_generic
from pyhanko.pdf_utils.font import api as pyhanko_font_api
from pyhanko.pdf_utils.font.basic import SimpleFontEngine, SimpleFontEngineFactory
from pyhanko.pdf_utils.images import PdfImage
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields as sig_fields
from pyhanko.sign.signers.pdf_byterange import PreparedByteRangeDigest
from pyhanko.sign.signers.pdf_cms import ExternalSigner
from pyhanko.sign.signers.pdf_signer import (
	PdfSignatureMetadata,
	PdfSigner,
	PdfTBSDocument,
)
from pyhanko_certvalidator.registry import SimpleCertificateStore


# Sessions are stored in Frappe's Redis cache so they survive across worker
# processes, bench restarts, and live-reloads — an in-memory dict here would be
# lost any time the worker recycled, breaking finalize with "session expired".
_SESSION_KEY_PREFIX = "e_sign:session:"
_SESSION_TTL_SECONDS = 600  # 10 minutes — enough for the user to enter a PIN


def _session_key(session_id):
	return _SESSION_KEY_PREFIX + session_id


def _store_session(session_id, data):
	frappe.cache().set_value(
		_session_key(session_id),
		json.dumps(data, default=str),
		expires_in_sec=_SESSION_TTL_SECONDS,
	)


def _load_session(session_id, pop=False):
	key = _session_key(session_id)
	raw = frappe.cache().get_value(key)
	if not raw:
		return None
	if pop:
		frappe.cache().delete_value(key)
	if isinstance(raw, bytes):
		raw = raw.decode("utf-8")
	return json.loads(raw)


def prepare_pdf_for_signing(
	doctype,
	docname,
	print_format,
	sig_template,
	profile,
	signing_request_name,
	cert_der,
	signer_location_text=None,
	pdf_bytes=None,
	placement=None,
):
	"""Phase 1: build a PAdES-compliant PDF, return the SignedAttrs hash for the token.

	Implements the proper deferred external signing flow:
	1. pyHanko places the signature dictionary with a fixed-size placeholder
	2. pyHanko computes the ByteRange digest (sha256 of bytes excluding placeholder)
	3. We build CMS SignedAttrs manually with that digest as `message-digest`
	4. The token signs sha256(SignedAttrs DER) — that goes into SignerInfo.signature
	5. finalize_signed_pdf injects the complete CMS into the placeholder

	cert_der is the signer's certificate from the token — required because
	SignedAttrs references the signer-certificate via `signing-certificate-v2`
	and Adobe's verifier checks that the cert chain in the CMS matches.

	pdf_bytes / placement support ad-hoc uploaded-document signing (DSC Document
	Sign): when pdf_bytes is given, that PDF is signed as-is instead of being
	rendered from a print format, and placement — a dict of
	{page, x, y, width, height} in PDF points — positions the signature box
	instead of the saved signature template field.

	Returns:
		dict with session_id, hash_to_sign (hex of SignedAttrs hash), hash_algorithm, expected_cert_fingerprint
	"""
	if pdf_bytes is None:
		pdf_bytes = generate_pdf_from_print_format(doctype, docname, print_format)

	if placement:
		# Interactive placement (uploaded document) — coordinates already in
		# PDF points with origin at the bottom-left, exactly what pyHanko wants.
		page_number = max(int(placement.get("page") or 1) - 1, 0)
		px = placement.get("x") or 0
		py = placement.get("y") or 0
		box = (
			px,
			py,
			px + (placement.get("width") or 200),
			py + (placement.get("height") or 80),
		)
	else:
		# Dynamic placeholder takes precedence: if the print format used
		# {{ dsc_signature_anchor(...) }}, stamp the signature wherever that
		# marker landed in the rendered PDF (flows with variable content, e.g.
		# a Sales Invoice's line items). Falls back to the Signature Template's
		# fixed coordinates when no anchor is present.
		anchor = locate_signature_anchor(pdf_bytes)
		if anchor:
			page_number = anchor["page"]
			box = (
				anchor["x"],
				anchor["top"] - anchor["height"],
				anchor["x"] + anchor["width"],
				anchor["top"],
			)
		else:
			sig_field_row = None
			if sig_template.fields:
				sig_field_row = sig_template.fields[0]

			page_number = (sig_field_row.page_number - 1) if sig_field_row else 0
			box = None
			if sig_field_row and sig_field_row.x and sig_field_row.y:
				box = (
					sig_field_row.x,
					sig_field_row.y,
					sig_field_row.x + (sig_field_row.width or 200),
					sig_field_row.y + (sig_field_row.height or 80),
				)

	settings = frappe.get_single("DSC Settings")
	hash_algorithm = settings.default_hash_algorithm or "sha256"
	reason = settings.default_reason or "Approved"
	location = signer_location_text or settings.default_location or ""
	signer_name = profile.certificate_common_name or profile.label or profile.profile_name
	stamp_text = build_stamp_text(sig_template, profile, signer_location_text=location)
	stamp_style = build_stamp_style(sig_template, profile, stamp_text)

	session_id = str(uuid.uuid4())
	signer_cert = asn1_x509.Certificate.load(cert_der)

	field_name = f"DSC_Signature_{signing_request_name}"
	new_field = sig_fields.SigFieldSpec(
		sig_field_name=field_name,
		on_page=page_number,
		box=box,
	)
	sig_meta = PdfSignatureMetadata(
		field_name=field_name,
		md_algorithm=hash_algorithm,
		location=location,
		reason=reason,
		name=signer_name,
	)

	# ExternalSigner needs *some* signature_value at construction time — pyHanko
	# only uses it during async_sign which we don't call here. The deferred
	# helper (async_digest_doc_for_signing) only needs the cert to size the
	# placeholder. We pass a max-size zeroed value; the real signature replaces
	# it via PdfTBSDocument.finish_signing in phase 2.
	placeholder_signer = ExternalSigner(
		signing_cert=signer_cert,
		cert_registry=SimpleCertificateStore(),
		signature_value=b"\x00" * 512,
	)

	pdf_input = BytesIO(pdf_bytes)
	pdf_writer = IncrementalPdfFileWriter(pdf_input)
	pdf_signer = PdfSigner(
		signature_meta=sig_meta,
		signer=placeholder_signer,
		stamp_style=stamp_style,
		new_field_spec=new_field,
	)

	output = BytesIO()

	async def _prepare():
		# Reserve enough room for the full CMS — Indian DSCs have a 3-cert
		# chain (signer → CA → CCA root) plus OCSP, which pushes the CMS
		# past pyHanko's default 8 KB estimate. 32 KB gives comfortable
		# headroom without bloating the PDF.
		return await pdf_signer.async_digest_doc_for_signing(
			pdf_out=pdf_writer,
			output=output,
			bytes_reserved=32768,
		)

	prep_digest, _tbs_doc, _ = asyncio.run(_prepare())

	# Capture the prepared PDF bytes (with placeholder) — these are what
	# finalize will inject the CMS into. We must preserve byte-for-byte.
	output.seek(0)
	prepared_pdf_bytes = output.read()

	# Build CMS SignedAttrs manually. The token signs sha256 of this DER.
	signing_time = datetime.now(timezone.utc).replace(microsecond=0)
	signed_attrs = cms.CMSAttributes([
		cms.CMSAttribute({
			"type": "content_type",
			"values": [cms.ContentType("data")],
		}),
		cms.CMSAttribute({
			"type": "signing_time",
			"values": [cms.Time({"utc_time": signing_time})],
		}),
		cms.CMSAttribute({
			"type": "message_digest",
			"values": [core.OctetString(prep_digest.document_digest)],
		}),
	])
	signed_attrs_der = signed_attrs.dump()
	hash_to_sign_hex = hashlib.sha256(signed_attrs_der).hexdigest()

	_store_session(session_id, {
		"hash_algorithm": hash_algorithm,
		"field_name": field_name,
		"signing_request_name": signing_request_name,
		"doctype": doctype,
		"docname": docname,
		"print_format": print_format,
		"created_at": str(now_datetime()),
		"prepared_pdf_b64": base64.b64encode(prepared_pdf_bytes).decode("ascii"),
		"signed_attrs_b64": base64.b64encode(signed_attrs_der).decode("ascii"),
		"cert_der_b64": base64.b64encode(cert_der).decode("ascii"),
		"prep_digest": {
			"document_digest_hex": prep_digest.document_digest.hex(),
			"reserved_region_start": prep_digest.reserved_region_start,
			"reserved_region_end": prep_digest.reserved_region_end,
		},
	})

	cert_fingerprint = hashlib.sha256(cert_der).hexdigest()

	return {
		"session_id": session_id,
		"hash_to_sign": hash_to_sign_hex,
		"hash_algorithm": hash_algorithm,
		"expected_cert_fingerprint": cert_fingerprint,
	}


def _load_chain_cert(cert_b64):
	"""Parse one intermediate cert sent by the bridge.

	Some CAs (e.g. SignX) publish their AIA .cer as bare base64 or PEM text, and
	the bridge forwards those bytes as-is, so the payload can be base64 of
	base64. The chain is optional for the signature, so an unreadable entry is
	logged and skipped rather than failing the whole signing.
	"""
	data = base64.b64decode(cert_b64)
	stripped = data.strip()
	if stripped.startswith(b"-----BEGIN"):
		stripped = b"".join(
			line for line in stripped.splitlines() if line and not line.startswith(b"-----")
		)
	if stripped[:1] != b"\x30":
		try:
			data = base64.b64decode(stripped, validate=False)
		except (ValueError, TypeError):
			pass
	try:
		cert = asn1_x509.Certificate.load(data)
		cert.native  # force a full parse so bad DER fails here
		return cert
	except Exception:
		frappe.log_error(title="DSC: skipped unreadable chain certificate")
		return None


def finalize_signed_pdf(
	session_id,
	signature_bytes_b64,
	cert_der_b64,
	cert_chain_der_b64=None,
	ocsp_der_b64=None,
):
	"""Phase 2: Build CMS from the token signature, inject into the prepared placeholder.

	The prepared PDF (with placeholder) and the SignedAttrs we hashed in
	prepare are both stored in the session. We:
	1. Construct the full CMS ContentInfo with the token's signature value
	2. Use PreparedByteRangeDigest.fill_with_cms to drop those bytes into the
	   reserved region without touching the rest of the PDF.

	The result is a PAdES-compliant PDF where Adobe's verifier hashes the
	exact bytes the token signed.

	Args:
		session_id: session ID from prepare step
		signature_bytes_b64: base64-encoded raw signature from the agent
		cert_der_b64: base64-encoded signer certificate (from the bridge —
			should match the cert stored at prepare time)
		cert_chain_der_b64: list of base64-encoded intermediate certs (DER)
		ocsp_der_b64: base64-encoded OCSP response (DER) — currently unused
	"""
	session = _load_session(session_id, pop=True)
	if not session:
		frappe.throw("Signing session expired or not found. Please try again.")

	signature_bytes = base64.b64decode(signature_bytes_b64)

	# Prefer the cert from session (matches what we built SignedAttrs against).
	# The bridge re-sends it on /sign for redundancy, but if there's any
	# mismatch we must trust the prepare-time cert.
	cert_der = base64.b64decode(session["cert_der_b64"])
	signer_cert = asn1_x509.Certificate.load(cert_der)

	chain_certs = []
	for c in cert_chain_der_b64 or []:
		chain_cert = _load_chain_cert(c)
		if chain_cert is not None:
			chain_certs.append(chain_cert)

	signed_attrs_der = base64.b64decode(session["signed_attrs_b64"])
	signed_attrs = cms.CMSAttributes.load(signed_attrs_der)

	signer_info = cms.SignerInfo({
		"version": "v1",
		"sid": cms.SignerIdentifier({
			"issuer_and_serial_number": cms.IssuerAndSerialNumber({
				"issuer": signer_cert.issuer,
				"serial_number": signer_cert.serial_number,
			}),
		}),
		"digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
		"signed_attrs": signed_attrs,
		"signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "rsassa_pkcs1v15"}),
		"signature": signature_bytes,
	})

	cert_choices = [cms.CertificateChoices({"certificate": signer_cert})]
	for c in chain_certs:
		cert_choices.append(cms.CertificateChoices({"certificate": c}))

	signed_data = cms.SignedData({
		"version": "v1",
		"digest_algorithms": cms.DigestAlgorithms([
			algos.DigestAlgorithm({"algorithm": "sha256"})
		]),
		"encap_content_info": cms.ContentInfo({
			"content_type": "data",
		}),
		"certificates": cms.CertificateSet(cert_choices),
		"signer_infos": cms.SignerInfos([signer_info]),
	})

	cms_content = cms.ContentInfo({
		"content_type": "signed_data",
		"content": signed_data,
	})
	cms_bytes = cms_content.dump()

	prepared_pdf_bytes = base64.b64decode(session["prepared_pdf_b64"])
	prep = session["prep_digest"]
	prep_digest_obj = PreparedByteRangeDigest(
		document_digest=bytes.fromhex(prep["document_digest_hex"]),
		reserved_region_start=prep["reserved_region_start"],
		reserved_region_end=prep["reserved_region_end"],
	)

	output = BytesIO(prepared_pdf_bytes)
	prep_digest_obj.fill_with_cms(output, cms_bytes)
	output.seek(0)
	signed_pdf_bytes = output.read()

	# Generate file name
	docname = session["docname"]
	file_name = f"{docname}_signed_v1.pdf"

	# Check if a previous version exists to increment
	existing = frappe.db.count(
		"File",
		filters={
			"attached_to_doctype": session["doctype"],
			"attached_to_name": docname,
			"file_name": ["like", f"{docname}_signed_v%.pdf"],
		},
	)
	if existing:
		file_name = f"{docname}_signed_v{existing + 1}.pdf"

	return {
		"signed_pdf_bytes": signed_pdf_bytes,
		"file_name": file_name,
		"doctype": session["doctype"],
		"docname": session["docname"],
		"signing_request_name": session["signing_request_name"],
		"certificate_fingerprint": hashlib.sha256(cert_der).hexdigest(),
	}


def save_signed_pdf(signed_result):
	"""Save the signed PDF as a Frappe File attachment.

	Tags the File with `is_dsc_signed=1` (custom field added by after_install)
	so the protection hook can refuse deletion by non-DSC-Administrators.

	Args:
		signed_result: dict returned from finalize_signed_pdf

	Returns:
		File document
	"""
	file_doc = frappe.get_doc(
		{
			"doctype": "File",
			"file_name": signed_result["file_name"],
			"attached_to_doctype": signed_result["doctype"],
			"attached_to_name": signed_result["docname"],
			"content": signed_result["signed_pdf_bytes"],
			"is_private": 1,
		}
	)
	file_doc.save(ignore_permissions=True)

	# Flag if the custom field exists (it should, after install runs)
	if frappe.get_meta("File").get_field("is_dsc_signed"):
		frappe.db.set_value("File", file_doc.name, "is_dsc_signed", 1)

	return file_doc


# PEM bundle of every CCA India licensed CA, shipped with the app so signature
# verification trusts all Indian DSC tokens out of the box — no admin setup.
_BUILTIN_TRUST_BUNDLE = os.path.join(
	os.path.dirname(__file__), "cca_india_trust_bundle.pem"
)


def _parse_pem_certs(pem_bytes):
	"""Parse a PEM bundle's bytes into a list of x509 Certificate objects."""
	from asn1crypto import pem
	from asn1crypto.x509 import Certificate

	if isinstance(pem_bytes, str):
		pem_bytes = pem_bytes.encode()
	return [
		Certificate.load(der)
		for _, _, der in pem.unarmor(pem_bytes, multiple=True)
	]


def _load_trust_store():
	"""Build a pyhanko ValidationContext for signature verification.

	Trust roots = the CCA India bundle shipped with the app, plus any extra CA
	bundle an admin uploads in DSC Settings. The built-in bundle means every
	Indian DSC token verifies as trusted with zero setup; the uploaded bundle
	is additive, for trusting extra CAs (e.g. a private/internal CA).

	Returns ValidationContext or None. None falls back to pyhanko defaults so
	verification never breaks if neither source yields any certificates.
	"""
	try:
		from pyhanko_certvalidator import ValidationContext

		anchors = []

		if os.path.exists(_BUILTIN_TRUST_BUNDLE):
			# hardcoded path inside the app
			# directory (see _BUILTIN_TRUST_BUNDLE above); no user-controlled input.
			with open(_BUILTIN_TRUST_BUNDLE, "rb") as fh:  # nosemgrep: frappe-security-file-traversal
				anchors.extend(_parse_pem_certs(fh.read()))

		bundle_url = frappe.db.get_single_value("DSC Settings", "trust_store_bundle")
		if bundle_url:
			file_doc = frappe.get_doc("File", {"file_url": bundle_url})
			anchors.extend(_parse_pem_certs(file_doc.get_content()))

		if not anchors:
			return None

		return ValidationContext(trust_roots=anchors, allow_fetching=False)
	except Exception:
		frappe.log_error(title="DSC trust store load failed")
		return None


def verify_signed_pdf(pdf_bytes):
	"""Verify a signed PDF's signature.

	Args:
		pdf_bytes: bytes of the signed PDF

	Returns:
		dict with is_valid, signer_name, signature_count, details
	"""
	from pyhanko.pdf_utils.reader import PdfFileReader
	from pyhanko.sign.validation import async_validate_pdf_signature

	try:
		reader = PdfFileReader(BytesIO(pdf_bytes))
		sigs = list(reader.embedded_signatures)

		if not sigs:
			return {"is_valid": False, "error": "No signatures found in PDF"}

		validation_context = _load_trust_store()

		results = []
		for sig in sigs:
			try:
				status = asyncio.run(
					async_validate_pdf_signature(
						sig, signer_validation_context=validation_context
					)
				)
				results.append(
					{
						"field_name": sig.field_name,
						"intact": status.intact,
						"valid": status.valid,
						"trusted": status.trusted,
						"bottom_line": status.bottom_line,
					}
				)
			except Exception as ve:
				results.append(
					{
						"field_name": sig.field_name,
						"intact": None,
						"valid": None,
						"trusted": False,
						"bottom_line": False,
						"validation_error": str(ve),
					}
				)

		all_valid = all(r.get("bottom_line", False) for r in results)
		return {
			"is_valid": all_valid,
			"signatures": results,
			"signature_count": len(results),
			"trust_store_configured": validation_context is not None,
		}

	except Exception as e:
		return {"is_valid": False, "error": str(e)}


def generate_pdf_from_print_format(doctype, docname, print_format):
	"""Generate PDF bytes from a Frappe print format.

	Args:
		doctype: DocType name
		docname: document name
		print_format: Print Format name

	Returns:
		bytes of the generated PDF
	"""
	from frappe.utils.pdf import get_pdf

	html = frappe.get_print(doctype, docname, print_format=print_format)
	pdf_bytes = get_pdf(html)
	return pdf_bytes


def build_stamp_text(sig_template, profile, signer_location_text=None):
	"""Build the visual stamp text based on template and profile config.

	Args:
		sig_template: DSC Signature Template doc
		profile: DSC Profile doc
		signer_location_text: optional per-signer address to use for the
			"Location:" line. Falls back to DSC Settings.default_location.

	Returns:
		str with the stamp text
	"""
	lines = []
	if not sig_template:
		name = profile.certificate_common_name or profile.label or profile.profile_name
		return f"Digitally signed by {name}"

	name = profile.certificate_common_name or profile.label or profile.profile_name
	if sig_template.stamp_show_digitally_signed_by and sig_template.stamp_show_signer_name:
		lines.append(f"Digitally signed by {name}")
	elif sig_template.stamp_show_digitally_signed_by:
		lines.append("Digitally signed")
	elif sig_template.stamp_show_signer_name:
		lines.append(name)

	if sig_template.stamp_show_designation:
		designation = profile.designation_for_stamp or profile.label
		if designation:
			lines.append(designation)

	if sig_template.stamp_show_timestamp:
		fmt = sig_template.stamp_timestamp_format or "%d-%m-%Y %H:%M:%S %Z"
		now = datetime.now(ZoneInfo(frappe.utils.get_system_timezone()))
		lines.append(f"Date: {now.strftime(fmt)}")

	if sig_template.stamp_show_reason:
		settings = frappe.get_single("DSC Settings")
		lines.append(f"Reason: {settings.default_reason or 'Approved'}")

	if sig_template.stamp_show_location:
		if signer_location_text:
			location = signer_location_text
		else:
			settings = frappe.get_single("DSC Settings")
			location = settings.default_location or ""
		lines.append(f"Location: {location}")

	return "\n".join(lines)


_STANDARD_FONTS = {
	# PDF standard-14 fonts need no embedding; avg_width is a rough glyph
	# width (in em) pyHanko uses to wrap and size the text box.
	"helvetica": ("Helvetica", 0.5),
	"helvetica-bold": ("Helvetica-Bold", 0.55),
	"times": ("Times-Roman", 0.45),
	"times-roman": ("Times-Roman", 0.45),
	"times-bold": ("Times-Bold", 0.5),
	"courier": ("Courier", 0.6),
}

# Fonts shipped with the app and embedded into the PDF, so the stamp can match
# the print format (Lato is the Rocin Design print font). Each font has a
# <name>.metrics.json with its WinAnsi glyph widths (1000 units/em), generated
# with fontTools from the .ttf, so no font library is needed at runtime.
_BUNDLED_FONTS = {
	"lato": "Lato-Regular",
}
_FONT_DIR = os.path.join(os.path.dirname(__file__), "fonts")


class _EmbeddedTrueTypeEngine(SimpleFontEngine):
	"""Single-byte (WinAnsi) TrueType font engine with real glyph widths."""

	def __init__(self, writer, font_name):
		with open(os.path.join(_FONT_DIR, font_name + ".metrics.json")) as f:
			self.metrics = json.load(f)
		self.font_file = os.path.join(_FONT_DIR, font_name + ".ttf")
		super().__init__(writer, self.metrics["base_font"], 0.5)

	def _encode(self, txt):
		return txt.encode("cp1252", errors="replace")

	def shape(self, txt):
		m = self.metrics
		raw = self._encode(txt)
		width = 0
		for code in raw:
			idx = code - m["first_char"]
			w = m["widths"][idx] if 0 <= idx < len(m["widths"]) else 0
			width += w or m["missing_width"]
		escaped = raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
		return pyhanko_font_api.ShapeResult(
			graphics_ops=b"(" + escaped + b") Tj", x_advance=width / 1000, y_advance=0
		)

	def as_resource(self):
		m = self.metrics
		with open(self.font_file, "rb") as f:
			font_bytes = f.read()
		font_stream = pdf_generic.StreamObject(
			{pdf_generic.NameObject("/Length1"): pdf_generic.NumberObject(len(font_bytes))},
			stream_data=font_bytes,
		)
		font_stream.compress()
		name = pdf_generic.NameObject
		num = pdf_generic.NumberObject
		descriptor = pdf_generic.DictionaryObject(
			{
				name("/Type"): name("/FontDescriptor"),
				name("/FontName"): name("/" + m["base_font"]),
				name("/Flags"): num(32),
				name("/FontBBox"): pdf_generic.ArrayObject(map(num, m["bbox"])),
				name("/ItalicAngle"): num(0),
				name("/Ascent"): num(m["ascent"]),
				name("/Descent"): num(m["descent"]),
				name("/CapHeight"): num(m["cap_height"]),
				name("/StemV"): num(80),
				name("/MissingWidth"): num(m["missing_width"]),
				name("/FontFile2"): self.writer.add_object(font_stream),
			}
		)
		return pdf_generic.DictionaryObject(
			{
				name("/Type"): name("/Font"),
				name("/Subtype"): name("/TrueType"),
				name("/BaseFont"): name("/" + m["base_font"]),
				name("/Encoding"): name("/WinAnsiEncoding"),
				name("/FirstChar"): num(m["first_char"]),
				name("/LastChar"): num(m["first_char"] + len(m["widths"]) - 1),
				name("/Widths"): pdf_generic.ArrayObject(map(num, m["widths"])),
				name("/FontDescriptor"): self.writer.add_object(descriptor),
			}
		)


class _EmbeddedTrueTypeFactory(pyhanko_font_api.FontEngineFactory):
	def __init__(self, font_name):
		self.font_name = font_name

	def create_font_engine(self, writer, obj_stream=None):
		return _EmbeddedTrueTypeEngine(writer, self.font_name)


def build_stamp_style(sig_template, profile, stamp_text):
	"""Build the pyHanko stamp style from the template's Stamp Style settings.

	Without an explicit style pyHanko draws its own default appearance
	(monospace "Digitally signed by … Timestamp: … UTC" over the pyHanko logo,
	with a thick border), ignoring every stamp option on the template.
	"""
	family = ((sig_template and sig_template.stamp_font_family) or "Helvetica").strip().lower()
	# pyHanko writes the font size with %d, so a fractional size is silently
	# truncated in the PDF while text is laid out at the full size.
	font_size = max(round(float((sig_template and sig_template.stamp_font_size) or 8)), 1)
	font = None
	if family in _BUNDLED_FONTS and os.path.exists(os.path.join(_FONT_DIR, _BUNDLED_FONTS[family] + ".ttf")):
		font = _EmbeddedTrueTypeFactory(_BUNDLED_FONTS[family])
	if font is None:
		font_name, avg_width = _STANDARD_FONTS.get(family, _STANDARD_FONTS["helvetica"])
		font = SimpleFontEngineFactory(font_name, avg_width)
	border = 1 if (sig_template and sig_template.stamp_border) else 0

	background = None
	if sig_template:
		image_field = None
		if sig_template.stamp_include_signature_image and profile.signature_image:
			image_field = profile.signature_image
		elif sig_template.stamp_include_seal_image and profile.seal_image:
			image_field = profile.seal_image
		if image_field:
			background = _load_stamp_image(image_field)

	# Right (default) is flush right, like the "For <company>" and "Authorised
	# Signatory" lines of invoice and order prints; Left lines up with a letter's
	# left-hand signature block.
	left = sig_template and (sig_template.get("stamp_alignment") or "Right") == "Left"
	x_align = pyhanko_layout.AxisAlignment.ALIGN_MIN if left else pyhanko_layout.AxisAlignment.ALIGN_MAX
	style_class = _LeftAlignedTextStampStyle if left else _RightAlignedTextStampStyle
	return style_class(
		# pyHanko %-formats stamp_text with its own params; escape literal %.
		stamp_text=stamp_text.replace("%", "%%"),
		border_width=border,
		background=background,
		background_opacity=1.0,
		inner_content_layout=pyhanko_layout.SimpleBoxLayoutRule(
			x_align=x_align,
			y_align=pyhanko_layout.AxisAlignment.ALIGN_MID,
			margins=pyhanko_layout.Margins(left=0, right=2, top=2, bottom=2)
			if left
			else pyhanko_layout.Margins(left=2, right=0, top=2, bottom=2),
		),
		text_box_style=pyhanko_text.TextBoxStyle(
			font=font,
			font_size=font_size,
			# pyHanko's layout uses Fraction(width, height): leading must be an int.
			leading=round(font_size * 1.25),
			# No inner padding, so the text lines up with the print format's edge.
			box_layout_rule=pyhanko_layout.SimpleBoxLayoutRule(
				x_align=x_align,
				y_align=pyhanko_layout.AxisAlignment.ALIGN_MID,
				margins=pyhanko_layout.Margins.uniform(0),
			),
		),
	)


_MAX_SEAL_HEIGHT = 72  # PDF points


class _RightAlignedTextBox(pyhanko_text.TextBox):
	"""pyHanko text box whose lines are right-aligned instead of left-aligned."""

	def put_string_line(self, txt):
		ops, extent = super().put_string_line(txt)
		self._line_extents.append(extent)
		return ops, extent

	@property
	def content(self):
		return self._content

	@content.setter
	def content(self, content):
		self._line_extents = []
		pyhanko_text.TextBox.content.fset(self, content)
		width = self._nat_text_width
		# Shift each line right by its slack, then undo the shift so the next
		# line starts from the left edge again.
		self._wrapped_lines = [
			b"%g 0 Td %s %g 0 Td" % (width - extent, ops, extent - width)
			for ops, extent in zip(self._wrapped_lines, self._line_extents, strict=True)
		]


class _RightAlignedTextStamp(pyhanko_stamp.TextStamp):
	def _text_layout(self):
		self.text_box = tb = _RightAlignedTextBox(
			self.style.text_box_style, writer=self.writer, resources=self.resources, box=None
		)
		params = self.get_default_text_params()
		if self.text_params is not None:
			params.update(self.text_params)
		tb.content = self.style.stamp_text % params
		return tb.render()

	def _render_background(self):
		# Inner content is rendered first, so the text width is known here: put
		# the image (company seal) just left of the right-aligned text instead
		# of at the far left of the box.
		text_width = self.text_box.box.width
		seal_margin = max((self.box.height - _MAX_SEAL_HEIGHT) / 2, 0)
		style = self.style
		self.style = dataclasses.replace(
			style,
			background_layout=pyhanko_layout.SimpleBoxLayoutRule(
				x_align=pyhanko_layout.AxisAlignment.ALIGN_MAX,
				y_align=pyhanko_layout.AxisAlignment.ALIGN_MID,
				# Cap the seal at ~25 mm so a tall signature box (which can overlap
				# the surrounding print lines, as a rubber stamp would) doesn't make
				# it huge; it stays vertically centred on the text.
				margins=pyhanko_layout.Margins(
					left=0, right=text_width + 4, top=seal_margin, bottom=seal_margin
				),
			),
		)
		try:
			return super()._render_background()
		finally:
			self.style = style


class _RightAlignedTextStampStyle(pyhanko_stamp.TextStampStyle):
	def create_stamp(self, writer, box, text_params):
		return _RightAlignedTextStamp(writer=writer, style=self, box=box, text_params=text_params)


class _LeftAlignedTextStamp(pyhanko_stamp.TextStamp):
	"""pyHanko's own left-aligned lines, with the seal (if any) just right of the text."""

	def _render_background(self):
		text_width = self.text_box.box.width
		seal_margin = max((self.box.height - _MAX_SEAL_HEIGHT) / 2, 0)
		style = self.style
		self.style = dataclasses.replace(
			style,
			background_layout=pyhanko_layout.SimpleBoxLayoutRule(
				x_align=pyhanko_layout.AxisAlignment.ALIGN_MIN,
				y_align=pyhanko_layout.AxisAlignment.ALIGN_MID,
				margins=pyhanko_layout.Margins(
					left=text_width + 4, right=0, top=seal_margin, bottom=seal_margin
				),
			),
		)
		try:
			return super()._render_background()
		finally:
			self.style = style


class _LeftAlignedTextStampStyle(pyhanko_stamp.TextStampStyle):
	def create_stamp(self, writer, box, text_params):
		return _LeftAlignedTextStamp(writer=writer, style=self, box=box, text_params=text_params)


def _load_stamp_image(file_url):
	"""Load a profile image (signature/seal) attached as a Frappe File."""
	try:
		from PIL import Image

		file_doc = frappe.get_doc("File", {"file_url": file_url})
		return PdfImage(Image.open(BytesIO(file_doc.get_content())))
	except Exception:
		frappe.log_error(title="DSC stamp image could not be loaded")
		return None


def get_session_info(session_id):
	"""Get info about a pending signing session.

	Returns None if session doesn't exist or expired.
	"""
	return _load_session(session_id)


def cleanup_expired_sessions(max_age_seconds=300):
	"""No-op kept for backwards compatibility — Redis TTL handles expiry now."""
	return 0
