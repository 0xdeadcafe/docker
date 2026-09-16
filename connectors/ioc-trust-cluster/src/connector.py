#!/usr/bin/env python3
"""
IOC Trust Cluster — OpenCTI Internal Enrichment Connector

Implements a trust-parent grouping and false-positive candidate identification
system modelled on TrashPanda's trust-chain pipeline (ioc.clp / triage.clp).

Supported observable types and their parent/cluster model
═══════════════════════════════════════════════════════════════════════════════
Type                Parent extraction          Parent mode    Verdict cascade
───────────────────────────────────────────────────────────────────────────
IPv4-Addr           RDAP announced CIDR        observable     ✓ full
                    fallback: /<prefix> (/24)
IPv6-Addr           RDAP announced prefix      observable     ✓ full
                    fallback: /<prefix> (/48)
Domain-Name         strip subdomain →          observable     ✓ full
                    root domain
Url                 extract host →             observable     ✓ full
                    IPv4/Domain-Name logic
StixFile            none                       —              ubiquity only
X509-Certificate    issuer DN →                observable     ✓ full
                    CA certificate
Network-Traffic     JA4 profile prefix         label-only     ubiquity only
  (JA3/JA3S:        (no structural parent)     label-only     ubiquity only
   JA4/JA4S:        profile prefix             label-only     ubiquity only
   JA4X:            (no structural parent)     label-only     ubiquity only)
Autonomous-System   RDAP ASN owner name        label-only     ubiquity only
═══════════════════════════════════════════════════════════════════════════════

Observable vs label-only parent modes
───────────────────────────────────────
observable   A parent StixCyberObservable is found-or-created.  A "related-to"
             relationship links child → parent.  The parent's score and labels
             drive full verdict cascade (CONFIRMED_MALICIOUS / CONFIRMED_BENIGN).

label-only   No OpenCTI observable type exists for the parent concept (e.g. TLS
             profile, ASN owner organisation).  A cluster label is applied
             directly to the child.  No verdict cascade is possible — verdicts
             from the connected feed connectors still influence the ubiquity
             heuristic via the child's own score.

Propagation rules (three explicit parent states — observable mode only)
───────────────────────────────────────────────────────────────────────
CONFIRMED_MALICIOUS  parent.score ≥ MALICIOUS_SCORE_MIN
                     AND parent does NOT carry "malicious-cascade"
                     (a cascaded parent was inferred, not directly assessed —
                      propagating further would let a single malicious child
                      infect its entire sibling population through the parent)
                     → cascade DOWN: child gets "malicious-cascade"

CONFIRMED_BENIGN     parent carries "fp-candidate"
                     AND parent is not CONFIRMED_MALICIOUS
                     → propagate DOWN to children with score ≤
                       TRUST_CLUSTER_FP_CASCADE_SCORE_MAX (default:
                       same as TRUST_CLUSTER_UNKNOWN_SCORE_MAX): "fp-candidate"

UNKNOWN              everything else — no explicit assessment, OR parent
                     carries "malicious-cascade" (inferred, not feed-assessed)
                     → PROPAGATION STOPS in both directions
                     → child → parent: NEVER (single malicious child does not
                        make the parent malicious)

Pipeline (per observable)
───────────────────────────────────────────────────────────────────────
  Step 1  Structural parent discovery
  Step 2  Parent upsert (observable mode: find-or-create; label mode: skip)
  Step 3  Trust relationship (observable mode only: child → parent "related-to")
  Step 4  Cluster label (both modes: shared label on child; parent if observable)
  Step 5  Verdict inheritance (observable mode only; UNKNOWN parent stops)
  Step 6  Ubiquity heuristic (all types)
  Step 7  Audit note
"""

import json
import os
import ipaddress
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

import dns.resolver
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError
from pycti import OpenCTIConnectorHelper
import tldextract

# PSL-aware registered-domain extractor (offline — uses bundled suffix list).
# ponytail: suffix_list_urls=None disables the network fetch on first use;
#           update the tldextract package to refresh the bundled PSL.
_tld = tldextract.TLDExtract(suffix_list_urls=None)


# ── Constants ──────────────────────────────────────────────────────────────────

LABEL_FP_CANDIDATE      = "fp-candidate"
LABEL_MALICIOUS_CASCADE = "malicious-cascade"
LABEL_SINKHOLED         = "sinkholed"
CLUSTER_LABEL_PREFIX    = "trust-cluster"

COLOR_CLUSTER   = "#1565c0"   # blue   — structural grouping
COLOR_FP        = "#2e7d32"   # green  — likely benign / FP candidate
COLOR_MALICIOUS = "#b71c1c"   # red    — inherited malicious context
COLOR_SINKHOLED = "#6a1b9a"   # purple — confirmed sinkholed

# Observable-mode types: a real parent observable is created and verdict cascades.
# Label-only types: no parent observable; cluster label + ubiquity only.
# Both sets are inlined here — the intermediate constants were never used in logic.
SUPPORTED_TYPES = {
    "IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "StixFile",
    "X509-Certificate", "Network-Traffic", "Autonomous-System",
}

# Maximum entries per session cache before a full eviction.
# ponytail: clears the whole dict on overflow rather than LRU-evicting one entry;
#           upgrade to an LRU dict if per-entry eviction matters.
_CACHE_MAXSIZE: int = 10_000
# label-only mode (no parent observable to create).
LABEL_ONLY = "label-only"

# JA4 fingerprint format: {protocol}{version}{sni}{ciphers}{exts}{alpn}_{hash}_{hash}
# e.g.  t13d1516h2_8daaf6152771_e5627efa2ab1
#       s13d_8daaf6152771_e5627efa2ab1  (JA4S — server side)
_JA4_RE = re.compile(r'^([a-z]\d{2}[a-z]\d+[a-z0-9]*)_[a-f0-9]{12}_[a-f0-9]{12}$', re.I)


# ── Connector class ────────────────────────────────────────────────────────────

class IocTrustClusterConnector:

    def __init__(self):
        config = {
            "opencti": {
                "url":   os.environ.get("OPENCTI_URL", "http://opencti:8080"),
                "token": os.environ.get("OPENCTI_TOKEN"),
            },
            "connector": {
                "id":               os.environ.get("CONNECTOR_ID"),
                "type":             "INTERNAL_ENRICHMENT",
                "name":             os.environ.get("CONNECTOR_NAME", "IOC Trust Cluster"),
                "scope":            (
                    "IPv4-Addr,IPv6-Addr,Domain-Name,Url,StixFile,"
                    "X509-Certificate,Network-Traffic,Autonomous-System"
                ),
                "auto":             os.environ.get("CONNECTOR_AUTO", "true").lower() == "true",
                "confidence_level": int(os.environ.get("CONNECTOR_CONFIDENCE_LEVEL", "75")),
                "log_level":        os.environ.get("CONNECTOR_LOG_LEVEL", "info"),
            },
        }
        self.helper = OpenCTIConnectorHelper(config)
        self.confidence: int = int(os.environ.get("CONNECTOR_CONFIDENCE_LEVEL", "75"))

        # ── Thresholds ─────────────────────────────────────────────────────────
        self.fp_sighting_threshold  = int(os.environ.get("TRUST_CLUSTER_FP_SIGHTING_THRESHOLD",   "10"))
        self.cidr_fallback_prefix   = int(os.environ.get("TRUST_CLUSTER_CIDR_FALLBACK_PREFIX",    "24"))
        self.ipv6_fallback_prefix   = int(os.environ.get("TRUST_CLUSTER_IPV6_FALLBACK_PREFIX",    "48"))
        self.malicious_score_min    = int(os.environ.get("TRUST_CLUSTER_MALICIOUS_SCORE_MIN",     "70"))
        self.unknown_score_max      = int(os.environ.get("TRUST_CLUSTER_UNKNOWN_SCORE_MAX",       "50"))
        # Separate ceiling for the CONFIRMED_BENIGN cascade from parent to child.
        # Defaults to unknown_score_max so behaviour is unchanged out of the box;
        # operators can raise it (e.g. to 65) to cascade fp-candidate to children
        # that carry a moderate non-zero score from a low-confidence feed import.
        # Must be kept below TRUST_CLUSTER_MALICIOUS_SCORE_MIN to avoid cascading
        # fp-candidate onto observables already flagged by a feed.
        self.fp_cascade_score_max   = int(os.environ.get(
                                        "TRUST_CLUSTER_FP_CASCADE_SCORE_MAX",
                                        str(self.unknown_score_max)
                                    ))
        self.use_rdap               = os.environ.get("TRUST_CLUSTER_USE_RDAP", "true").lower() == "true"
        self.rdap_timeout           = int(os.environ.get("TRUST_CLUSTER_RDAP_TIMEOUT",            "5"))
        self.rdap_retries: int      = int(os.environ.get("TRUST_CLUSTER_RDAP_RETRIES",            "2"))
        self.use_ns_lookup          = os.environ.get("TRUST_CLUSTER_USE_NS_LOOKUP", "true").lower() == "true"
        self.ns_timeout             = int(os.environ.get("TRUST_CLUSTER_NS_TIMEOUT",              "5"))
        _sinkhole_raw = os.environ.get("TRUST_CLUSTER_SINKHOLE_IPS", "").strip()
        self.sinkhole_ips: frozenset[str] = frozenset(
            ip.strip() for ip in _sinkhole_raw.split(",") if ip.strip()
        )
        # Only count sightings from these connector IDs toward the ubiquity
        # threshold.  Prevents noisy feed-import sightings (OTX pulses, etc.)
        # from inflating the fp-candidate heuristic.  Empty = count all.
        _sfilter_raw = os.environ.get("TRUST_CLUSTER_SIGHTING_SOURCE_FILTER", "").strip()
        self.sighting_source_filter: frozenset[str] = frozenset(
            cid.strip() for cid in _sfilter_raw.split(",") if cid.strip()
        )
        # NS provider allowlist — root domains whose NS servers should never be
        # used as structural parents.  Cloudflare, Route53, etc. each serve
        # millions of domains; creating a parent for their NS creates enormous
        # meaningless clusters.  Empty = allow all NS parents.
        _ns_allowlist_raw = os.environ.get("TRUST_CLUSTER_NS_ALLOWLIST", "").strip()
        self.ns_allowlist: frozenset[str] = frozenset(
            d.strip().lower() for d in _ns_allowlist_raw.split(",") if d.strip()
        )
        # Stats: emit a summary log every N processed observables (0 = off).
        self._stats_interval: int = int(os.environ.get("TRUST_CLUSTER_STATS_INTERVAL", "100"))
        self._stats_n: int = 0
        self._stats: dict[str, int] = IocTrustClusterConnector._reset_stats()

        # Session caches — avoid redundant network calls for the same address / domain
        self._cidr_cache: dict[str, str | None] = {}   # ip_str → CIDR string
        self._asn_desc_cache: dict[str, str | None] = {}  # "AS{n}" → owner name
        self._ns_cache: dict[str, str | None] = {}     # domain → primary NS hostname
        self._ip_cache: dict[str, list[str]] = {}      # domain → A record IP list

        # Per-session dedup for analyst advisory notes — prevents duplicate notes
        # across consecutive triggers.  Reset on container restart (acceptable:
        # a single re-notification after restart is harmless).
        self._revocation_noted: set[str] = set()   # entity IDs that received a revocation note
        self._conflict_noted:   set[str] = set()   # entity IDs that received a conflict note

    # ── DNS helpers ──────────────────────────────────────────────────────────────────────

    def _get_authoritative_ns(self, domain: str) -> str | None:
        """
        Return the primary authoritative NS hostname for a root domain.

        Queries public DNS for NS records and returns the first alphabetically
        (for determinism across multi-NS delegations). Caches results. Guards
        against self-referential NS records that would create a cycle
        (e.g. evil.com NS ns1.evil.com → evil.com → ns1.evil.com → …).
        """
        if domain in self._ns_cache:
            return self._ns_cache[domain]

        try:
            answers = dns.resolver.resolve(domain, 'NS', lifetime=self.ns_timeout)
            ns_list = sorted(
                str(r.target).rstrip('.').lower()
                for r in answers
                if str(r.target).rstrip('.')
            )
            ns = ns_list[0] if ns_list else None

            # Guard: skip NS whose registered domain == queried domain (cycle).
            # Uses PSL-aware extraction so ns1.example.co.uk is correctly
            # identified as belonging to example.co.uk (old [-2:] slice would
            # compare co.uk != example.co.uk and miss the cycle).
            if ns and _tld(ns).top_domain_under_public_suffix == domain:
                ns = None

            self._cache_set(self._ns_cache, domain, ns)
            if ns:
                self.helper.log_debug(f"[trust-cluster] NS {domain} → {ns}")
            return ns

        except Exception as exc:
            self.helper.log_debug(
                f"[trust-cluster] NS lookup failed for {domain}: {exc}"
            )
            self._cache_set(self._ns_cache, domain, None)
            return None

    def _get_resolved_ips(self, domain: str) -> list[str]:
        """
        Return the IPv4 addresses that domain currently resolves to (A records).
        Caches results to avoid repeated queries within the same connector session.
        """
        if domain in self._ip_cache:
            return self._ip_cache[domain]
        try:
            answers = dns.resolver.resolve(domain, 'A', lifetime=self.ns_timeout)
            ips = [str(r.address) for r in answers]
            self._cache_set(self._ip_cache, domain, ips)
            if ips:
                self.helper.log_debug(
                    f"[trust-cluster] A {domain} → {', '.join(ips)}"
                )
            return ips
        except Exception as exc:
            self.helper.log_debug(
                f"[trust-cluster] A lookup failed for {domain}: {exc}"
            )
            self._cache_set(self._ip_cache, domain, [])
            return []

    # ── RDAP helpers ──────────────────────────────────────────────────────────────────────

    def _get_announced_cidr(self, ip_str: str) -> str | None:
        """
        Return the ASN-announced CIDR block for a public IP/IPv6 address via RDAP.

        Both IPv4 and IPv6 are supported — ipwhois handles the full RFC 3596
        address space.  Private / special-purpose addresses are skipped; the
        caller falls back to a computed prefix for those.

        Side-effect: caches the ASN description in self._asn_desc_cache so that
        a subsequent Autonomous-System observable for the same ASN can be grouped
        by owner without a second RDAP round-trip.
        """
        try:
            addr = ipaddress.ip_address(ip_str.split("/")[0])
            if (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
                return None
        except ValueError:
            return None

        if ip_str in self._cidr_cache:
            return self._cidr_cache[ip_str]

        try:
            result = IPWhois(ip_str, timeout=self.rdap_timeout).lookup_rdap(
                depth=0, rate_limit_timeout=self.rdap_timeout
            )
            # Cache ASN description as a side-effect for AutonomousSystem processing
            asn = result.get("asn")
            asn_desc = result.get("asn_description") or ""
            if asn and asn_desc:
                self._cache_set(self._asn_desc_cache, f"AS{asn}", asn_desc)

            network  = result.get("network") or {}
            raw_cidr = network.get("cidr") or result.get("asn_cidr") or ""

            if raw_cidr and "/" in raw_cidr:
                candidates = [c.strip() for c in raw_cidr.split(",") if "/" in c.strip()]
                if candidates:
                    best = max(candidates, key=lambda c: int(c.split("/")[1]))
                    normalised = str(ipaddress.ip_network(best, strict=False))
                    self._cache_set(self._cidr_cache, ip_str, normalised)
                    self.helper.log_debug(
                        f"[trust-cluster] RDAP {ip_str} → {normalised} "
                        f"(ASN{asn} {asn_desc})"
                    )
                    return normalised

        except IPDefinedError:
            pass
        except Exception as e:
            self.helper.log_debug(f"[trust-cluster] RDAP failed for {ip_str}: {e}")

        self._cache_set(self._cidr_cache, ip_str, None)
        return None

    def _get_asn_owner(self, asn_value: str) -> str | None:
        """
        Return the registered owner/organisation name for an ASN.

        Look-up order:
          1. In-process cache (populated as a side-effect of IP RDAP lookups)
          2. Direct RDAP ASN query via the IANA bootstrap redirect endpoint

        The IANA bootstrap endpoint redirects to the authoritative RIR (ARIN,
        RIPE, APNIC, LACNIC, AFRINIC) so a single URL works for all ASNs.

        Returns None if both lookups fail or the ASN is invalid.
        """
        # Normalise: strip non-digit characters and re-add "AS" prefix for cache key
        digits = re.sub(r"[^0-9]", "", asn_value)
        if not digits:
            return None
        cache_key = f"AS{digits}"

        if cache_key in self._asn_desc_cache:
            return self._asn_desc_cache[cache_key]

        # Direct RDAP ASN query with exponential backoff on rate-limits.
        # IANA bootstrap endpoint redirects to the authoritative RIR.
        url = f"https://rdap.iana.org/autnum/{digits}"
        last_exc: Exception | None = None
        for attempt in range(self.rdap_retries + 1):
            try:
                req = urllib.request.Request(
                    url,
                    headers={"Accept": "application/rdap+json, application/json"}
                )
                with urllib.request.urlopen(req, timeout=self.rdap_timeout) as resp:
                    data = json.loads(resp.read(1_048_576).decode())

                # Try name field first, then vcardArray "fn" for the registrant
                name = data.get("name") or ""
                for entity in data.get("entities", []):
                    for role in entity.get("roles", []):
                        if role in ("registrant", "administrative"):
                            for item in (entity.get("vcardArray") or [None, []])[1]:
                                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                                    name = item[3] or name
                                    break

                name = name.strip()
                if name:
                    self._cache_set(self._asn_desc_cache, cache_key, name)
                    self.helper.log_debug(
                        f"[trust-cluster] RDAP ASN {cache_key} → owner: {name}"
                    )
                    return name
                break  # valid response but no name — no point retrying

            except urllib.error.HTTPError as exc:
                last_exc = exc
                if exc.code in (429, 500, 502, 503, 504) and attempt < self.rdap_retries:
                    delay = 2 ** attempt   # 1s, 2s, 4s
                    self.helper.log_debug(
                        f"[trust-cluster] RDAP ASN {cache_key} HTTP {exc.code}, "
                        f"retry {attempt + 1}/{self.rdap_retries} in {delay}s"
                    )
                    time.sleep(delay)
                else:
                    break
            except Exception as exc:
                last_exc = exc
                break

        if last_exc is not None:
            self.helper.log_warning(
                f"[trust-cluster] RDAP ASN query failed for {cache_key} "
                f"after {attempt + 1} attempt(s): {last_exc}"
            )

        self._cache_set(self._asn_desc_cache, cache_key, None)
        return None

    # ── TLS fingerprint helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_tls_profile(entity: dict) -> str | None:
        """
        Extract a JA4 algorithm-profile string from a Network-Traffic observable.

        JA4 encodes TLS client parameters in a structured prefix before the
        underscore-delimited hash segments:
          t13d1516h2_<cipher_hash>_<ext_hash>
          └──────────┘
          profile: protocol (t=TLS), version (13=TLS1.3), SNI type (d), cipher
                   count (15), extension count (16), ALPN (h2)

        All JA4 fingerprints sharing the same profile come from the same TLS
        client configuration family — a useful grouping independent of the
        specific random cipher ordering that produces the hash.

        JA3/JA3S are 32-char MD5 hashes with no extractable structure.
        JA4X encodes certificate characteristics — no profile prefix.

        Returns the profile string (for JA4/JA4S) or None (JA3/JA3S/JA4X).
        """
        # Check common field locations for the fingerprint value
        value = (
            entity.get("value")
            or entity.get("observable_value")
            or entity.get("hashes", {}).get("JA4")
            or entity.get("hashes", {}).get("JA3")
            or ""
        )
        # Also check extensions if present
        ext = (entity.get("extensions") or {})
        tls_ext = ext.get("tls-ext") or ext.get("tls_ext") or {}
        value = (
            value
            or tls_ext.get("ja4_hash")
            or tls_ext.get("ja4s_hash")
            or tls_ext.get("ja3_hash")
            or tls_ext.get("ja3s_hash")
            or ""
        )

        if not value:
            return None

        m = _JA4_RE.match(value)
        if m:
            return m.group(1).lower()   # e.g. "t13d1516h2"

        return None   # JA3/JA3S/JA4X or unrecognised — no profile to extract

    # ── Structural parent extraction ───────────────────────────────────────────

    def _extract_parent(self, entity_type: str, value: str, entity: dict | None = None):
        """
        Return (parent_type, parent_value) describing the structural parent.

        Return types:
          ("IPv4-Addr", "1.2.3.0/24")         → observable mode (full pipeline)
          ("IPv6-Addr", "2001:db8::/32")       → observable mode
          ("Domain-Name", "example.com")       → observable mode
          ("X509-Certificate", "CN=DigiCert…") → observable mode (CA cert by subject)
          (LABEL_ONLY, "asn-owner:GOOGLE")     → label-only mode (no parent observable)
          (LABEL_ONLY, "tls-profile:t13d1516") → label-only mode
          None                                 → no parent (StixFile, root domain, etc.)
        """
        entity = entity or {}
        try:
            # ── IPv4-Addr ──────────────────────────────────────────────────────
            if entity_type == "IPv4-Addr":
                host = value.split("/")[0]
                # Skip parent discovery for network addresses (CIDR notation).
                # CIDRs are parents themselves — recursing up would cascade
                # indefinitely and flood downstream enrichment connectors
                # (AbuseIPDB, VT) with CIDR queries they cannot handle.
                if "/" in value:
                    return None
                if self.use_rdap:
                    announced = self._get_announced_cidr(host)
                    if announced and announced != value:
                        return ("IPv4-Addr", announced)
                net = ipaddress.ip_network(f"{host}/{self.cidr_fallback_prefix}", strict=False)
                parent = str(net)
                return ("IPv4-Addr", parent) if parent != value else None

            # ── IPv6-Addr ──────────────────────────────────────────────────────
            elif entity_type == "IPv6-Addr":
                host = value.split("/")[0]
                # Same guard as IPv4 — skip parent discovery for prefix observables
                if "/" in value:
                    return None
                # Skip link-local, loopback, unique-local, etc.
                try:
                    addr = ipaddress.ip_address(host)
                    if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
                        return None
                except ValueError:
                    return None
                if self.use_rdap:
                    announced = self._get_announced_cidr(host)
                    if announced and announced != value:
                        return ("IPv6-Addr", announced)
                # Fallback to /48 (typical ISP allocation unit for IPv6)
                net = ipaddress.ip_network(
                    f"{host}/{self.ipv6_fallback_prefix}", strict=False
                )
                parent = str(net)
                return ("IPv6-Addr", parent) if parent != value else None

            # ── Domain-Name ───────────────────────────────────────────────────
            elif entity_type == "Domain-Name":
                root = _tld(value.rstrip(".")).top_domain_under_public_suffix
                if not root:
                    return None   # unresolvable (localhost, single-label, etc.)
                if root != value:
                    return ("Domain-Name", root)
                # value IS the registrable root domain — use NS as parent.
                # ns1.bulletproof.ru itself then flows up to bulletproof.ru
                # on its own enrichment pass.
                if self.use_ns_lookup:
                    ns = self._get_authoritative_ns(value)
                    if ns and ns != value:
                        # Skip NS providers that serve millions of domains
                        # (Cloudflare, Route53, etc.) — they produce meaningless
                        # mega-clusters.  Uses PSL-aware extraction so
                        # ccTLD NS providers are handled correctly.
                        if self.ns_allowlist:
                            ns_root = _tld(ns).top_domain_under_public_suffix
                            if ns_root in self.ns_allowlist:
                                self.helper.log_debug(
                                    f"[trust-cluster] NS {ns} skipped "
                                    f"(allowlisted provider: {ns_root})"
                                )
                                return None
                        return ("Domain-Name", ns)
                return None   # no further parent

            # ── Url ───────────────────────────────────────────────────────────
            elif entity_type == "Url":
                parsed = urlparse(value)
                host = (parsed.hostname or "").lower()
                if not host:
                    return None
                try:
                    ipaddress.IPv6Address(host)
                    return self._extract_parent("IPv6-Addr", host)
                except ValueError:
                    pass
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                    return self._extract_parent("IPv4-Addr", host)
                return self._extract_parent("Domain-Name", host)

            # ── X509-Certificate ──────────────────────────────────────────────
            elif entity_type == "X509-Certificate":
                # Parent = the CA that issued this certificate.
                # The issuer DN of the child becomes the subject of the parent cert.
                # Skip self-signed certificates (issuer == subject).
                issuer  = (entity.get("issuer")  or "").strip()
                subject = (entity.get("subject") or "").strip()
                if issuer and issuer != subject:
                    return ("X509-Certificate", issuer)
                return None   # self-signed or no issuer info

            # ── Network-Traffic (TLS fingerprints) ────────────────────────────
            elif entity_type == "Network-Traffic":
                profile = self._extract_tls_profile(entity)
                if profile:
                    return (LABEL_ONLY, f"tls-profile:{profile}")
                # JA3/JA3S/JA4X: no structural profile to extract
                return None   # ubiquity heuristic still applies

            # ── Autonomous-System → OWNER ─────────────────────────────────────
            elif entity_type == "Autonomous-System":
                if not self.use_rdap:
                    return None
                # value is typically "AS15169" or just "15169"
                owner = self._get_asn_owner(value)
                if owner:
                    return (LABEL_ONLY, f"asn-owner:{owner}")
                return None

            # StixFile: no structural parent
            return None

        except Exception as e:
            self.helper.log_warning(
                f"[trust-cluster] parent extraction failed {entity_type}:{value}: {e}"
            )
            return None

    # ── Parent verdict classification ──────────────────────────────────────────

    def _classify_parent(self, p_score: int, p_labels: set) -> str:
        """
        Classify a parent observable into one of three explicit verdict states.

        CONFIRMED_MALICIOUS
            Feed score ≥ MALICIOUS_SCORE_MIN AND parent does NOT carry
            "malicious-cascade" (i.e. it was directly assessed by a feed,
            not inferred from a child).  A child → parent cascade is NEVER
            performed — a single malicious child does not make the parent
            malicious.  Only then can the parent cascade DOWN to its children.

        CONFIRMED_BENIGN
            Parent carries "fp-candidate" AND is not CONFIRMED_MALICIOUS.

        UNKNOWN
            Everything else — no direct feed assessment, OR the parent carries
            "malicious-cascade" (it was itself a cascade recipient, not directly
            assessed).  UNKNOWN propagation stops in BOTH directions.
        """
        if LABEL_SINKHOLED in p_labels:
            return "CONFIRMED_MALICIOUS"
        if p_score >= self.malicious_score_min and LABEL_MALICIOUS_CASCADE not in p_labels:
            return "CONFIRMED_MALICIOUS"
        if LABEL_FP_CANDIDATE in p_labels and p_score < self.malicious_score_min:
            return "CONFIRMED_BENIGN"
        return "UNKNOWN"

    # ── OpenCTI API helpers ────────────────────────────────────────────────────

    @staticmethod
    def _cache_set(cache: dict, key, value) -> None:
        """Write to a bounded session cache. Clears on overflow.
        ponytail: full clear, not LRU eviction; add LRU if hit-rate matters.
        """
        if len(cache) >= _CACHE_MAXSIZE:
            cache.clear()
        cache[key] = value

    @staticmethod
    def _reset_stats() -> dict[str, int]:
        """Fresh per-interval counter dict for stats logging."""
        return {
            "cascade_malicious":  0, "cascade_fp":        0, "ubiquity_fp":     0,
            "sinkholed":          0, "newly_clustered":   0, "already_clustered": 0,
            "no_actions":         0, "parents_malicious": 0, "parents_benign":  0,
            "parents_unknown":    0, "cascade_revoked":   0, "cascade_conflict": 0,
        }

    @staticmethod
    def _entity_score(entity: dict) -> int:
        raw = entity.get("x_opencti_score")
        return int(raw) if raw is not None else 50

    @staticmethod
    def _entity_label_values(entity: dict) -> set:
        return {lbl.get("value", "") for lbl in (entity.get("objectLabel") or [])}

    def _add_label(self, obs_id: str, label_value: str, color: str) -> bool:
        # label.create is idempotent — returns existing label if value already exists.
        try:
            result = self.helper.api.label.create(value=label_value, color=color)
            self.helper.api.stix_cyber_observable.add_label(id=obs_id, label_id=result["id"])
            return True
        except Exception as e:
            self.helper.log_warning(f"[trust-cluster] add_label failed '{label_value}': {e}")
            return False

    def _find_observable(self, obs_type: str, value: str) -> dict | None:
        try:
            results = self.helper.api.stix_cyber_observable.list(
                types=[obs_type],
                filters={"mode": "and", "filters": [{"key": "value", "values": [value]}], "filterGroups": []},
                first=1,
            )
            return results[0] if results else None
        except Exception as e:
            self.helper.log_debug(
                f"[trust-cluster] observable lookup failed {obs_type}:{value}: {e}"
            )
            return None

    def _find_or_create_parent(self, obs_type: str, value: str) -> dict | None:
        """
        Get or create the parent observable.  Handles all observable-mode types.

        IPv4-Addr / IPv6-Addr → simple value match
        Domain-Name           → simple value match
        X509-Certificate      → search by subject = issuer_dn of child;
                                 create with that subject if absent
        """
        # ── X509-Certificate: search by subject (= issuer DN of the child) ────
        if obs_type == "X509-Certificate":
            # X509-Certificate observables have no 'value' field in OpenCTI —
            # their identity is a fingerprint hash.  Using _find_observable would
            # AND in a 'value' filter that always returns zero results, causing a
            # new duplicate CA anchor on every enrichment run (B3).  Query by
            # subject DN alone.
            try:
                results = self.helper.api.stix_cyber_observable.list(
                    types=["X509-Certificate"],
                    filters={
                        "mode": "and",
                        "filters": [{"key": "subject", "values": [value]}],
                        "filterGroups": [],
                    },
                    first=1,
                )
                existing = results[0] if results else None
            except Exception as e:
                self.helper.log_debug(
                    f"[trust-cluster] X509 subject lookup failed '{value}': {e}"
                )
                existing = None
            if existing:
                return existing
            try:
                created = self.helper.api.stix_cyber_observable.create(
                    observableData={
                        "type":    "x509-certificate",
                        "subject": value,
                        "x_opencti_score": 50,
                        "x_opencti_description": (
                            f"Auto-created CA cert anchor (subject: {value}). "
                            "Represents the issuing CA — feed enrichment will "
                            "assign a real score and link to actual cert data."
                        ),
                    }
                )
                self.helper.log_info(
                    f"[trust-cluster] created CA cert anchor: {value}"
                )
                return created
            except Exception as e:
                self.helper.log_error(
                    f"[trust-cluster] CA cert creation failed '{value}': {e}"
                )
            return None

        # ── Standard network observables (IPv4, IPv6, Domain-Name) ─────────────
        existing = self._find_observable(obs_type, value)
        if existing:
            return existing

        stix_type = {
            "IPv4-Addr":   "ipv4-addr",
            "IPv6-Addr":   "ipv6-addr",
            "Domain-Name": "domain-name",
        }.get(obs_type)
        if not stix_type:
            return None

        try:
            created = self.helper.api.stix_cyber_observable.create(
                observableData={
                    "type":  stix_type,
                    "value": value,
                    "x_opencti_score": 50,
                    "x_opencti_description": (
                        f"Auto-created trust-cluster anchor ({obs_type}: {value}). "
                        "UNKNOWN until a feed connector assigns a real score."
                    ),
                }
            )
            self.helper.log_info(
                f"[trust-cluster] created UNKNOWN parent anchor {obs_type}:{value}"
            )
            return created
        except Exception as e:
            self.helper.log_error(
                f"[trust-cluster] parent creation failed {obs_type}:{value}: {e}"
            )
            return None

    def _ensure_relationship(self, child_id: str, parent_id: str) -> bool:
        try:
            self.helper.api.stix_core_relationship.create(
                fromId=child_id, toId=parent_id,
                relationship_type="related-to",
                description="IOC trust-cluster structural parent link (auto-created)",
                confidence=self.confidence,
            )
            return True
        except Exception as e:
            self.helper.log_warning(
                f"[trust-cluster] relationship create failed: {e}"
            )
            return False

    def _get_sightings_count(self, entity_id: str) -> int:
        try:
            # ponytail: fetches all sightings; add count-only API param when slow
            sightings = (
                self.helper.api.stix_sighting_relationship.list(toId=entity_id) or []
            )
            if not self.sighting_source_filter:
                return len(sightings)
            # Filter: only count sightings whose creator is an approved connector.
            # Sightings without a createdBy are excluded when a filter is active.
            return sum(
                1 for s in sightings
                if (s.get("createdBy") or {}).get("id") in self.sighting_source_filter
            )
        except Exception:
            return 0

    def _has_malicious_context(self, entity: dict) -> bool:
        """Return True if any linked indicator has a score ≥ MALICIOUS_SCORE_MIN."""
        for ind in (entity.get("indicators") or []):
            try:
                if int(ind.get("x_opencti_score") or 0) >= self.malicious_score_min:
                    return True
            except (TypeError, ValueError):
                pass  # non-integer score from external feed (e.g. "high") — treat as 0
        return False

    def _create_audit_note(self, obs_id: str, obs_label: str,
                            actions: list[str]) -> None:
        """Persist a Note for every label/relationship change (STATE-CHANGE| equivalent)."""
        if not actions:
            return
        try:
            content = (
                "## IOC Trust Cluster — Automated Assessment\n\n"
                f"**Observable:** `{obs_label}`\n\n"
                "**Actions taken:**\n"
                + "\n".join(f"- {a}" for a in actions)
                + "\n\n---\n"
                "_Generated by the IOC Trust Cluster connector._"
            )
            self.helper.api.note.create(
                abstract=f"Trust Cluster: {'; '.join(actions[:2])}",
                content=content,
                objectRefs=[obs_id],
                confidence=self.confidence,
            )
        except Exception as e:
            self.helper.log_warning(f"[trust-cluster] audit note failed: {e}")

    def _create_revocation_note(self, obs_id: str, obs_label: str,
                                 p_type: str, p_value: str, p_score: int) -> None:
        """Alert analyst that malicious-cascade may no longer be valid."""
        try:
            self.helper.api.note.create(
                abstract=f"Trust Cluster: cascade revocation — {obs_label}",
                content=(
                    "## IOC Trust Cluster — Cascade Revocation Advisory\n\n"
                    f"**Observable:** `{obs_label}`\n\n"
                    "This observable carries `malicious-cascade` but its parent "
                    f"(`{p_type}:{p_value}`, current score={p_score}) is no longer "
                    "assessed as CONFIRMED_MALICIOUS.\n\n"
                    "**OpenCTI does not support programmatic label removal.** "
                    "An analyst should review whether `malicious-cascade` is still "
                    "valid and remove it manually if not.\n\n"
                    "---\n_Generated by the IOC Trust Cluster connector._"
                ),
                objectRefs=[obs_id],
                confidence=self.confidence,
            )
        except Exception as e:
            self.helper.log_warning(f"[trust-cluster] revocation note failed: {e}")

    def _create_conflict_note(self, obs_id: str, obs_label: str,
                               p_type: str, p_value: str, p_score: int) -> None:
        """Alert analyst that fp-candidate and malicious-cascade coexist."""
        try:
            self.helper.api.note.create(
                abstract=f"Trust Cluster: fp/malicious conflict — {obs_label}",
                content=(
                    "## IOC Trust Cluster — fp-candidate / malicious-cascade Conflict\n\n"
                    f"**Observable:** `{obs_label}`\n\n"
                    "Both `fp-candidate` and `malicious-cascade` are now present:\n\n"
                    "- `fp-candidate` was applied before the parent was assessed as malicious\n"
                    f"- `malicious-cascade` was just applied from `{p_type}:{p_value}` "
                    f"(parent score={p_score})\n\n"
                    "**Operational precedence:** `malicious-cascade` takes priority — "
                    "treat as malicious until reviewed. The `fp-candidate` signal may "
                    "indicate benign infrastructure repurposed by an attacker, or an "
                    "incorrect parent score.\n\n"
                    "Analyst action: review the parent score and remove the "
                    "appropriate label manually if warranted.\n\n"
                    "---\n_Generated by the IOC Trust Cluster connector._"
                ),
                objectRefs=[obs_id],
                confidence=self.confidence,
            )
        except Exception as e:
            self.helper.log_warning(f"[trust-cluster] conflict note failed: {e}")

    # ── Main processing pipeline ───────────────────────────────────────────────

    def process_message(self, data: dict) -> str:
        entity_id   = data.get("entity_id")
        entity_type = data.get("entity_type")

        if not entity_id:
            return "skipped: no entity_id"
        if entity_type not in SUPPORTED_TYPES:
            return f"skipped: unsupported type {entity_type}"

        entity = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if not entity:
            return "skipped: entity not found"

        value        = entity.get("value") or entity.get("observable_value") or ""
        score        = self._entity_score(entity)
        labels       = self._entity_label_values(entity)
        has_malicious = self._has_malicious_context(entity)
        actions: list[str] = []
        _parent_verdict: str | None = None   # captured for stats
        _conflict_this_trigger: bool = False  # captured for stats

        self.helper.log_info(
            f"[trust-cluster] {entity_type}:{value}  score={score}"
        )

        # ── Structural parent path ──────────────────────────────────────────────
        # If the observable already carries a trust-cluster label the structural
        # link (relationship + cluster label) was created on a previous run.
        # Skip _extract_parent entirely — no redundant DNS/RDAP lookups.
        # For verdict cascade, look up the known parent directly from the label
        # so score changes on the parent still propagate on the next trigger.
        existing_cluster = next(
            (lbl for lbl in labels if lbl.startswith(CLUSTER_LABEL_PREFIX + ':')),
            None
        )

        if existing_cluster:
            # Parent value is encoded in the label; infer its type from the value.
            pv = existing_cluster[len(CLUSTER_LABEL_PREFIX) + 1:]
            if pv.startswith('asn-owner:') or pv.startswith('tls-profile:'):
                parent_info = (LABEL_ONLY, pv)
            elif '/' in pv:
                parent_info = ('IPv6-Addr' if ':' in pv.split('/')[0] else 'IPv4-Addr', pv)
            elif entity_type == 'X509-Certificate':
                # X509-Certificate is the only type whose parent is also an
                # X509-Certificate (issuer DN).  Issuer DNs use comma-separated
                # Key=Value pairs (RFC 2253) which contain neither '/' nor the
                # label-only prefixes, so they would otherwise fall through to
                # the Domain-Name branch and silently fail the parent lookup.
                parent_info = ('X509-Certificate', pv)
            else:
                parent_info = ('Domain-Name', pv)
            already_clustered = True
        else:
            # First time — full parent discovery (DNS/RDAP as appropriate).
            parent_info = self._extract_parent(entity_type, value, entity)
            already_clustered = False

        if parent_info:
            p_type, p_value = parent_info

            # ── Label-only path ───────────────────────────────────────────────────
            # Network-Traffic (JA4 profile) and Autonomous-System (ASN owner).
            # No parent observable, no verdict cascade.
            if p_type == LABEL_ONLY:
                cluster_lbl = f"{CLUSTER_LABEL_PREFIX}:{p_value}"
                if cluster_lbl not in labels:
                    if self._add_label(entity_id, cluster_lbl, COLOR_CLUSTER):
                        labels.add(cluster_lbl)
                        actions.append(f"labelled {p_value}")

            # ── Observable parent path ────────────────────────────────────────────────
            # IPv4/IPv6 network, Domain-Name root/NS, X509 CA cert.
            elif p_value != value:
                cluster_lbl = f"{CLUSTER_LABEL_PREFIX}:{p_value}"

                # Already clustered + already cascaded: no-op, skip parent lookup.
                # Already clustered, no verdict yet: re-check parent score only.
                # First time: full pipeline (create parent, link, label, verdict).
                if already_clustered and LABEL_MALICIOUS_CASCADE in labels:
                    # Re-check whether the parent still supports the cascade.
                    # If the parent was cleared (score dropped / label removed)
                    # the cascade on this child is now stale — surface a
                    # revocation advisory to the analyst (deduplicated per session).
                    _rev_parent = self._find_observable(p_type, p_value)
                    if _rev_parent is not None:
                        _rp_score  = self._entity_score(_rev_parent)
                        _rp_labels = self._entity_label_values(_rev_parent)
                        if self._classify_parent(_rp_score, _rp_labels) != "CONFIRMED_MALICIOUS":
                            if entity_id not in self._revocation_noted:
                                self._revocation_noted.add(entity_id)
                                self._create_revocation_note(
                                    entity_id, f"{entity_type}:{value}",
                                    p_type, p_value, _rp_score
                                )
                                actions.append(
                                    f"cascade-revocation: parent {p_type}:{p_value} "
                                    f"no longer CONFIRMED_MALICIOUS (score={_rp_score})"
                                )
                    parent = None  # cascade label already set; skip normal verdict block
                elif already_clustered:
                    parent = self._find_observable(p_type, p_value)
                    if parent is None:
                        self.helper.log_warning(
                            f"[trust-cluster] orphaned {entity_type}:{value} — "
                            f"cluster label references {p_type}:{p_value} which no longer exists"
                        )
                else:
                    parent = self._find_or_create_parent(p_type, p_value)

                if parent:
                    p_id     = parent["id"]
                    p_score  = self._entity_score(parent)
                    p_labels = self._entity_label_values(parent)

                    if not already_clustered:
                        # Step 3: trust relationship child → parent (never reversed)
                        rel_ok = self._ensure_relationship(entity_id, p_id)

                        # Step 4: shared cluster label on both child and parent
                        lbl_ok = self._add_label(entity_id, cluster_lbl, COLOR_CLUSTER)
                        self._add_label(p_id, cluster_lbl, COLOR_CLUSTER)  # parent: best-effort
                        if rel_ok and lbl_ok:
                            labels.add(cluster_lbl)
                            actions.append(f"clustered under {p_type}:{p_value}")

                    # Step 5: verdict re-checked every trigger so parent score
                    # changes propagate down to children on their next update.
                    parent_verdict = self._classify_parent(p_score, p_labels)
                    _parent_verdict = parent_verdict   # capture for stats

                    if parent_verdict == "CONFIRMED_MALICIOUS":
                        if LABEL_MALICIOUS_CASCADE not in labels:
                            if self._add_label(
                                entity_id, LABEL_MALICIOUS_CASCADE, COLOR_MALICIOUS
                            ):
                                labels.add(LABEL_MALICIOUS_CASCADE)
                                cascade_msg = (
                                    f"malicious-cascade from {p_type}:{p_value} "
                                    f"(parent score={p_score}, direct feed assessment)"
                                )
                                if LABEL_FP_CANDIDATE in labels:
                                    # fp-candidate and malicious-cascade now coexist.
                                    # Create a dedicated Note so the conflict is visible
                                    # in the feed view, not buried in the audit note.
                                    if entity_id not in self._conflict_noted:
                                        self._conflict_noted.add(entity_id)
                                        _conflict_this_trigger = True
                                        self._create_conflict_note(
                                            entity_id, f"{entity_type}:{value}",
                                            p_type, p_value, p_score
                                        )
                                actions.append(cascade_msg)

                    elif parent_verdict == "CONFIRMED_BENIGN":
                        if (
                            score <= self.fp_cascade_score_max
                            and score < self.malicious_score_min
                            and LABEL_FP_CANDIDATE      not in labels
                            and LABEL_MALICIOUS_CASCADE not in labels
                            and not has_malicious
                        ):
                            if self._add_label(entity_id, LABEL_FP_CANDIDATE, COLOR_FP):
                                labels.add(LABEL_FP_CANDIDATE)
                                actions.append(
                                    f"fp-candidate inherited from {p_type}:{p_value} "
                                    f"(parent CONFIRMED_BENIGN)"
                                )

                    else:  # UNKNOWN parent — stop propagation
                        self.helper.log_debug(
                            f"[trust-cluster] propagation stopped — "
                            f"parent {p_type}:{p_value} is UNKNOWN (score={p_score})"
                        )

        # ── Sinkhole check (Domain-Name only) ──────────────────────────────────────────────
        # Resolve the domain's A records and check against the configured sinkhole
        # IP set.  A match is a direct malicious signal: the domain was deliberately
        # redirected to a sinkhole by law enforcement / security infrastructure.
        if (
            entity_type in ("Domain-Name", "Url")
            and self.sinkhole_ips
            and LABEL_SINKHOLED not in labels
        ):
            # For URLs extract the hostname; for Domain-Name use the value directly.
            lookup_host = (
                (urlparse(value).hostname or "").lower()
                if entity_type == "Url" else value
            )
            if lookup_host:
                resolved = self._get_resolved_ips(lookup_host)
                hit = next((ip for ip in resolved if ip in self.sinkhole_ips), None)
                if hit:
                    if self._add_label(entity_id, LABEL_SINKHOLED, COLOR_SINKHOLED):
                        labels.add(LABEL_SINKHOLED)
                        actions.append(f"sinkholed: {lookup_host} → {hit}")

        # ── Step 6: Ubiquity heuristic (all types) ─────────────────────────────
        if (
            score <= self.unknown_score_max
            and LABEL_FP_CANDIDATE      not in labels
            and LABEL_MALICIOUS_CASCADE not in labels
            and not has_malicious
        ):
            sightings = self._get_sightings_count(entity_id)
            if sightings >= self.fp_sighting_threshold:
                if self._add_label(entity_id, LABEL_FP_CANDIDATE, COLOR_FP):
                    labels.add(LABEL_FP_CANDIDATE)
                    actions.append(
                        f"fp-candidate via ubiquity "
                        f"(sightings={sightings} ≥ threshold={self.fp_sighting_threshold})"
                    )

        # ── Step 7: Audit note ─────────────────────────────────────────────────
        self._create_audit_note(entity_id, f"{entity_type}:{value}", actions)

        result = f"{len(actions)} action(s): {'; '.join(actions)}" if actions else "no actions"
        self.helper.log_info(f"[trust-cluster] {entity_type}:{value} → {result}")

        # ── Stats ───────────────────────────────────────────────────────────────────
        if self._stats_interval > 0:
            self._stats_n += 1
            for action in actions:
                if "malicious-cascade"      in action: self._stats["cascade_malicious"] += 1
                if "fp-candidate inherited" in action: self._stats["cascade_fp"]         += 1
                if "fp-candidate via ubiquity" in action: self._stats["ubiquity_fp"]     += 1
                if "sinkholed"              in action: self._stats["sinkholed"]          += 1
                if "clustered under"        in action: self._stats["newly_clustered"]    += 1
                if "cascade-revocation"     in action: self._stats["cascade_revoked"]   += 1
            if _conflict_this_trigger:             self._stats["cascade_conflict"]    += 1
            if already_clustered:                  self._stats["already_clustered"] += 1
            if not actions:                        self._stats["no_actions"]        += 1
            if   _parent_verdict == "CONFIRMED_MALICIOUS": self._stats["parents_malicious"] += 1
            elif _parent_verdict == "CONFIRMED_BENIGN":    self._stats["parents_benign"]    += 1
            elif _parent_verdict == "UNKNOWN":             self._stats["parents_unknown"]   += 1
            if self._stats_n % self._stats_interval == 0:
                self.helper.log_info(
                    f"[trust-cluster] stats[last {self._stats_interval}]: "
                    + " ".join(f"{k}={v}" for k, v in self._stats.items())
                )
                self._stats = IocTrustClusterConnector._reset_stats()

        return result

    def run(self):
        self.helper.listen(self.process_message)


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    connector = IocTrustClusterConnector()
    connector.run()
