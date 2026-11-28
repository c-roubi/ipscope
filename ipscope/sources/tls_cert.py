"""Read names from the TLS certificates (and SMTP banners) the server presents.

Checks many ports at once: web (443, 8443), cPanel/WHM/webmail (2083, 2087, 2096),
mail over TLS (465, 993, 995) and SMTP with STARTTLS (25, 587). Mail and panel
ports often carry a certificate for the server's real hostname even when 443
serves a generic default certificate.
"""

from __future__ import annotations

import asyncio
import ssl

from cryptography import x509
from cryptography.x509.oid import NameOID

from ipscope.models import DomainRecord, is_placeholder, normalize_domain
from ipscope.sources.base import Source

STARTTLS_SMTP = {25, 587}
DEFAULT_TLS_PORTS = [443, 8443, 2083, 2087, 2096, 465, 993, 995, 587, 25]


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we only read the cert, we don't trust it
    return ctx


class TLSCert(Source):
    name = "tls"
    description = "Names from TLS certificates on web, panel and mail ports + SMTP banner (ACTIVE: contacts the target)"
    rate = 0
    active = True

    async def _lookup(self, ip: str) -> list[DomainRecord]:
        found = await asyncio.gather(*(self._port(ip, p) for p in self.ctx.tls_ports))
        out: dict[str, DomainRecord] = {}
        for names in found:
            for name in names:
                d = normalize_domain(name)
                if d and d not in out and not is_placeholder(d):
                    out[d] = DomainRecord(d, self.name)
        return list(out.values())

    @property
    def _connect_timeout(self) -> float:
        return min(self.ctx.timeout, 5)

    async def _port(self, ip: str, port: int) -> list[str]:
        try:
            if port in STARTTLS_SMTP:
                return await asyncio.wait_for(self._smtp(ip, port), self.ctx.timeout)
            return self.names_from_der(await self._grab(ip, port))
        except (OSError, ssl.SSLError, asyncio.TimeoutError, ValueError, EOFError, ConnectionError):
            return []  # closed port / no TLS is normal

    async def _grab(self, ip: str, port: int) -> bytes:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=_ctx(), server_hostname=""),
            self._connect_timeout,
        )
        try:
            der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 2)
            except Exception:
                pass
        if not der:
            raise ValueError("no certificate")
        return der

    async def _smtp(self, ip: str, port: int) -> list[str]:
        """Banner hostname + certificate after STARTTLS."""
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), self._connect_timeout)
        names: list[str] = []
        tls_transport = None
        try:
            banner = await self._reply(reader)
            if not banner or not banner[0].startswith("220"):
                return names
            parts = banner[0][4:].split()
            if parts:
                names.append(parts[0])                      # "220 mail.example.com ESMTP ..."
            writer.write(b"EHLO ipscope.invalid\r\n")
            await writer.drain()
            ehlo = await self._reply(reader)
            if ehlo and len(ehlo[0]) > 4:
                names.append(ehlo[0][4:].split()[0])        # "250-mail.example.com Hello"
            if not any("STARTTLS" in line.upper() for line in ehlo):
                return names
            writer.write(b"STARTTLS\r\n")
            await writer.drain()
            ok = await self._reply(reader)
            if not ok or not ok[0].startswith("220"):
                return names
            loop = asyncio.get_running_loop()
            tls_transport = await asyncio.wait_for(
                loop.start_tls(writer.transport, writer.transport.get_protocol(), _ctx()),
                self._connect_timeout,
            )
            der = tls_transport.get_extra_info("ssl_object").getpeercert(binary_form=True)
            if der:
                names += self.names_from_der(der)
            return names
        finally:
            (tls_transport or writer.transport).close()

    async def _reply(self, reader: asyncio.StreamReader) -> list[str]:
        """Read one (possibly multi-line) SMTP reply."""
        lines = []
        for _ in range(50):
            raw = await asyncio.wait_for(reader.readline(), self._connect_timeout)
            if not raw:
                break
            line = raw.decode("latin-1").rstrip("\r\n")
            lines.append(line)
            if len(line) < 4 or line[3] != "-":
                break
        return lines

    @staticmethod
    def names_from_der(der: bytes) -> list[str]:
        cert = x509.load_der_x509_certificate(der)
        names: list[str] = []
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names.extend(san.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            pass
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            if isinstance(attr.value, str):
                names.append(attr.value)
        return names
