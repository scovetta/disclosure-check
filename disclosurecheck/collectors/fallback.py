import logging

from disclosurecheck.util.context import Context

logger = logging.getLogger(__name__)


def add_fallback_mechanisms(context: Context) -> None:
    """Adds fallback disclosure mechanisms to all projects."""

    context.add_contact(
        {
            "priority": 100,
            "type": "fallback_url",
            "value": "https://www.kb.cert.org/vuls/report/",
            "source": "CERT/CC Vulnerability Reporting Form",
        }
    )

    context.add_contact(
        {
            "priority": 100,
            "type": "fallback_url",
            "value": "https://snyk.io/vulnerability-disclosure/",
            "source": "Snyk Vulnerability Disclosure Program",
        }
    )

    context.add_contact(
        {
            "priority": 100,
            "type": "fallback_email",
            "value": "securitylab@github.com",
            "source": "GitHub Security Lab",
        }
    )
