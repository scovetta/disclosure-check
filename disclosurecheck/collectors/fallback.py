import logging

from disclosurecheck.util.context import Context

logger = logging.getLogger(__name__)


def add_fallback_mechanisms(context: Context) -> None:
    """Adds fallback disclosure mechanisms to all projects."""

    context.contacts.append(
        {
            "priority": 100,
            "type": "url",
            "value": "https://www.kb.cert.org/vuls/report/",
            "source": "CERT/CC Vulnerability Reporting Form",
        }
    )

    context.contacts.append(
        {
            "priority": 100,
            "type": "url",
            "value": "https://snyk.io/vulnerability-disclosure/",
            "source": "Snyk Vulnerability Disclosure Program",
        }
    )

    context.contacts.append(
        {
            "priority": 100,
            "type": "email",
            "value": "securitylab@github.com",
            "source": "https://securitylab.github.com/",
        }
    )
