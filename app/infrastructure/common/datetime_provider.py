from datetime import datetime
from zoneinfo import ZoneInfo

BRASILIA_TZ = ZoneInfo("America/Sao_Paulo")


def now_brasilia() -> datetime:
    # Save timestamps using Brasilia wall time regardless of server timezone.
    return datetime.now(BRASILIA_TZ).replace(tzinfo=None)
