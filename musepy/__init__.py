"""muse.ai 注册 / 邀请码兑换协议客户端（纯 HTTP，无浏览器）。"""

from .client import MuseClient, MuseError, parse_onboarding, random_dob
from .runner import BatchRunner
from .temp_mail import GeneratorMail, TempMailError, generate_email

__version__ = "0.3.0"

__all__ = [
    "BatchRunner",
    "GeneratorMail",
    "MuseClient",
    "MuseError",
    "TempMailError",
    "__version__",
    "generate_email",
    "parse_onboarding",
    "random_dob",
]
