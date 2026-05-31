"""
core/http_client.py

Merkezi HTTP istemcisi. Session yönetimi, timeout, retry, User-Agent
rotasyonu ve oturum çerezlerini kapsüller. Tüm OWASP modülleri bu
istemciyi paylaşır.

Oturum çerezi kullanımı (DVWA örneği):
    client = HTTPClient(cookies={"PHPSESSID": "abc123", "security": "low"})
"""

from __future__ import annotations

import logging
import random
import time
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

_USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]


class HTTPClient:
    """
    Merkezi HTTP istemcisi.

    Attributes:
        timeout: İstek başına saniye cinsinden zaman aşımı.
        max_retries: Geçici hatalar için yeniden deneme sayısı.
        proxy: İsteğe bağlı proxy URL'si (örn. "http://127.0.0.1:8080").
        rotate_ua: Her istekte rastgele User-Agent kullan.
        cookies: Session başlangıcında yüklenecek çerezler.
                 DVWA gibi auth gerektiren uygulamalar için kullanılır
                 (örn. {"PHPSESSID": "abc123", "security": "low"}).
    """

    def __init__(
        self,
        timeout: int = 5,
        max_retries: int = 2,
        proxy: Optional[str] = None,
        rotate_ua: bool = True,
        cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        self.timeout = timeout
        self.rotate_ua = rotate_ua
        self._proxies: Dict[str, str] = {"http": proxy, "https": proxy} if proxy else {}

        self._session = requests.Session()
        self._mount_retry_adapter(max_retries)

        # Oturum çerezlerini session başlangıcında yükle; sonraki tüm
        # isteklerde otomatik olarak gönderilir.
        if cookies:
            self._session.cookies.update(cookies)
            logger.debug("Session çerezleri yüklendi: %s", list(cookies.keys()))

    # ------------------------------------------------------------------
    # Dahili yardımcılar
    # ------------------------------------------------------------------

    def _mount_retry_adapter(self, max_retries: int) -> None:
        """Bağlantı ve okuma hatalarında otomatik yeniden deneme yapılandırır."""
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    def _build_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "User-Agent": random.choice(_USER_AGENTS) if self.rotate_ua else _USER_AGENTS[0],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        if extra:
            headers.update(extra)
        return headers

    # ------------------------------------------------------------------
    # Genel amaçlı istek yöntemleri
    # ------------------------------------------------------------------

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        verify_ssl: bool = False,
    ) -> requests.Response:
        """HTTP GET isteği atar."""
        try:
            response = self._session.get(
                url,
                params=params,
                headers=self._build_headers(headers),
                timeout=self.timeout,
                proxies=self._proxies,
                allow_redirects=allow_redirects,
                verify=verify_ssl,
            )
            logger.debug("GET %s → %d (%d bytes)", url, response.status_code, len(response.content))
            return response
        except requests.exceptions.Timeout:
            logger.warning("GET %s zaman aşımına uğradı (%ds)", url, self.timeout)
            raise
        except requests.exceptions.ConnectionError as exc:
            logger.error("GET %s bağlantı hatası: %s", url, exc)
            raise

    def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        verify_ssl: bool = False,
    ) -> requests.Response:
        """HTTP POST isteği atar."""
        try:
            response = self._session.post(
                url,
                data=data,
                json=json,
                headers=self._build_headers(headers),
                timeout=self.timeout,
                proxies=self._proxies,
                allow_redirects=allow_redirects,
                verify=verify_ssl,
            )
            logger.debug("POST %s → %d (%d bytes)", url, response.status_code, len(response.content))
            return response
        except requests.exceptions.Timeout:
            logger.warning("POST %s zaman aşımına uğradı (%ds)", url, self.timeout)
            raise
        except requests.exceptions.ConnectionError as exc:
            logger.error("POST %s bağlantı hatası: %s", url, exc)
            raise

    # ------------------------------------------------------------------
    # Session yardımcıları
    # ------------------------------------------------------------------

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """Session'a çerez ekler (örn. DVWA auth cookie'leri)."""
        self._session.cookies.update(cookies)

    def get_cookies(self) -> Dict[str, str]:
        """Mevcut session çerezlerini döndürür."""
        return dict(self._session.cookies)

    def close(self) -> None:
        """Bağlantı havuzunu temizler."""
        self._session.close()

    def __enter__(self) -> "HTTPClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        cookie_keys = list(self._session.cookies.keys())
        return (
            f"HTTPClient(timeout={self.timeout}, rotate_ua={self.rotate_ua}, "
            f"cookies={cookie_keys})"
        )
