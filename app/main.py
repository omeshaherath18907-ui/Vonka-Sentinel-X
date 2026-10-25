import logging
import sys
import threading
import time
from urllib.error import URLError
from urllib.request import urlopen

import uvicorn
from PySide6.QtWidgets import QApplication

from app.core.logging_setup import setup_logging
from app.services.api import api
from app.ui.main_window import MainWindow

HOST = "127.0.0.1"
PORT = 8765
HEALTH_URL = f"http://{HOST}:{PORT}/health"


def wait_for_backend(server, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if not server.started:
            time.sleep(0.1)
            continue

        try:
            with urlopen(HEALTH_URL, timeout=0.5) as response:
                return response.status == 200
        except (URLError, TimeoutError, OSError):
            time.sleep(0.15)

    return False


def main() -> int:
    logger = setup_logging()
    logger.info("Starting VONKA SENTINEL-X.")

    config = uvicorn.Config(
        api,
        host=HOST,
        port=PORT,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)

    backend_thread = threading.Thread(
        target=server.run,
        name="sentinel-local-api",
        daemon=True,
    )
    backend_thread.start()

    if not wait_for_backend(server):
        logger.error(
            "Backend did not become ready. Port %s may already be in use.",
            PORT,
        )
        server.should_exit = True
        backend_thread.join(timeout=3)
        return 1

    logger.info("Local backend is ready at %s", HEALTH_URL)

    qt_app = QApplication(sys.argv)
    qt_app.setApplicationName("VONKA SENTINEL-X")
    qt_app.setOrganizationName("VONKA")

    window = MainWindow()
    window.show()

    try:
        return qt_app.exec()
    finally:
        logger.info("Shutting down local backend.")
        server.should_exit = True
        backend_thread.join(timeout=3)


if __name__ == "__main__":
    raise SystemExit(main())
