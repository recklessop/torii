"""Container entrypoint: python -m torii.server"""

import uvicorn

from . import config


def main() -> None:
    uvicorn.run(
        "torii.app:app",
        host=config.HOST,
        port=config.PORT,
        log_level=config.LOG_LEVEL.lower(),
    )


if __name__ == "__main__":
    main()
