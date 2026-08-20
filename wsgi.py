"""Production WSGI entry point for cloud application servers."""

from app import create_app
from config import ProductionConfig

app = create_app(ProductionConfig)

__all__ = ["app"]
