"""AWS Lambda adapter for the FastAPI application."""

from mangum import Mangum

from .main import app

handler = Mangum(app)
