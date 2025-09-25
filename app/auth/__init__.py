"""Authentication blueprint for the Access Control System."""
from flask import Blueprint

bp = Blueprint('auth', __name__)

from app.auth import routes

