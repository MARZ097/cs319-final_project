"""Profile blueprint for the Access Control System."""
from flask import Blueprint

bp = Blueprint('profile', __name__)

from app.profile import routes

