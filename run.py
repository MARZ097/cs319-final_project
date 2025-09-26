import os
from app import create_app
from build_tailwind import build_tailwind

# Build Tailwind CSS if needed
if not os.path.exists('app/static/css/tailwind.css'):
    build_tailwind()

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
