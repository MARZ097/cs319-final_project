# Tailwind CSS Integration for Access Control System

This document provides instructions for setting up and using the modern UI with Tailwind CSS.

## Setup Instructions

1. Make sure Node.js is installed on your system (download from https://nodejs.org/)

2. Install the required npm packages:
   ```bash
   npm install
   ```

3. Build the Tailwind CSS:
   ```bash
   npm run build
   ```

4. Run the application with Tailwind CSS:
   - Windows: `start_tailwind.bat`
   - Others: `python run_tailwind.py`

5. Access the modern UI at: http://127.0.0.1:5000/tailwind

## Directory Structure

- `app/static/src/input.css` - Source Tailwind CSS file
- `app/static/css/tailwind.css` - Compiled CSS file (generated)
- `app/templates/tailwind_*.html` - Templates for the modern UI
- `app/static/js/main.js` - JavaScript functions for the UI

## Development

For development, you can run the Tailwind watcher to automatically rebuild CSS when changes are made:

```bash
npm run watch
```

## Features

The modern UI includes several enhanced features:

- Responsive sidebar navigation
- Dark/light mode toggle
- Interactive password strength meter
- Sortable tables
- Session timeout notifications
- Improved form validation
- Mobile optimizations

## Browser Support

The modern UI is optimized for the latest versions of:
- Chrome
- Firefox
- Safari
- Edge
