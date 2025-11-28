# FocusPad

Note-taking app. Fast capture and secure local storage

## What / Why

What: Lightweight note app built with Flask and SQLite.
Why: Capture and organize thoughts quickly in a distraction-free environment space

## Quick start

1. Clone and enter directory

   ```bash
   git clone https://github.com/m6lvink/FocusPad.git
   cd FocusPad
   ```

2. Set up environment

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Run application

   ```bash
   python app.py
   ```

4. Open [http://localhost:5000](http://localhost:5000)

## Features

* User registration and login
* Create, view, and delete notes
* Secure sessions and CSRF protection
* Light and dark themes
* SQLite storage

## Design

* Blue-Cream White color scheme
* Clean typography and simple animations
* Responsive layout with minimal clutter

## File structure

```
FocusPad/
├── app.py              # Flask application
├── notes.db            # SQLite db --> Gen
├── requirements.txt    # Python dependencies
├── static/
│   └── style.css       # Styles and theme
└── templates/
    ├── base.html       # Base layout
    ├── index.html      # Landing page
    ├── login.html      # Login view
    ├── register.html   # Registration view
    └── dashboard.html  # Notes dashboard
```

## Tech used

* Backend: Flask + SQLite
* Frontend: HTML, CSS, light JavaScript
* No external UI frameworks


## Security

* Passwords hashed with Werkzeug
* Session cookies HTTP-only and same-site
* CSRF protection via Flask-WTF
* Strict security headers and CSP
* Use a strong `SECRET_KEY` in prod

## Known limitations

* Single-user database instance
* No search or export yet
* No multi-user collaboration
* Local storage only

## License

MIT
