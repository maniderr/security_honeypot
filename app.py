from __future__ import annotations

from honeypot import create_app, init_db

app = create_app()


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
