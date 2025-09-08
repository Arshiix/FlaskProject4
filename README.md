Adora Home Renovation Website
 A Flask-based web application for managing home renovation services, including a gallery, contact form, and admin dashboard.

 ## Features
 - Service listings with image galleries
 - User authentication and admin dashboard
 - Contact form with email notifications and PDF attachments
 - Database-driven content management (SQLite/PostgreSQL)

 ## Credits
 - Built with [Flask](https://flask.palletsprojects.com/), [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/), [Flask-Admin](https://flask-admin.readthedocs.io/), [Flask-Login](https://flask-login.readthedocs.io/), and [Flask-Mail](https://pythonhosted.org/Flask-Mail/).
 - PDF generation powered by [ReportLab](https://www.reportlab.com/).
 - Image processing using [Pillow](https://pillow.readthedocs.io/).
 - Code optimization and deployment guidance assisted by [Grok](https://x.ai/grok), created by xAI.
 - [Add other credits, e.g., template designers, tutorials, or Stack Overflow posts used]

 ## Setup
 1. Install dependencies: `pip install -r requirements.txt`
 2. Set environment variables in `.env` (see `.env.example`)
 3. Initialize database: `python -c "from app import init_db; init_db()"`
 4. Run locally: `python app.py`

 ## License
 MIT License - see the [LICENSE](LICENSE) file for details.
