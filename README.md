# SE4389-encryption-app-demo

#### Manual Setup

Backend:
`cd backend`
`pip install -r requirements.txt`

Copy the sessions.example.json, db.example.json, and .env.example and remove the .example from their file names.

In .env, replace the SECRET_KEY with a random string (can be gibberish in dev, recommend a 32 byte key though `openssl rand -base64 32`)

`python app.py`

Frontend:
`cd frontend`
`npm install`
`npm run dev`
Look at package.json for other commands

#### Docker Setup

`docker compose up --build`
