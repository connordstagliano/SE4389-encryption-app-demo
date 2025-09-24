# TACO Password Manager Frontend Setup

## Environment Configuration

Create a `.env.local` file in the frontend directory with the following content:

```
NEXT_PUBLIC_API_URL=http://localhost:5000
```

## Installation

1. Install dependencies:

```bash
npm install
# or
bun install
```

## Development

1. Start the development server:

```bash
npm run dev
# or
bun dev
```

2. Open [http://localhost:3000](http://localhost:3000) in your browser.

## Backend Setup

Make sure the Flask backend is running on port 5000:

```bash
cd ../backend
python app.py
```

## Features

- **Authentication**: Secure login/signup with JWT tokens
- **Password Management**: Add, view, and manage stored passwords
- **Security**: Military-grade encryption with AES-256-GCM
- **Modern UI**: Built with Next.js, TailwindCSS, and Framer Motion
- **Responsive Design**: Works on desktop and mobile devices

## API Integration

The frontend communicates with the Flask backend through the following endpoints:

- `POST /auth/signup` - User registration
- `POST /auth/login` - User authentication
- `POST /credentials/` - Add new credential
- `GET /credentials/` - Retrieve all credentials

## Security Features

- JWT token-based authentication
- Automatic token expiration
- Secure password visibility toggles
- Copy-to-clipboard functionality
- Search and filter capabilities
