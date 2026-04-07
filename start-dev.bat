@echo off
echo 🚀 Starting Email Phishing Scanner Dev Environment...

:: Start Backend in new window
start "Backend" cmd /k "cd backend && .venv\Scripts\activate && uvicorn main:app --reload"

:: Wait a bit for backend to start
timeout /t 3

:: Start Frontend in new window
start "Frontend" cmd /k "cd frontend && npm run dev"

echo ✅ Both servers started!
echo 🌐 Backend: http://localhost:8000
echo 🎨 Frontend: http://localhost:5173
pause