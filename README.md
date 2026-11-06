# MailGuard

MailGuard is an email security tool that checks Gmail messages for possible phishing attempts. It uses a Chrome extension to collect the currently opened email and a local Python API to send the content to an AI model running through Ollama.

The project is intended to help users spot suspicious messages. Its results are not a guarantee that an email is safe.

## Features

- Scans the currently opened Gmail message.
- Reviews the email text and available sender details.
- Looks for suspicious links, impersonation, requests for sensitive information, and social engineering.
- Uses a locally running Ollama model for analysis.
- Shows the analysis in a Chrome extension.
- Provides a FastAPI endpoint for email analysis.

## How it works

1. Open a message in Gmail.
2. Open the MailGuard extension.
3. The extension extracts the visible message text and available details such as sender, recipient, subject, and date.
4. The extension sends this information to the local MailGuard API.
5. The API sends the email to Ollama for analysis.
6. The extension displays the result.

MailGuard currently analyzes the most recently expanded message in a Gmail conversation. It does not retrieve the complete raw email headers.

## Requirements

- Python 3.10 or newer
- [Ollama](https://ollama.com/)
- [Google Chrome](https://www.google.com/chrome/)
- An internet connection to download the model and project dependencies

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/gamestag-py/MailGuard.git
cd MailGuard
```


### 2. Create a virtual environment

**Windows (PowerShell):**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux / macOS:**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install fastapi uvicorn requests pydantic
```

## Set up Ollama

### 1. Install Ollama

Download and install Ollama from:

https://ollama.com/download

Make sure Ollama is running before starting the MailGuard backend.

### 2. Download the model

MailGuard is configured to use `qwen3.5:0.8b`.

```bash
ollama pull qwen3.5:0.8b
```

You can check that the model is available with:

```bash
ollama list
```

If you change the model, update `MODEL_NAME` in `email_server.py` to match the model installed in Ollama.

## Start the backend

From the project's root directory, run:

```bash
uvicorn email_server:app --host 127.0.0.1 --port 8000
```

The API should now be available at:

- API health check: http://127.0.0.1:8000/health
- API endpoint: http://127.0.0.1:8000/check/email
- API documentation: http://127.0.0.1:8000/docs

Keep this terminal open while using the extension.

## Install the Chrome extension

1. Open Chrome.
2. Visit `chrome://extensions`.
3. Turn on **Developer mode**.
4. Select **Load unpacked**.
5. Select the `extension` folder inside the MailGuard project.
6. Pin MailGuard to the Chrome toolbar if you want quick access.

You do not need to extract or install `extension/manifest.zip` when loading the unpacked extension.

## Using MailGuard

1. Make sure Ollama is running and the required model is installed.
2. Start the MailGuard backend.
3. Open Gmail in Chrome.
4. Open an email message.
5. Click the MailGuard extension icon.
6. Wait for the scan to finish.
7. Review the classification, risk score, explanation, indicators, and recommendation shown by the extension.

The extension also provides a way to start the scan again.

## API usage

MailGuard exposes a `POST /check/email` endpoint.

Example request:

```bash
curl -X POST http://127.0.0.1:8000/check/email \
  -H "Content-Type: application/json" \
  -d '{
    "email": "Your email message text goes here.",
    "headers": "From: sender@example.com\nTo: user@example.com\nSubject: Example message\nDate: Mon, 1 Jan 2026 10:00:00 +0000"
  }'
```

The API returns a JSON response containing the classification, estimated phishing risk, confidence, explanation, indicators, and recommendation.

You can also open `http://127.0.0.1:8000/docs` to try the endpoint through FastAPI's interactive API documentation.

## Configuration

The main backend settings are at the top of `email_server.py`:

```python
OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "qwen3.5:0.8b"
MAX_MODEL_CHARS = 12000
```

The extension's API address is configured in `extension/popup.js`:

```javascript
const API_URL = 'http://127.0.0.1:8000/check/email';
```

The backend and extension must use matching addresses and ports.

## Troubleshooting

**The backend cannot connect to Ollama**

- Check that Ollama is installed and running.
- Run `ollama list` and confirm that `qwen3.5:0.8b` is installed.
- Check that `OLLAMA_URL` in `email_server.py` points to the correct Ollama API address.

**The extension cannot connect to the backend**

- Confirm that the FastAPI server is running.
- Open http://127.0.0.1:8000/health in Chrome.
- Make sure the API address in `extension/popup.js` matches the backend address.
- Reload the extension from `chrome://extensions`.

**The extension does not scan an email**

- Make sure you are viewing an individual Gmail message, not just the inbox.
- Refresh the Gmail tab and open the message again.
- Reload the extension and try again.

**The scan takes a long time**

- The first scan may take longer while Ollama loads the model.
- Model speed depends on your computer's available memory and hardware.
- Try a smaller model if your system cannot run the configured model comfortably, and update `MODEL_NAME` accordingly.

## Project structure

```text
MailGuard/
├── email_server.py
└── extension/
    ├── manifest.json
    ├── popup.html
    ├── popup.css
    ├── popup.js
    └── icons/
        └── image.png
```

`test.py` is also included in the repository as an alternative backend implementation. The setup instructions above use `email_server.py`.

## Notes and limitations

- MailGuard is an assistance tool, not a replacement for email security software or careful user judgment.
- A **Safe** result does not guarantee that a message is legitimate.
- The current implementation uses the visible Gmail message content and selected message details; it does not perform complete SPF, DKIM, or DMARC verification.
- The model does not independently browse URLs or perform live domain reputation checks.
- Attachment contents are not scanned by the current implementation.
- Keep the backend bound to localhost unless you have added appropriate authentication and network security controls.

## License

Add a `LICENSE` file to the repository if you want to specify how others may use, modify, and distribute this project.
