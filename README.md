# Email to Print

A lightweight bot that watches an IMAP inbox and automatically sends PDF attachments to a CUPS printer. The project includes a Docker container with a configured CUPS server and a Python worker that reads the IMAP account.

## How it works
- Starts an IMAP connection using credentials provided via environment variables.
- Searches for unread messages (INBOX, flag `UNSEEN`).
- Extracts all PDF attachments from the message and submits them to CUPS as print jobs.
- Marks messages as "read" once at least one PDF has been submitted successfully.

## Requirements
- Python 3.11 (if running locally without Docker)
- A reachable IMAP server with valid credentials
- A reachable CUPS server with a printer (included in the container)

## Important environment variables
| Variable | Description | Example |
| --- | --- | --- |
| `IMAP_SERVER` | Hostname or IP address of the IMAP server | `imap.example.com` |
| `IMAP_PORT` | Port of the IMAP server (default: 993) | `993` |
| `IMAP_USER` | Username for IMAP | `drucker@example.com` |
| `IMAP_PASSWORD` | Password for IMAP | `sicheres-passwort` |
| `ALLOWED_SENDERS` | Comma-separated list of allowed sender addresses. When empty, all senders are accepted. | `alice@example.com,bob@example.com` |
| `CUPS_ADMIN_USER` | Username for the CUPS admin account (default: `admin`) | `secure-admin` |
| `CUPS_ADMIN_PASSWORD` | Password for the CUPS admin user (must be set) | `dein-sicheres-passwort` |
| `CHECK_INTERVAL` | Polling interval in seconds (default: 60) | `120` |
| `CUPS_PRINTER_NAME` | (Optional) Name of the printer to use. If not set, the CUPS default printer is used. | `Office-Printer` |
| `PRINT_SIDES` | CUPS `sides` printing option. Default: `two-sided-long-edge` for duplex printing. | `one-sided` |

Set `ALLOWED_SENDERS` if only certain senders should be printed automatically; all other emails are ignored. If the variable is not set or empty, the bot accepts all senders.

## Running with Docker
1. Build the image:
   ```bash
   docker build -t email-to-print .
   ```
2. Start the container (set IMAP variables accordingly):
   ```bash
   docker run -d \
     -e IMAP_SERVER=imap.example.com \
     -e IMAP_PORT=993 \
      -e IMAP_USER=drucker@example.com \
      -e IMAP_PASSWORD=sicheres-passwort \
     -e CUPS_ADMIN_PASSWORD=dein-sicheres-passwort \
      -e CHECK_INTERVAL=60 \
      -e CUPS_PRINTER_NAME=Office-Printer \
     -e PRINT_SIDES=two-sided-long-edge \
      -v cups-config:/etc/cups \   # keeps CUPS configuration persistent
      -v cups-spool:/var/spool/cups \ # preserves printer and job state
      -v cups-logs:/var/log/cups \    # optional: keep log files
      -p 631:631 \
      --name email-to-print \
      email-to-print
    ```
   Port 631 exposes the CUPS web interface. An admin user is created (default name `admin`, override via `CUPS_ADMIN_USER`); the password must be set via `CUPS_ADMIN_PASSWORD` or the container will not start.

   The volume mounts ensure that CUPS settings and printer information persist across restarts. Use custom paths instead of named volumes if preferred.

## Running locally (without Docker)
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Set environment variables (see above).
3. Start the bot:
   ```bash
   python app.py
   ```

## Printer configuration notes
- If `CUPS_PRINTER_NAME` is not set, the bot uses the default printer configured in CUPS.
- CUPS must have access to a reachable printer; configure it via the web interface or CLI inside the container.

## Troubleshooting
- **No printers found**: Verify that CUPS is running and that a default printer is defined or `CUPS_PRINTER_NAME` is set.
- **IMAP connection errors**: Check hostname/port; DNS or network errors are logged with descriptive messages.
- **No PDFs printed**: The bot only processes attachments with the `.pdf` extension.

## License
MIT License.
