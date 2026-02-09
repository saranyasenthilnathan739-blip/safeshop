# Deployment Guide

## Deploy to Vercel

The project is now configured for Vercel deployment.

1. **Install Vercel CLI** (if not installed):
   ```bash
   npm install -g vercel
   ```

2. **Deploy**:
   ```bash
   vercel
   ```
   
   - Follow the prompts to log in and set up the project.
   - Use default settings (just press Enter).

## Environment Variables

Don't forget to add your API keys in the Vercel dashboard after deployment:
- `GOOGLE_SAFE_BROWSING_API_KEY`
- `VIRUSTOTAL_API_KEY`

## Project Structure

- `public/`: valid static files (HTML, CSS, JS)
- `server.js`: Express backend (runs as serverless function on Vercel)
- `vercel.json`: Deployment configuration
