"""
MangoPanel Custom Error Pages Generator for OpenLiteSpeed & Web Servers.
"""

def generate_error_page_html(code: int, title: str, description: str, suggestion: str, icon: str = "⚠️") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{code} {title} - MangoPanel</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-gradient: radial-gradient(circle at 50% 20%, #1e1b4b 0%, #0f172a 60%, #020617 100%);
      --card-bg: rgba(30, 41, 59, 0.7);
      --card-border: rgba(255, 255, 255, 0.1);
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #6366f1;
      --accent-glow: rgba(99, 102, 241, 0.25);
      --badge-bg: rgba(99, 102, 241, 0.15);
      --badge-text: #818cf8;
      --btn-bg: #4f46e5;
      --btn-hover: #4338ca;
    }}

    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}

    body {{
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      background: var(--bg-gradient);
      color: var(--text-main);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
      overflow-x: hidden;
    }}

    .background-glow {{
      position: absolute;
      width: 600px;
      height: 600px;
      background: radial-gradient(circle, var(--accent-glow) 0%, rgba(0,0,0,0) 70%);
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      pointer-events: none;
      z-index: 0;
    }}

    .error-card {{
      position: relative;
      z-index: 1;
      max-width: 540px;
      width: 100%;
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--card-border);
      border-radius: 24px;
      padding: 3rem 2.5rem;
      text-align: center;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      animation: fadeIn 0.5s ease-out;
    }}

    @keyframes fadeIn {{
      from {{ opacity: 0; transform: translateY(12px); }}
      to {{ opacity: 1; transform: translateY(0); }}
    }}

    .icon-wrapper {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 72px;
      height: 72px;
      background: var(--badge-bg);
      border-radius: 20px;
      font-size: 2.2rem;
      margin-bottom: 1.5rem;
      box-shadow: inset 0 0 12px rgba(99, 102, 241, 0.2);
    }}

    .error-code {{
      display: inline-block;
      font-size: 0.875rem;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--badge-text);
      background: var(--badge-bg);
      padding: 0.35rem 0.85rem;
      border-radius: 9999px;
      margin-bottom: 1rem;
      border: 1px solid rgba(129, 140, 248, 0.2);
    }}

    h1 {{
      font-size: 2.25rem;
      font-weight: 800;
      letter-spacing: -0.025em;
      line-height: 1.25;
      margin-bottom: 0.75rem;
      background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }}

    p.description {{
      color: var(--text-muted);
      font-size: 1rem;
      line-height: 1.6;
      margin-bottom: 1.75rem;
    }}

    .suggestion-box {{
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid rgba(255, 255, 255, 0.06);
      border-radius: 14px;
      padding: 1rem 1.25rem;
      font-size: 0.875rem;
      color: #cbd5e1;
      text-align: left;
      margin-bottom: 2rem;
    }}

    .suggestion-box strong {{
      color: #f8fafc;
      display: block;
      margin-bottom: 0.25rem;
    }}

    .action-buttons {{
      display: flex;
      gap: 0.75rem;
      justify-content: center;
      flex-wrap: wrap;
    }}

    .btn {{
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.75rem 1.5rem;
      border-radius: 12px;
      font-size: 0.925rem;
      font-weight: 600;
      text-decoration: none;
      transition: all 0.2s ease;
      cursor: pointer;
    }}

    .btn-primary {{
      background: var(--btn-bg);
      color: #ffffff;
      border: none;
      box-shadow: 0 4px 14px rgba(79, 70, 229, 0.4);
    }}

    .btn-primary:hover {{
      background: var(--btn-hover);
      transform: translateY(-1px);
    }}

    .btn-secondary {{
      background: rgba(255, 255, 255, 0.05);
      color: var(--text-main);
      border: 1px solid var(--card-border);
    }}

    .btn-secondary:hover {{
      background: rgba(255, 255, 255, 0.1);
      transform: translateY(-1px);
    }}

    .footer-brand {{
      margin-top: 2rem;
      font-size: 0.8rem;
      color: #64748b;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.4rem;
    }}

    .footer-brand span {{
      color: #818cf8;
      font-weight: 600;
    }}
  </style>
</head>
<body>
  <div class="background-glow"></div>
  <div class="error-card">
    <div class="icon-wrapper">{icon}</div>
    <br>
    <div class="error-code">Error {code}</div>
    <h1>{title}</h1>
    <p class="description">{description}</p>
    
    <div class="suggestion-box">
      <strong>💡 Diagnostic Suggestion:</strong>
      {suggestion}
    </div>

    <div class="action-buttons">
      <a href="javascript:history.back()" class="btn btn-secondary">
        ← Go Back
      </a>
      <a href="/" class="btn btn-primary">
        Return Home
      </a>
    </div>

    <div class="footer-brand">
      Powered by <span>MangoPanel Web Server</span>
    </div>
  </div>
</body>
</html>
"""


DEFAULT_ERROR_PAGES = {
    "suspended": generate_error_page_html(
        code=503,
        title="Account Temporarily Unavailable",
        description="This hosting account is temporarily unavailable while it is suspended.",
        suggestion="Please contact the hosting provider or account administrator if you believe this is unexpected.",
        icon="🛠️"
    ),
    "403": generate_error_page_html(
        code=403,
        title="Access Forbidden",
        description="You do not have permission to access this file or directory on the server.",
        suggestion="Ensure index.html or index.php exists in public_html and check file permissions in MangoPanel File Manager.",
        icon="🔒"
    ),
    "404": generate_error_page_html(
        code=404,
        title="Page Not Found",
        description="The page or resource you requested could not be found on this web server.",
        suggestion="Verify the URL for typos, or make sure the requested file has been uploaded to public_html.",
        icon="🔍"
    ),
    "500": generate_error_page_html(
        code=500,
        title="Internal Server Error",
        description="The web server encountered an unexpected error while processing your request.",
        suggestion="Check error logs in MangoPanel or inspect your application scripts / .htaccess configuration.",
        icon="⚠️"
    ),
    "502": generate_error_page_html(
        code=502,
        title="Bad Gateway",
        description="The web server received an invalid or timed out response from the upstream PHP-FPM / application process.",
        suggestion="Check if PHP process or database service is running, or inspect application memory usage.",
        icon="⚡"
    ),
    "503": generate_error_page_html(
        code=503,
        title="Service Unavailable",
        description="The web server is currently unable to handle this request due to temporary overloading or maintenance.",
        suggestion="Please try again in a few moments, or check backend service health in MangoPanel.",
        icon="🛠️"
    ),
}
