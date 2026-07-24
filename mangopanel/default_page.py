"""
Default HTML/PHP page template generated when a new website is created in MangoPanel.
"""

DEFAULT_PAGE_CONTENT = """<!-- MangoPanel default page -->
<!-- MangoPanel dev site: {domain} -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to {domain} | Powered by MangoPanel</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0b0f19;
            --bg-secondary: #111827;
            --bg-card: rgba(17, 24, 39, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --border-hover: rgba(245, 158, 11, 0.3);
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --text-muted: #6b7280;
            --accent-mango: #f59e0b;
            --accent-gradient: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            --glow: rgba(245, 158, 11, 0.15);
            --success-color: #10b981;
            --font-main: 'Inter', system-ui, -apple-system, sans-serif;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: var(--font-main);
            background-color: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 2rem 1.5rem;
            position: relative;
            overflow-x: hidden;
        }

        /* Ambient Glow Effect */
        .ambient-glow {
            position: absolute;
            top: -20%;
            left: 50%;
            transform: translateX(-50%);
            width: 600px;
            height: 600px;
            background: radial-gradient(circle, var(--glow) 0%, rgba(11, 15, 25, 0) 70%);
            pointer-events: none;
            z-index: 0;
        }

        .container {
            max-width: 900px;
            width: 100%;
            z-index: 1;
        }

        .header {
            text-align: center;
            margin-bottom: 2.5rem;
        }

        .badge-status {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.2);
            color: var(--success-color);
            padding: 0.4rem 1rem;
            border-radius: 9999px;
            font-size: 0.85rem;
            font-weight: 500;
            margin-bottom: 1.5rem;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            background-color: var(--success-color);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--success-color);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(0.85); }
            100% { opacity: 1; transform: scale(1); }
        }

        .brand-logo {
            font-size: 2rem;
            font-weight: 700;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 1rem;
            color: var(--text-primary);
            text-decoration: none;
        }

        .brand-icon {
            font-size: 2.2rem;
        }

        .domain-title {
            font-size: 2.5rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            margin-bottom: 0.75rem;
            background: linear-gradient(180deg, #ffffff 0%, #d1d5db 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .domain-highlight {
            color: var(--accent-mango);
            -webkit-text-fill-color: initial;
        }

        .subtitle {
            font-size: 1.1rem;
            color: var(--text-secondary);
            max-width: 600px;
            margin: 0 auto;
            line-height: 1.6;
        }

        /* Card Grid */
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2.5rem;
        }

        .card {
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            transition: all 0.25s ease;
        }

        .card:hover {
            border-color: var(--border-hover);
            transform: translateY(-2px);
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
        }

        .card-icon {
            width: 44px;
            height: 44px;
            border-radius: 10px;
            background: rgba(245, 158, 11, 0.1);
            color: var(--accent-mango);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.4rem;
            margin-bottom: 1rem;
        }

        .card h3 {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: var(--text-primary);
        }

        .card p {
            font-size: 0.9rem;
            color: var(--text-secondary);
            line-height: 1.5;
        }

        .stack-bar {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.25rem 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 2.5rem;
        }

        .stack-info {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .stack-info strong {
            font-size: 0.95rem;
            color: var(--text-primary);
        }

        .tags {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }

        .tag {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-size: 0.8rem;
            padding: 0.25rem 0.65rem;
            border-radius: 6px;
            font-family: monospace;
        }

        .footer {
            text-align: center;
            color: var(--text-muted);
            font-size: 0.875rem;
        }

        .footer a {
            color: var(--text-secondary);
            text-decoration: none;
            transition: color 0.2s;
        }

        .footer a:hover {
            color: var(--accent-mango);
        }
    </style>
</head>
<body>
    <div class="ambient-glow"></div>

    <div class="container">
        <header class="header">
            <div class="badge-status">
                <span class="status-dot"></span>
                <span>Website Online &amp; Ready</span>
            </div>
            
            <div style="display: block;">
                <div class="brand-logo">
                    <span class="brand-icon">🥭</span> MangoPanel
                </div>
            </div>

            <h1 class="domain-title">Welcome to <span class="domain-highlight">{domain}</span></h1>
            <p class="subtitle">
                Your website has been successfully created and configured on MangoPanel. 
                You can now upload your files, manage databases, or launch your application.
            </p>
        </header>

        <div class="grid">
            <div class="card">
                <div class="card-icon">📁</div>
                <h3>File Manager</h3>
                <p>Upload your website contents directly into <code>public_html</code> using File Manager or SFTP/FTP.</p>
            </div>

            <div class="card">
                <div class="card-icon">🗄️</div>
                <h3>Databases</h3>
                <p>Create MariaDB/MySQL databases and manage your tables effortless with built-in phpMyAdmin access.</p>
            </div>

            <div class="card">
                <div class="card-icon">⚡</div>
                <h3>1-Click Installers</h3>
                <p>Quickly deploy WordPress, Node.js applications, or static sites directly from your control panel.</p>
            </div>
        </div>

        <div class="stack-bar">
            <div class="stack-info">
                <strong>Active Environment:</strong>
            </div>
            <div class="tags">
                <span class="tag">PHP 8.3</span>
                <span class="tag">Caddy / Nginx</span>
                <span class="tag">MariaDB</span>
                <span class="tag">SSL Ready</span>
            </div>
        </div>

        <footer class="footer">
            <p>Powered by <strong>MangoPanel</strong> • High-performance web hosting platform</p>
        </footer>
    </div>
</body>
</html>
"""
