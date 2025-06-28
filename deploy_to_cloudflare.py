#!/usr/bin/env python3
"""
Deploy NeuroCipher website to Cloudflare Pages using MCP integration
"""

import asyncio
import json
import os
import subprocess
from pathlib import Path

# Cloudflare credentials
CLOUDFLARE_API_TOKEN = "OQr6Rmg9_Oyfu-aNvjJL0Jd2fbK3CmuEGcZSjt0N"
CLOUDFLARE_ZONE_ID = "9c3eebdab6db092b3da4290c62232ae6"

async def deploy_neurocipher_website():
    """Deploy NeuroCipher website to Cloudflare Pages"""
    
    print("🚀 Deploying NeuroCipher to neurocipher.io...")
    
    # Set up environment variables
    os.environ['CLOUDFLARE_API_TOKEN'] = CLOUDFLARE_API_TOKEN
    os.environ['CLOUDFLARE_ZONE_ID'] = CLOUDFLARE_ZONE_ID
    
    # Check if we have wrangler CLI
    try:
        result = subprocess.run(['wrangler', '--version'], capture_output=True, text=True)
        print(f"✅ Wrangler CLI found: {result.stdout.strip()}")
    except FileNotFoundError:
        print("❌ Wrangler CLI not found. Installing...")
        subprocess.run(['npm', 'install', '-g', 'wrangler'], check=True)
    
    # Create pages deployment
    try:
        print("📦 Creating Cloudflare Pages deployment...")
        
        # Deploy to Pages using wrangler
        result = subprocess.run([
            'wrangler', 'pages', 'deploy', '.',
            '--project-name', 'neurocipher',
            '--compatibility-date', '2024-06-28'
        ], capture_output=True, text=True, cwd='/Users/cody/audithound-unified')
        
        if result.returncode == 0:
            print("✅ Website deployed successfully!")
            print(f"📝 Deployment output: {result.stdout}")
            print("🌐 Your website is now live at: https://neurocipher.pages.dev")
            print("🔗 Custom domain neurocipher.io will be available once DNS propagates")
        else:
            print(f"❌ Deployment failed: {result.stderr}")
            
            # Fallback: provide manual deployment instructions
            print("\n📋 Manual deployment steps:")
            print("1. Go to: https://dash.cloudflare.com/")
            print("2. Click 'Pages' in the sidebar")
            print("3. Click 'Create application' > 'Pages' > 'Connect to Git'")
            print("4. Select your neurocipher repository")
            print("5. Set build command: (leave empty)")
            print("6. Set build output directory: /")
            print("7. Set custom domain to neurocipher.io")
            print("8. Deploy!")
            
    except Exception as e:
        print(f"❌ Error during deployment: {e}")
        print("\n📋 Manual deployment fallback:")
        print("1. Go to: https://dash.cloudflare.com/")
        print("2. Click 'Pages' in the sidebar") 
        print("3. Click 'Create application' > 'Pages' > 'Upload assets'")
        print("4. Upload all files from this directory")
        print("5. Set custom domain to neurocipher.io")

if __name__ == "__main__":
    asyncio.run(deploy_neurocipher_website())