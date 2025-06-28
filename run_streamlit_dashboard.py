#!/usr/bin/env python3
"""
AuditHound Streamlit Dashboard Launcher
Starts the interactive scorecards and export dashboard
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

def check_streamlit():
    """Check if Streamlit is installed"""
    try:
        import streamlit
        return True
    except ImportError:
        return False

def install_streamlit():
    """Install Streamlit and required dependencies"""
    print("📦 Installing Streamlit and dashboard dependencies...")
    
    packages = [
        'streamlit',
        'plotly',
        'pandas',
        'pyyaml'
    ]
    
    try:
        for package in packages:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
        
        print("✅ All dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def setup_environment():
    """Setup environment for Streamlit dashboard"""
    print("🔧 Setting up environment...")
    
    # Create necessary directories
    dirs = ['logs', 'reports', 'models/coral']
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    # Check if config.yaml exists
    config_path = Path("config.yaml")
    if not config_path.exists():
        print("📝 Creating sample configuration...")
        
        sample_config = """# AuditHound Configuration
organization:
  name: "Demo Organization"

cloud_providers:
  aws:
    enabled: false
  gcp:
    enabled: false
  azure:
    enabled: false

compliance_frameworks:
  soc2:
    enabled: true
    controls:
      - "CC6.1"
      - "CC6.2"
      - "CC6.3"
      - "CC7.1"
      - "CC8.1"

dashboard:
  host: "0.0.0.0"
  port: 8501
  debug: false

tpu_acceleration:
  enabled: true
  max_devices: 4

logging:
  level: "INFO"
  file: "./logs/audithound.log"
"""
        
        with open(config_path, 'w') as f:
            f.write(sample_config)
        
        print(f"✅ Created configuration file: {config_path}")
    
    print("✅ Environment setup complete")

def check_tpu():
    """Check TPU availability and display status"""
    try:
        from pycoral.utils import edgetpu
        devices = edgetpu.list_edge_tpus()
        if devices:
            print(f"✅ Google Coral TPU detected: {len(devices)} device(s)")
            print("   ⚡ Ultra-fast analytics enabled (100x speedup)")
        else:
            print("⚠️  Google Coral TPU not detected")
            print("   💡 Connect Coral USB Accelerator for acceleration")
    except ImportError:
        print("⚠️  Google Coral TPU libraries not installed")
        print("   💡 Install with: pip install pycoral tflite-runtime")
    except Exception as e:
        print(f"⚠️  TPU check failed: {e}")

def start_dashboard(port=8501, host="0.0.0.0", debug=False):
    """Start the Streamlit dashboard"""
    dashboard_script = "streamlit_dashboard.py"
    
    if not Path(dashboard_script).exists():
        print(f"❌ Dashboard script not found: {dashboard_script}")
        return False
    
    print(f"🚀 Starting AuditHound Streamlit Dashboard...")
    print("=" * 60)
    print("🛡️  AuditHound Interactive Security Dashboard")
    print("=" * 60)
    print("📊 Features:")
    print("   • Interactive compliance scorecards")
    print("   • Real-time threat detection analytics")
    print("   • Asset inventory and risk assessment")
    print("   • Multi-format export (CSV, JSON, Markdown)")
    print("   • Google Coral TPU acceleration")
    print("   • Multi-tenant organization support")
    print("=" * 60)
    print(f"🌐 Dashboard URL: http://localhost:{port}")
    print("🔄 Auto-refresh available")
    print("📱 Mobile-responsive design")
    print("=" * 60)
    
    try:
        # Build streamlit command
        cmd = [
            'streamlit', 'run', dashboard_script,
            '--server.port', str(port),
            '--server.address', host,
            '--server.headless', 'true' if not debug else 'false',
            '--browser.gatherUsageStats', 'false'
        ]
        
        if debug:
            cmd.extend(['--logger.level', 'debug'])
        
        # Set environment variables
        env = os.environ.copy()
        env['STREAMLIT_SERVER_ENABLE_CORS'] = 'false'
        env['STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION'] = 'false'
        
        # Run Streamlit
        subprocess.run(cmd, env=env)
        
    except KeyboardInterrupt:
        print("\n⏹️  Dashboard stopped by user")
    except FileNotFoundError:
        print("❌ Streamlit not found. Please install with: pip install streamlit")
        return False
    except Exception as e:
        print(f"❌ Failed to start dashboard: {e}")
        return False
    
    return True

def main():
    """Main launcher function"""
    parser = argparse.ArgumentParser(
        description="AuditHound Streamlit Dashboard Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_streamlit_dashboard.py                    # Start on default port 8501
  python run_streamlit_dashboard.py --port 8080       # Start on custom port
  python run_streamlit_dashboard.py --debug           # Start in debug mode
  python run_streamlit_dashboard.py --setup-only      # Setup environment only
  python run_streamlit_dashboard.py --install         # Install dependencies

Environment Variables:
  WEAVIATE_URL           Weaviate server URL (optional)
  MISP_URL              MISP server URL (optional)
  MISP_API_KEY          MISP API key (optional)
  THEHIVE_URL           TheHive server URL (optional)
  THEHIVE_API_KEY       TheHive API key (optional)
        """
    )
    
    parser.add_argument('--port', type=int, default=8501,
                       help='Port to run dashboard on (default: 8501)')
    parser.add_argument('--host', default='0.0.0.0',
                       help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true',
                       help='Run in debug mode')
    parser.add_argument('--setup-only', action='store_true',
                       help='Setup environment and exit')
    parser.add_argument('--install', action='store_true',
                       help='Install dependencies and exit')
    
    args = parser.parse_args()
    
    print("🛡️  AuditHound Streamlit Dashboard Launcher")
    print("=" * 50)
    
    # Install dependencies if requested
    if args.install:
        success = install_streamlit()
        sys.exit(0 if success else 1)
    
    # Check if Streamlit is installed
    if not check_streamlit():
        print("❌ Streamlit not installed")
        print("💡 Install with: python run_streamlit_dashboard.py --install")
        print("   Or manually: pip install streamlit plotly pandas")
        sys.exit(1)
    
    # Setup environment
    setup_environment()
    
    # Check TPU status
    check_tpu()
    
    if args.setup_only:
        print("✅ Setup complete. Run again without --setup-only to start dashboard")
        return
    
    # Start dashboard
    success = start_dashboard(port=args.port, host=args.host, debug=args.debug)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()