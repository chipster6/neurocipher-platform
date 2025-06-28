#!/usr/bin/env python3
"""
AuditHound Unified Dashboard Launcher
Starts the unified compliance + threat hunting + SOC integration dashboard
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = [
        'flask', 'requests', 'pyyaml', 'sqlalchemy',
        'python-dotenv', 'click'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("❌ Missing required packages:")
        for package in missing_packages:
            print(f"   • {package}")
        print("\n📦 Install missing packages with:")
        print(f"   pip install {' '.join(missing_packages)}")
        return False
    
    return True

def setup_environment():
    """Setup environment variables and configuration"""
    print("🔧 Setting up environment...")
    
    # Create logs directory
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    
    # Create reports directory
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    
    # Check Weaviate connection
    weaviate_url = os.getenv('WEAVIATE_URL', 'http://localhost:8080')
    try:
        import weaviate
        client = weaviate.Client(weaviate_url)
        client.get_meta()
        print(f"✅ Weaviate connected at {weaviate_url}")
        print("   📊 Advanced compliance analytics enabled")
    except Exception:
        print(f"⚠️  Weaviate not available at {weaviate_url}")
        print("   📊 Basic compliance scoring will be used")
        print("   💡 Start Weaviate for enhanced analytics: docker run -p 8080:8080 semitechnologies/weaviate:latest")
    
    # Check Google Coral TPU acceleration
    try:
        from pycoral.utils import edgetpu
        tpu_devices = edgetpu.list_edge_tpus()
        if tpu_devices:
            print(f"✅ Google Coral TPU detected: {len(tpu_devices)} device(s)")
            print("   ⚡ Ultra-fast audit processing enabled (10-100x speedup)")
            for i, device in enumerate(tpu_devices):
                print(f"      Device {i}: {device.get('type', 'USB')}")
        else:
            print("⚠️  Google Coral TPU not detected")
            print("   ⚡ CPU processing will be used (slower)")
            print("   💡 Connect Coral USB Accelerator for 10-100x speedup")
    except ImportError:
        print("⚠️  Google Coral TPU libraries not installed")
        print("   ⚡ CPU processing will be used")
        print("   💡 Install with: pip install pycoral tflite-runtime")
    except Exception:
        print("⚠️  TPU detection failed - using CPU processing")
    
    # Check Coral TPU acceleration
    try:
        from src.coral_tpu_engine import is_coral_available, get_coral_engine
        
        if is_coral_available():
            coral_engine = get_coral_engine()
            device_count = len(coral_engine.tpu_devices)
            model_count = len(coral_engine.loaded_models)
            print(f"✅ Coral TPU acceleration enabled")
            print(f"   ⚡ {device_count} TPU devices, {model_count} models loaded")
            print("   🚀 100x+ faster security analytics enabled")
            
            # Quick benchmark
            try:
                benchmark = coral_engine.benchmark_acceleration(iterations=5)
                if benchmark:
                    avg_accel = sum(r.get('acceleration_factor', 1.0) 
                                  for r in benchmark.values() 
                                  if isinstance(r, dict)) / len(benchmark) if benchmark else 1.0
                    print(f"   📈 Average acceleration factor: {avg_accel:.1f}x")
            except Exception:
                pass
                
        else:
            print("⚠️  Coral TPU not available")
            print("   ⚡ CPU-based analytics will be used")
            print("   💡 Connect Coral USB Accelerator for 100x speedup")
            
    except Exception as e:
        print("⚠️  Coral TPU libraries not available")
        print("   💡 Install with: pip install pycoral tflite-runtime")
    
    # Check for environment variables
    env_vars = {
        'MISP_URL': 'MISP server URL (optional)',
        'MISP_API_KEY': 'MISP API key (optional)',
        'THEHIVE_URL': 'TheHive server URL (optional)',
        'THEHIVE_API_KEY': 'TheHive API key (optional)',
        'SLACK_WEBHOOK_URL': 'Slack webhook URL (optional)',
        'WEAVIATE_URL': 'Weaviate server URL (optional)'
    }
    
    missing_optional = []
    for var, description in env_vars.items():
        if not os.getenv(var):
            missing_optional.append(f"   • {var}: {description}")
    
    if missing_optional:
        print("ℹ️  Optional environment variables not set:")
        for var in missing_optional:
            print(var)
        print("\n⚠️  Some integrations will be disabled.")
    
    print("✅ Environment setup complete")

def create_sample_config():
    """Create sample configuration file if it doesn't exist"""
    config_path = Path("config.yaml")
    
    if config_path.exists():
        print("✅ Configuration file exists")
        return
    
    print("📝 Creating sample configuration...")
    
    sample_config = """# AuditHound Unified Configuration
cloud_providers:
  aws:
    enabled: false
    region: "us-west-2"
    access_key_id: "${AWS_ACCESS_KEY_ID}"
    secret_access_key: "${AWS_SECRET_ACCESS_KEY}"
  
  gcp:
    enabled: false
    project_id: "your-project-id"
    credentials_path: "./credentials/gcp-service-account.json"
  
  azure:
    enabled: false
    tenant_id: "${AZURE_TENANT_ID}"
    subscription_id: "${AZURE_SUBSCRIPTION_ID}"
    client_id: "${AZURE_CLIENT_ID}"
    client_secret: "${AZURE_CLIENT_SECRET}"

compliance_frameworks:
  soc2:
    enabled: true
    controls:
      - "CC6.1"
      - "CC6.2"
      - "CC6.3"
      - "CC7.1"
      - "CC8.1"

scoring:
  thresholds:
    compliant: 90
    partial: 70

dashboard:
  host: "0.0.0.0"
  port: 5001
  debug: true

logging:
  level: "INFO"
  file: "./logs/audithound.log"

notifications:
  slack:
    enabled: false
    webhook_url: "${SLACK_WEBHOOK_URL}"
    channel: "#security"
  
  mattermost:
    enabled: false
    webhook_url: "${MATTERMOST_WEBHOOK_URL}"
    channel: "security"

integrations:
  misp:
    enabled: false
    url: "${MISP_URL}"
    api_key: "${MISP_API_KEY}"
    verify_ssl: true
  
  thehive:
    enabled: false
    url: "${THEHIVE_URL}"
    api_key: "${THEHIVE_API_KEY}"
  
  weaviate:
    enabled: false
    url: "${WEAVIATE_URL}"
    api_key: "${WEAVIATE_API_KEY}"
"""
    
    with open(config_path, 'w') as f:
        f.write(sample_config)
    
    print(f"✅ Created sample configuration: {config_path}")
    print("📝 Edit config.yaml to customize your setup")

def start_dashboard(port=5001, debug=False, test_mode=False):
    """Start the unified dashboard"""
    print(f"🚀 Starting AuditHound Unified Dashboard on port {port}")
    
    # Add src to Python path
    src_path = Path(__file__).parent / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))
    
    try:
        if test_mode:
            # Import and run test workflow
            from test_unified_workflow import main as test_main
            import asyncio
            print("🧪 Running unified workflow test...")
            asyncio.run(test_main())
        else:
            # Import and run dashboard
            from dashboard.unified_app import app
            
            print("=" * 80)
            print("🛡️  AuditHound Unified Security Dashboard")
            print("=" * 80)
            print("📊 Features:")
            print("   • Compliance auditing (SOC 2)")
            print("   • Threat hunting and analytics")
            print("   • Asset inventory and risk scoring")
            print("   • MISP threat intelligence integration")
            print("   • TheHive incident response integration")
            print("   • Real-time chat notifications")
            print("=" * 80)
            print(f"🌐 Dashboard URL: http://localhost:{port}")
            print("🔑 API endpoints available at /api/*")
            print("📖 Documentation: Check README.md")
            print("=" * 80)
            
            app.run(
                host='0.0.0.0',
                port=port,
                debug=debug,
                threaded=True
            )
            
    except KeyboardInterrupt:
        print("\n⏹️  Dashboard stopped by user")
    except Exception as e:
        print(f"❌ Failed to start dashboard: {str(e)}")
        sys.exit(1)

def main():
    """Main launcher function"""
    parser = argparse.ArgumentParser(
        description="AuditHound Unified Dashboard Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_unified_dashboard.py                    # Start dashboard on port 5001
  python run_unified_dashboard.py --port 8080       # Start on custom port
  python run_unified_dashboard.py --debug           # Start in debug mode
  python run_unified_dashboard.py --test            # Run workflow tests
  python run_unified_dashboard.py --setup-only      # Setup environment only

Environment Variables:
  MISP_URL                MISP server URL (optional)
  MISP_API_KEY           MISP API key (optional)
  THEHIVE_URL            TheHive server URL (optional)
  THEHIVE_API_KEY        TheHive API key (optional)
  SLACK_WEBHOOK_URL      Slack webhook URL (optional)
  WEAVIATE_URL           Weaviate server URL (optional)
        """
    )
    
    parser.add_argument('--port', type=int, default=5001,
                       help='Port to run dashboard on (default: 5001)')
    parser.add_argument('--debug', action='store_true',
                       help='Run in debug mode')
    parser.add_argument('--test', action='store_true',
                       help='Run unified workflow tests')
    parser.add_argument('--setup-only', action='store_true',
                       help='Setup environment and exit')
    
    args = parser.parse_args()
    
    print("🛡️  AuditHound Unified Dashboard Launcher")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Setup environment
    setup_environment()
    create_sample_config()
    
    if args.setup_only:
        print("✅ Setup complete. Edit config.yaml and run again without --setup-only")
        return
    
    # Start dashboard or run tests
    start_dashboard(port=args.port, debug=args.debug, test_mode=args.test)

if __name__ == "__main__":
    main()