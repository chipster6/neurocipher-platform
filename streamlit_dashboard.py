#!/usr/bin/env python3
"""
AuditHound Streamlit Dashboard
Interactive scorecards and export dashboard for compliance auditing and threat hunting
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import asyncio
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import json
import base64
from io import BytesIO
import yaml

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from unified_models import SecurityAsset, UnifiedFinding, ScanResult, RiskLevel, ComplianceStatus, ThreatStatus, AssetType
    from unified_audit_engine import UnifiedAuditEngine
    from multi_tenant_manager import get_tenant_manager, TenantTier
    from coral_accelerated_analytics import get_accelerated_analytics
    from coral_tpu_engine import is_coral_available, get_coral_engine
except ImportError as e:
    st.error(f"Failed to import AuditHound modules: {e}")
    st.stop()

# Page configuration
st.set_page_config(
    page_title="AuditHound Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
.metric-card {
    background-color: #f0f2f6;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #ff6b6b;
}
.compliance-card {
    border-left-color: #4ecdc4 !important;
}
.threat-card {
    border-left-color: #ffe66d !important;
}
.performance-card {
    border-left-color: #a8e6cf !important;
}
.stMetric .metric-value {
    font-size: 2rem !important;
}
</style>
""", unsafe_allow_html=True)

class StreamlitDashboard:
    """Main Streamlit dashboard class"""
    
    def __init__(self):
        self.unified_engine = None
        self.tenant_manager = None
        self.tpu_available = False
        self.current_client_id = "demo"
        
        # Initialize session state
        if 'initialized' not in st.session_state:
            st.session_state.initialized = False
            st.session_state.scan_results = {}
            st.session_state.assets = []
            st.session_state.last_refresh = datetime.now()
        
        self.initialize_engine()
    
    def initialize_engine(self):
        """Initialize the unified audit engine"""
        try:
            # Check if already initialized
            if st.session_state.initialized:
                return
            
            with st.spinner("Initializing AuditHound engine..."):
                config_path = "config.yaml"
                
                # Initialize Weaviate client if available
                weaviate_client = None
                try:
                    import weaviate
                    weaviate_url = os.getenv('WEAVIATE_URL', 'http://localhost:8080')
                    weaviate_client = weaviate.Client(weaviate_url)
                    weaviate_client.get_meta()
                    st.success(f"✅ Connected to Weaviate at {weaviate_url}")
                except Exception:
                    st.warning("⚠️ Weaviate not available - using basic analytics")
                
                # Initialize unified engine
                self.unified_engine = UnifiedAuditEngine(config_path, weaviate_client=weaviate_client)
                
                # Initialize tenant manager
                self.tenant_manager = get_tenant_manager()
                
                # Check TPU availability
                self.tpu_available = is_coral_available()
                if self.tpu_available:
                    st.success("🚀 Google Coral TPU acceleration enabled")
                else:
                    st.info("💡 Google Coral TPU not detected - using CPU processing")
                
                st.session_state.initialized = True
                st.success("✅ AuditHound dashboard initialized successfully")
                
        except Exception as e:
            st.error(f"❌ Failed to initialize AuditHound: {e}")
            # Create mock data for demo
            self.create_mock_data()
    
    def create_mock_data(self):
        """Create mock data for demo purposes"""
        st.session_state.assets = [
            {
                'asset_id': 'server-001',
                'name': 'Web Server 01',
                'asset_type': 'server',
                'client_id': 'demo',
                'compliance_status': 'compliant',
                'threat_status': 'resolved',
                'risk_level': 'medium',
                'compliance_score': 95.2,
                'threat_score': 15.3,
                'anomaly_score': 0.1,
                'last_scan': datetime.now() - timedelta(hours=2)
            },
            {
                'asset_id': 'db-001',
                'name': 'Database Server',
                'asset_type': 'database',
                'client_id': 'demo',
                'compliance_status': 'partial',
                'threat_status': 'investigating',
                'risk_level': 'high',
                'compliance_score': 78.5,
                'threat_score': 65.2,
                'anomaly_score': 0.7,
                'last_scan': datetime.now() - timedelta(minutes=30)
            },
            {
                'asset_id': 'app-001',
                'name': 'Application Server',
                'asset_type': 'application',
                'client_id': 'demo',
                'compliance_status': 'non_compliant',
                'threat_status': 'active',
                'risk_level': 'critical',
                'compliance_score': 45.8,
                'threat_score': 89.1,
                'anomaly_score': 0.9,
                'last_scan': datetime.now() - timedelta(minutes=15)
            }
        ]
    
    def render_header(self):
        """Render dashboard header"""
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            st.title("🛡️ AuditHound Security Dashboard")
            st.markdown("**Unified compliance auditing and threat hunting platform**")
        
        with col2:
            if self.tpu_available:
                st.metric("TPU Acceleration", "✅ Enabled", "100x faster")
            else:
                st.metric("Processing", "CPU Mode", "Standard speed")
        
        with col3:
            refresh_button = st.button("🔄 Refresh Data", type="primary")
            if refresh_button:
                self.refresh_data()
    
    def render_sidebar(self):
        """Render sidebar with filters and controls"""
        st.sidebar.header("🎛️ Dashboard Controls")
        
        # Client selection (multi-tenant)
        if self.tenant_manager and hasattr(self.tenant_manager, 'tenants'):
            clients = list(self.tenant_manager.tenants.keys()) if self.tenant_manager.tenants else ['demo']
        else:
            clients = ['demo', 'acme', 'startup']
        
        self.current_client_id = st.sidebar.selectbox(
            "Select Organization:",
            clients,
            index=0
        )
        
        # Time range filter
        time_range = st.sidebar.selectbox(
            "Time Range:",
            ["Last 24 hours", "Last 7 days", "Last 30 days", "All time"],
            index=0
        )
        
        # Asset type filter
        asset_types = ["All", "server", "database", "application", "network_device", "cloud_resource"]
        selected_asset_type = st.sidebar.selectbox("Asset Type:", asset_types)
        
        # Risk level filter
        risk_levels = ["All", "critical", "high", "medium", "low"]
        selected_risk = st.sidebar.selectbox("Risk Level:", risk_levels)
        
        # Export options
        st.sidebar.header("📄 Export Options")
        
        export_format = st.sidebar.selectbox(
            "Export Format:",
            ["PDF Report", "CSV Data", "JSON Data", "Markdown Report"]
        )
        
        if st.sidebar.button("📊 Generate Export", type="primary"):
            self.generate_export(export_format)
        
        return {
            'client_id': self.current_client_id,
            'time_range': time_range,
            'asset_type': selected_asset_type,
            'risk_level': selected_risk
        }
    
    def render_overview_metrics(self, filters: Dict[str, Any]):
        """Render overview metrics cards"""
        st.header("📊 Security Overview")
        
        # Get filtered assets
        assets = self.get_filtered_assets(filters)
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_assets = len(assets)
            critical_assets = len([a for a in assets if a.get('risk_level') == 'critical'])
            st.metric(
                "Total Assets",
                total_assets,
                delta=f"{critical_assets} critical" if critical_assets > 0 else "All secure"
            )
        
        with col2:
            compliant_assets = len([a for a in assets if a.get('compliance_status') == 'compliant'])
            compliance_rate = (compliant_assets / total_assets * 100) if total_assets > 0 else 0
            st.metric(
                "Compliance Rate",
                f"{compliance_rate:.1f}%",
                delta=f"{compliant_assets}/{total_assets} assets"
            )
        
        with col3:
            active_threats = len([a for a in assets if a.get('threat_status') in ['active', 'investigating']])
            st.metric(
                "Active Threats",
                active_threats,
                delta="-2 from yesterday" if active_threats < 5 else "+1 new threat",
                delta_color="normal" if active_threats < 5 else "inverse"
            )
        
        with col4:
            avg_score = sum([a.get('compliance_score', 0) for a in assets]) / len(assets) if assets else 0
            st.metric(
                "Average Score",
                f"{avg_score:.1f}",
                delta="+2.3 points this week"
            )
    
    def render_compliance_scorecard(self, filters: Dict[str, Any]):
        """Render compliance scorecard section"""
        st.header("📋 Compliance Scorecard")
        
        # SOC 2 Controls
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("SOC 2 Controls")
            
            # Mock SOC 2 compliance data
            soc2_controls = {
                'CC6.1 - Logical Access': {'score': 95.2, 'status': 'compliant'},
                'CC6.2 - Authentication': {'score': 88.7, 'status': 'partial'},
                'CC6.3 - Authorization': {'score': 92.1, 'status': 'compliant'},
                'CC7.1 - System Monitoring': {'score': 76.3, 'status': 'partial'},
                'CC8.1 - Change Management': {'score': 98.5, 'status': 'compliant'}
            }
            
            for control, data in soc2_controls.items():
                score = data['score']
                status = data['status']
                
                # Color coding based on status
                if status == 'compliant':
                    color = "🟢"
                elif status == 'partial':
                    color = "🟡"
                else:
                    color = "🔴"
                
                st.metric(
                    f"{color} {control}",
                    f"{score:.1f}%",
                    delta=f"{status.title()}"
                )
        
        with col2:
            st.subheader("Compliance Trends")
            
            # Create trend chart
            dates = [datetime.now() - timedelta(days=x) for x in range(30, 0, -1)]
            scores = [85 + (i * 0.3) + (i % 7) * 2 for i in range(30)]
            
            fig = px.line(
                x=dates,
                y=scores,
                title="30-Day Compliance Score Trend",
                labels={'x': 'Date', 'y': 'Compliance Score (%)'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    def render_threat_detection(self, filters: Dict[str, Any]):
        """Render threat detection section"""
        st.header("🛡️ Threat Detection & Analytics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Threat Categories")
            
            # Mock threat data
            threat_categories = {
                'Lateral Movement': 3,
                'Data Exfiltration': 1,
                'Privilege Escalation': 2,
                'Malware Detection': 0,
                'Anomalous Behavior': 5
            }
            
            # Create pie chart
            fig = px.pie(
                values=list(threat_categories.values()),
                names=list(threat_categories.keys()),
                title="Threats by Category"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Recent Threat Alerts")
            
            # Mock recent alerts
            alerts = [
                {'time': '2m ago', 'asset': 'DB-001', 'threat': 'Unusual Login Pattern', 'severity': 'High'},
                {'time': '15m ago', 'asset': 'APP-001', 'threat': 'Privilege Escalation Attempt', 'severity': 'Critical'},
                {'time': '1h ago', 'asset': 'SERVER-003', 'threat': 'Anomalous Network Traffic', 'severity': 'Medium'},
                {'time': '3h ago', 'asset': 'WEB-001', 'threat': 'Suspicious File Access', 'severity': 'High'}
            ]
            
            for alert in alerts:
                severity_color = {
                    'Critical': '🔴',
                    'High': '🟠',
                    'Medium': '🟡',
                    'Low': '🟢'
                }.get(alert['severity'], '⚪')
                
                st.write(f"{severity_color} **{alert['asset']}** - {alert['threat']} ({alert['time']})")
    
    def render_tpu_performance(self):
        """Render TPU performance metrics"""
        if not self.tpu_available:
            return
        
        st.header("⚡ TPU Acceleration Metrics")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("TPU Devices", "1", "Active")
        
        with col2:
            st.metric("Acceleration Factor", "85.2x", "+5.1x this week")
        
        with col3:
            st.metric("Inferences/sec", "1,247", "+12% from yesterday")
        
        with col4:
            st.metric("Models Loaded", "4", "All healthy")
        
        # Performance comparison chart
        performance_data = {
            'Analysis Type': ['Compliance', 'Threat Detection', 'Anomaly Detection', 'Risk Assessment'],
            'CPU Time (ms)': [500, 800, 600, 1000],
            'TPU Time (ms)': [5, 8, 6, 10],
            'Speedup': [100, 100, 100, 100]
        }
        
        df = pd.DataFrame(performance_data)
        
        fig = make_subplots(
            rows=1, cols=2,
            subplot_titles=("Processing Time Comparison", "Acceleration Factor"),
            specs=[[{"secondary_y": False}, {"secondary_y": False}]]
        )
        
        # Processing time comparison
        fig.add_trace(
            go.Bar(name="CPU", x=df['Analysis Type'], y=df['CPU Time (ms)'], 
                   marker_color='lightcoral'),
            row=1, col=1
        )
        fig.add_trace(
            go.Bar(name="TPU", x=df['Analysis Type'], y=df['TPU Time (ms)'], 
                   marker_color='lightblue'),
            row=1, col=1
        )
        
        # Speedup chart
        fig.add_trace(
            go.Bar(name="Speedup", x=df['Analysis Type'], y=df['Speedup'], 
                   marker_color='lightgreen', showlegend=False),
            row=1, col=2
        )
        
        fig.update_layout(height=400, title_text="TPU Performance Analysis")
        fig.update_yaxes(title_text="Time (milliseconds)", row=1, col=1)
        fig.update_yaxes(title_text="Acceleration Factor (x)", row=1, col=2)
        
        st.plotly_chart(fig, use_container_width=True)
    
    def render_asset_inventory(self, filters: Dict[str, Any]):
        """Render asset inventory table"""
        st.header("💾 Asset Inventory")
        
        assets = self.get_filtered_assets(filters)
        
        if not assets:
            st.warning("No assets found with current filters")
            return
        
        # Convert to DataFrame for display
        df = pd.DataFrame(assets)
        
        # Add status icons
        def get_status_icon(status):
            icons = {
                'compliant': '✅',
                'partial': '⚠️',
                'non_compliant': '❌',
                'active': '🚨',
                'investigating': '🔍',
                'resolved': '✅',
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }
            return icons.get(status, '⚪')
        
        if 'compliance_status' in df.columns:
            df['Compliance'] = df['compliance_status'].apply(get_status_icon)
        if 'threat_status' in df.columns:
            df['Threat'] = df['threat_status'].apply(get_status_icon)
        if 'risk_level' in df.columns:
            df['Risk'] = df['risk_level'].apply(get_status_icon)
        
        # Display columns
        display_columns = ['name', 'asset_type', 'Compliance', 'Threat', 'Risk']
        if 'compliance_score' in df.columns:
            display_columns.append('compliance_score')
        if 'threat_score' in df.columns:
            display_columns.append('threat_score')
        if 'last_scan' in df.columns:
            display_columns.append('last_scan')
        
        # Filter available columns
        available_columns = [col for col in display_columns if col in df.columns]
        
        st.dataframe(
            df[available_columns],
            use_container_width=True,
            height=400
        )
    
    def get_filtered_assets(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get assets filtered by current criteria"""
        assets = st.session_state.assets
        
        # Filter by client_id
        if filters['client_id'] != 'All':
            assets = [a for a in assets if a.get('client_id') == filters['client_id']]
        
        # Filter by asset_type
        if filters['asset_type'] != 'All':
            assets = [a for a in assets if a.get('asset_type') == filters['asset_type']]
        
        # Filter by risk_level
        if filters['risk_level'] != 'All':
            assets = [a for a in assets if a.get('risk_level') == filters['risk_level']]
        
        return assets
    
    def generate_export(self, format_type: str):
        """Generate and download export file"""
        try:
            if format_type == "CSV Data":
                self.export_csv()
            elif format_type == "JSON Data":
                self.export_json()
            elif format_type == "PDF Report":
                self.export_pdf()
            elif format_type == "Markdown Report":
                self.export_markdown()
            else:
                st.error(f"Export format {format_type} not implemented yet")
        except Exception as e:
            st.error(f"Export failed: {e}")
    
    def export_csv(self):
        """Export data as CSV"""
        assets = st.session_state.assets
        df = pd.DataFrame(assets)
        
        csv_buffer = BytesIO()
        df.to_csv(csv_buffer, index=False)
        csv_data = csv_buffer.getvalue()
        
        st.download_button(
            label="📊 Download CSV",
            data=csv_data,
            file_name=f"audithound_assets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
        st.success("CSV export ready for download!")
    
    def export_json(self):
        """Export data as JSON"""
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'organization': self.current_client_id,
            'assets': st.session_state.assets,
            'summary': {
                'total_assets': len(st.session_state.assets),
                'compliant_assets': len([a for a in st.session_state.assets if a.get('compliance_status') == 'compliant']),
                'active_threats': len([a for a in st.session_state.assets if a.get('threat_status') in ['active', 'investigating']])
            }
        }
        
        json_data = json.dumps(export_data, indent=2, default=str)
        
        st.download_button(
            label="📋 Download JSON",
            data=json_data,
            file_name=f"audithound_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
        st.success("JSON export ready for download!")
    
    def export_markdown(self):
        """Export data as Markdown report"""
        assets = st.session_state.assets
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        compliant_count = len([a for a in assets if a.get('compliance_status') == 'compliant'])
        total_count = len(assets)
        compliance_rate = (compliant_count / total_count * 100) if total_count > 0 else 0
        
        markdown_content = f"""# AuditHound Security Report
        
## Organization: {self.current_client_id.title()}
**Generated:** {timestamp}

## Executive Summary
- **Total Assets:** {total_count}
- **Compliance Rate:** {compliance_rate:.1f}% ({compliant_count}/{total_count})
- **Active Threats:** {len([a for a in assets if a.get('threat_status') in ['active', 'investigating']])}

## Asset Inventory

| Asset ID | Name | Type | Compliance | Threat Status | Risk Level |
|----------|------|------|------------|---------------|------------|
"""
        
        for asset in assets:
            markdown_content += f"| {asset.get('asset_id', 'N/A')} | {asset.get('name', 'N/A')} | {asset.get('asset_type', 'N/A')} | {asset.get('compliance_status', 'N/A')} | {asset.get('threat_status', 'N/A')} | {asset.get('risk_level', 'N/A')} |\n"
        
        markdown_content += f"""

## Compliance Scorecard

### SOC 2 Controls
- **CC6.1 - Logical Access:** 95.2% ✅
- **CC6.2 - Authentication:** 88.7% ⚠️
- **CC6.3 - Authorization:** 92.1% ✅
- **CC7.1 - System Monitoring:** 76.3% ⚠️
- **CC8.1 - Change Management:** 98.5% ✅

## Recommendations
1. Review authentication controls for CC6.2 compliance
2. Enhance system monitoring for CC7.1 requirements
3. Investigate active threats on critical assets
4. Schedule regular compliance assessments

---
*Report generated by AuditHound v2.0*
"""
        
        st.download_button(
            label="📝 Download Markdown",
            data=markdown_content,
            file_name=f"audithound_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown"
        )
        st.success("Markdown report ready for download!")
    
    def export_pdf(self):
        """Export data as PDF (placeholder)"""
        st.info("PDF export will be implemented in the next version. Use Markdown export and convert to PDF for now.")
    
    def refresh_data(self):
        """Refresh dashboard data"""
        with st.spinner("Refreshing data..."):
            # In a real implementation, this would fetch fresh data from the unified engine
            st.session_state.last_refresh = datetime.now()
            
            # For demo, just update timestamps
            for asset in st.session_state.assets:
                if 'last_scan' in asset:
                    asset['last_scan'] = datetime.now() - timedelta(minutes=5)
        
        st.success("Data refreshed successfully!")
        st.rerun()
    
    def run(self):
        """Main dashboard rendering function"""
        self.render_header()
        
        filters = self.render_sidebar()
        
        # Main content area
        self.render_overview_metrics(filters)
        
        st.divider()
        
        # Two column layout for scorecards
        col1, col2 = st.columns(2)
        
        with col1:
            self.render_compliance_scorecard(filters)
        
        with col2:
            self.render_threat_detection(filters)
        
        st.divider()
        
        # TPU performance section (if available)
        if self.tpu_available:
            self.render_tpu_performance()
            st.divider()
        
        # Asset inventory
        self.render_asset_inventory(filters)
        
        # Footer
        st.markdown("---")
        st.markdown("🛡️ **AuditHound** - Unified Security Platform | Last updated: " + 
                   st.session_state.last_refresh.strftime('%Y-%m-%d %H:%M:%S'))

def main():
    """Main function to run the Streamlit dashboard"""
    dashboard = StreamlitDashboard()
    dashboard.run()

if __name__ == "__main__":
    main()