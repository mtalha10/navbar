# views/zap.py
import time
import logging
from urllib.parse import urlparse
import streamlit as st
import plotly.graph_objects as go
import pandas as pd
from zapv2 import ZAPv2
import json
import os
from functools import wraps


def rate_limited(max_per_minute):
    """Decorator to add rate limiting to scan methods"""
    min_interval = 60.0 / max_per_minute

    def decorator(func):
        last_called = [0.0]

        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            left_to_wait = min_interval - elapsed

            if left_to_wait > 0:
                time.sleep(left_to_wait)

            result = func(*args, **kwargs)
            last_called[0] = time.time()
            return result

        return wrapper

    return decorator


def setup_advanced_logging():
    """Enhanced logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('zap_scanner.log'),
            logging.StreamHandler()  # Console output
        ]
    )
    logger = logging.getLogger('ZAPScanner')
    logger.setLevel(logging.DEBUG)


# Call the logging setup immediately
setup_advanced_logging()


class ScannerConfig:
    """Configuration management for ZAP scanner"""

    @classmethod
    def load_config(cls):
        """Load configuration from environment and secrets"""
        return {
            'ZAP_API_KEY': st.secrets.get('ZAP_API_KEY', ''),
            'zap_proxy': {
                "http": "http://127.0.0.1:8080",
                "https": "http://127.0.0.1:8080"
            },
            'max_scan_depth': int(os.getenv('ZAP_MAX_SCAN_DEPTH', 100)),
            'scan_timeout': int(os.getenv('ZAP_SCAN_TIMEOUT', 1800))  # 30 minutes default
        }


def is_valid_url(url):
    """Enhanced URL validation"""
    try:
        result = urlparse(url)
        return all([
            result.scheme in ['http', 'https'],
            result.netloc,
            len(result.netloc) <= 255,
            all(len(part) <= 63 for part in result.netloc.split('.'))
        ])
    except Exception as e:
        logging.error(f"URL validation error: {e}")
        return False


def initialize_zap(api_key, proxies):
    """Initialize ZAP client with error handling"""
    try:
        return ZAPv2(apikey=api_key, proxies=proxies)
    except Exception as e:
        st.error(f"ZAP Initialization Error: {e}")
        logging.error(f"ZAP Initialization Error: {e}")
        return None


class ZAPScanner:
    @staticmethod
    def perform_comprehensive_scan(zap, url, max_children=100, timeout=1800):
        """
        Robust comprehensive scanning with timeout and advanced error handling

        Args:
            zap (ZAPv2): ZAP client instance
            url (str): Target URL to scan
            max_children (int): Max pages to spider
            timeout (int): Maximum scan time in seconds

        Returns:
            list: Detected vulnerabilities
        """
        start_time = time.time()

        try:
            # Context management for scan
            zap.context.newContext(url)

            # Spider scan with advanced configuration
            spider_id = zap.spider.scan(
                url=url,
                maxchildren=max_children,
                recurse=True,
                contextname=url
            )

            # Wait for spider scan
            while int(zap.spider.status(spider_id)) < 100:
                if time.time() - start_time > timeout:
                    zap.spider.stop(spider_id)
                    st.warning("Spider scan timed out")
                    break
                time.sleep(2)

            # Active scan with more nuanced approach
            active_scan_id = zap.ascan.scan(
                url=url,
                recurse=True,
                inScopeOnly=True
            )

            # Comprehensive progress tracking
            while int(zap.ascan.status(active_scan_id)) < 100:
                if time.time() - start_time > timeout:
                    zap.ascan.stop(active_scan_id)
                    st.warning("Active scan timed out")
                    break
                time.sleep(2)

            return ZAPScanner.fetch_alerts(zap)

        except Exception as e:
            logging.error(f"Comprehensive scan failed: {e}")
            st.error(f"Scan error: {e}")
            return []

    @staticmethod
    def open_target_url(zap, url):
        """Open the target URL in ZAP."""
        try:
            zap.urlopen(url)
        except Exception as e:
            logging.error(f"Error opening URL: {e}")
            st.error(f"Could not open URL: {e}")

    @staticmethod
    def start_spider_scan(zap, url, max_children=100):
        """Start a ZAP spider scan with configurable depth."""
        return zap.spider.scan(url=url, maxchildren=max_children)

    @staticmethod
    def start_active_scan(zap, url):
        """Start an active ZAP scan."""
        return zap.ascan.scan(url=url)

    @staticmethod
    def wait_for_scan_with_progress(zap, scan_id, scan_type='spider'):
        """Monitor scan progress with error handling"""
        try:
            progress_bar = st.progress(0)
            status_func = zap.spider.status if scan_type == 'spider' else zap.ascan.status

            while True:
                status = int(status_func(scan_id))
                progress_bar.progress(min(status, 100))

                if status >= 100:
                    return True

                time.sleep(2)

        except Exception as e:
            st.error(f"Scan monitoring error: {e}")
            logging.error(f"Scan monitoring error: {e}")
            return False

    @staticmethod
    def fetch_alerts(zap, batch_size=100):
        """Fetch and process alerts with error handling"""
        try:
            alerts = []
            start = 0
            while True:
                batch = zap.core.alerts(start=start, count=batch_size)
                if not batch:
                    break
                alerts.extend(batch)
                start += batch_size
            return alerts
        except Exception as e:
            logging.error(f"Error fetching alerts: {e}")
            st.error(f"Could not fetch vulnerability alerts: {e}")
            return []


# Rest of the code remains the same as in the original implementation

# Visualization Functions
class VulnerabilityVisualizer:
    @staticmethod
    def plot_risk_distribution(alerts):
        """Create advanced pie chart of vulnerability risks."""
        df = pd.DataFrame(alerts)
        risk_distribution = df['risk'].value_counts()

        color_map = {
            'High': 'red',
            'Medium': 'orange',
            'Low': 'yellow',
            'Informational': 'blue'
        }

        fig = go.Figure(data=[go.Pie(
            labels=risk_distribution.index,
            values=risk_distribution.values,
            hole=0.3,
            textinfo='label+percent',
            insidetextorientation='radial',
            marker_colors=[color_map.get(risk, 'gray') for risk in risk_distribution.index]
        )])

        fig.update_layout(
            title_text="Vulnerability Risk Distribution",
            title_font_size=16,
            legend_title_text="Risk Levels"
        )
        st.plotly_chart(fig)

    @staticmethod
    def plot_vulnerabilities_per_url(alerts):
        """Advanced bar chart of vulnerabilities per URL."""
        df = pd.DataFrame(alerts)
        url_vulnerabilities = df.groupby('url')['risk'].count().sort_values(ascending=False)

        # Color mapping based on risk
        def get_color(count):
            if count > 10:
                return 'red'
            elif count > 5:
                return 'orange'
            return 'green'

        fig = go.Figure(data=[
            go.Bar(
                x=url_vulnerabilities.index,
                y=url_vulnerabilities.values,
                marker_color=[get_color(count) for count in url_vulnerabilities.values]
            )
        ])

        fig.update_layout(
            title_text="Vulnerabilities per URL",
            xaxis_title="URL",
            yaxis_title="Number of Vulnerabilities",
            title_font_size=16
        )
        st.plotly_chart(fig)


class VulnerabilityAnalyzer:
    @staticmethod
    def categorize_vulnerabilities(alerts):
        """Advanced vulnerability categorization"""
        categories = {
            'Web Security': ['XSS', 'CSRF', 'SQL Injection'],
            'Configuration': ['HTTP Headers', 'Server Configurations'],
            'Sensitive Data': ['Information Disclosure', 'Sensitive Content']
        }

        categorized_alerts = {}
        for category, patterns in categories.items():
            categorized_alerts[category] = [
                alert for alert in alerts
                if any(pattern in alert['name'] for pattern in patterns)
            ]

        return categorized_alerts

    @staticmethod
    def calculate_risk_score(alerts):
        """Calculate overall application risk score"""
        risk_weights = {
            'High': 10,
            'Medium': 5,
            'Low': 2,
            'Informational': 1
        }

        total_score = sum(
            risk_weights.get(alert['risk'], 0)
            for alert in alerts
        )

        return min(total_score, 100)  # Normalize to 100
# Main Application
def show_zap_page():
    st.title("🔒 OWASP ZAP Vulnerability Scanner")

    # Scan Configuration with Descriptions
    st.markdown("""
    ## Vulnerability Scanning Tool
    Perform comprehensive security scans to identify potential vulnerabilities in web applications.
    """)

    # Scan Type Descriptions
    scan_descriptions = {
        "Spider Scan": "Crawls the website to discover all accessible pages and resources. Identifies potential entry points for further analysis.",
        "Active Scan": "Actively tests discovered pages for vulnerabilities by sending specially crafted requests to identify security weaknesses.",
        "Comprehensive Scan": "Combines Spider and Active scanning for thorough vulnerability detection. First crawls the site, then performs in-depth vulnerability testing."
    }

    # Scan Configuration
    col1, col2 = st.columns(2)

    with col1:
        target_url = st.text_input("Enter URL to Scan", value="https://example.com")
        scan_type = st.selectbox(
            "Select Scan Type",
            list(scan_descriptions.keys())
        )
        st.info(scan_descriptions[scan_type])

    with col2:
        max_children = st.slider(
            "Max Pages to Spider",
            min_value=10,
            max_value=500,
            value=100,
            help="Limit the number of pages ZAP will crawl during the spider scan. Higher values provide more comprehensive coverage but may increase scan time."
        )
        risk_filter = st.multiselect(
            "Filter Vulnerabilities",
            ["High", "Medium", "Low", "Informational"],
            default=["High", "Medium"],
            help="Select which risk levels of vulnerabilities you want to display in the results. Higher risk levels typically indicate more critical security issues."
        )

    # Initialize session state for scan results
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = None

    # Scan Trigger
    if st.button("Start Vulnerability Scan"):
        if not is_valid_url(target_url):
            st.error("Invalid URL. Please enter a valid URL.")
            return

        try:
            # Initialize ZAP
            config = ScannerConfig.load_config()
            zap = initialize_zap(config['ZAP_API_KEY'], config['zap_proxy'])

            if not zap:
                return

            # Open Target URL
            ZAPScanner.open_target_url(zap, target_url)
            st.success(f"Target URL {target_url} opened successfully.")

            # Perform Scan Based on Type
            if scan_type == "Spider Scan":
                scan_id = ZAPScanner.start_spider_scan(zap, target_url, max_children)
                scan_successful = ZAPScanner.wait_for_scan_with_progress(zap, scan_id, 'spider')
            elif scan_type == "Active Scan":
                scan_id = ZAPScanner.start_active_scan(zap, target_url)
                scan_successful = ZAPScanner.wait_for_scan_with_progress(zap, scan_id, 'active')
            else:  # Comprehensive Scan
                spider_id = ZAPScanner.start_spider_scan(zap, target_url, max_children)
                ZAPScanner.wait_for_scan_with_progress(zap, spider_id, 'spider')
                scan_id = ZAPScanner.start_active_scan(zap, target_url)
                scan_successful = ZAPScanner.wait_for_scan_with_progress(zap, scan_id, 'active')

            if scan_successful:
                # Fetch Alerts
                alerts = ZAPScanner.fetch_alerts(zap)

                # Filter Alerts by Risk
                filtered_alerts = [
                    alert for alert in alerts
                    if alert['risk'] in risk_filter
                ]

                # Store results in session state
                st.session_state.scan_results = filtered_alerts

                st.write(f"### Scan Results: {len(filtered_alerts)} Vulnerabilities")

                # Vulnerability Visualizations
                VulnerabilityVisualizer.plot_risk_distribution(filtered_alerts)
                VulnerabilityVisualizer.plot_vulnerabilities_per_url(filtered_alerts)

                # Detailed Vulnerability Display
                st.subheader("Vulnerability Details")
                for alert in filtered_alerts:
                    with st.expander(f"{alert['risk']} Risk: {alert['name']}"):
                        st.write(f"URL: {alert['url']}")
                        st.write(f"Description: {alert['description']}")
                        st.write(f"Solution: {alert['solution']}")

            else:
                st.warning("Scan did not complete successfully.")

        except Exception as e:
            st.error(f"An error occurred during the scan: {e}")
            logging.error(f"Scan Error: {e}")

    # Export Section (Outside of scan trigger to prevent refresh)
    if st.session_state.scan_results:
        st.markdown("## Export Vulnerability Report")

        export_format = st.selectbox(
            "Export Vulnerabilities",
            ["CSV", "JSON", "Raw Text"]
        )

        # Use st.download_button with key to prevent refresh
        if export_format == "CSV":
            df = pd.DataFrame(st.session_state.scan_results)
            st.download_button(
                label="Download CSV",
                data=df.to_csv(index=False),
                file_name="zap_vulnerabilities.csv",
                mime="text/csv",
                key="csv_download"
            )
        elif export_format == "JSON":
            st.download_button(
                label="Download JSON",
                data=json.dumps(st.session_state.scan_results, indent=2),
                file_name="zap_vulnerabilities.json",
                mime="application/json",
                key="json_download"
            )
        else:
            report_text = "\n\n".join([
                f"Risk: {a['risk']}\n"
                f"URL: {a['url']}\n"
                f"Description: {a['description']}\n"
                f"Solution: {a['solution']}\n"
                "---"
                for a in st.session_state.scan_results
            ])
            st.download_button(
                label="Download Text Report",
                data=report_text,
                file_name="zap_vulnerabilities.txt",
                mime="text/plain",
                key="txt_download"
            )